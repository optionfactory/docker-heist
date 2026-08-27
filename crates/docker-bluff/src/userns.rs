//! User-namespace construction for idmapped mounts.
//!
//! `mount_setattr(MOUNT_ATTR_IDMAP)` takes a file descriptor to a user
//! namespace whose `uid_map`/`gid_map` describe the translation. We build it by
//! forking a helper that calls `unshare(CLONE_NEWUSER)`, writing the maps into
//! `/proc/<pid>/{uid,gid}_map` from the (privileged) parent, then opening
//! `/proc/<pid>/ns/user`. The open fd pins the namespace, so the helper is
//! reaped immediately afterwards.
//!
//! # Mapping direction
//!
//! A `uid_map` line is `<id inside ns> <id in parent ns> <count>`. For an
//! idmapped mount the kernel (`mapped_kuid_fs`) takes the id stored in the
//! filesystem, looks it up in the *inside* column and hands the *parent*
//! column to the caller; file creation (`mapped_fsuid`) walks the same table
//! backwards. So to make files owned by `1000` on disk appear as `0`, and files
//! created as `0` land on disk as `1000`, the line is `1000 0 1` - "filesystem
//! id" on the left, "visible id" on the right.
//!
//! Each `--id DISK:SEEN` installs a bijective *swap* of the two ids
//! (`DISK <-> SEEN`) in the uid and/or gid map: a `uid_map` must be a bijection,
//! so mapping disk `DISK` to appear as `SEEN` forces `SEEN` to appear as `DISK`.
//! Multiple swaps may be given as long as they are disjoint. Every id not named
//! is identity-mapped, so it behaves exactly like a plain bind mount instead of
//! collapsing to `nobody`/`EOVERFLOW`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

/// One `uid_map`/`gid_map` extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Id as stored in the filesystem (left column).
    pub fs_id: u32,
    /// Id observed/used by processes through the idmapped mount (right column).
    pub visible_id: u32,
    pub count: u32,
}

impl fmt::Display for Extent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.fs_id, self.visible_id, self.count)
    }
}

/// Highest mappable id + 1. `(u32)-1` is the kernel's invalid id, and the
/// kernel requires `first + count` not to wrap past `u32::MAX`.
pub const ID_LIMIT: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapping {
    pub uids: Vec<Extent>,
    pub gids: Vec<Extent>,
}

impl IdMapping {
    /// Build a mapping from a list of uid swaps and gid swaps. Each swap
    /// `(W, A)` exchanges the two ids; all other ids in `[0, limit)` are
    /// identity-mapped. `limit` is `ID_LIMIT` in production; tests running in a
    /// nested user namespace pass the size of their parent mapping.
    ///
    /// Swaps must be disjoint: an id may appear in at most one swap (in either
    /// position), otherwise the map would not be a bijection.
    pub fn from_swaps(uid_swaps: &[(u32, u32)], gid_swaps: &[(u32, u32)], limit: u32) -> Result<Self, String> {
        Ok(Self {
            uids: build_extents(uid_swaps, limit, "uid")?,
            gids: build_extents(gid_swaps, limit, "gid")?,
        })
    }

    /// True when the mapping would not change any id (no effective swaps).
    pub fn is_identity(&self) -> bool {
        self.uids.iter().chain(&self.gids).all(|e| e.fs_id == e.visible_id)
    }

    fn render(extents: &[Extent]) -> String {
        let mut s = String::new();
        for e in extents {
            s.push_str(&e.to_string());
            s.push('\n');
        }
        s
    }

    pub fn uid_map(&self) -> String {
        Self::render(&self.uids)
    }

    pub fn gid_map(&self) -> String {
        Self::render(&self.gids)
    }
}

/// Turn a set of disjoint swaps into a full, bijective extent list over
/// `[0, limit)`: each swapped id gets a single-count extent, and the gaps
/// between them are filled with identity extents. `what` names the column
/// (`uid`/`gid`) for error messages.
fn build_extents(swaps: &[(u32, u32)], limit: u32, what: &str) -> Result<Vec<Extent>, String> {
    // Involution: W<->A means both W->A and A->W. Collect the point mappings,
    // rejecting any id that would be mapped to two different targets.
    let mut points: BTreeMap<u32, u32> = BTreeMap::new();
    let mut add = |k: u32, v: u32| -> Result<(), String> {
        match points.insert(k, v) {
            Some(prev) if prev != v => Err(format!(
                "overlapping {what} mapping: {k} is mapped to both {prev} and {v}"
            )),
            _ => Ok(()),
        }
    };
    for &(w, a) in swaps {
        if w >= limit || a >= limit {
            return Err(format!("{what} id out of range (must be < {limit}): {w}:{a}"));
        }
        if w == a {
            continue; // identity, nothing to do
        }
        add(w, a)?;
        add(a, w)?;
    }

    // Emit identity fills between the (sorted) swapped ids, plus a single-count
    // extent for each swapped id.
    let mut extents = Vec::with_capacity(points.len() * 2 + 1);
    let mut next = 0u32;
    for (&fs_id, &visible_id) in &points {
        if fs_id > next {
            extents.push(Extent {
                fs_id: next,
                visible_id: next,
                count: fs_id - next,
            });
        }
        extents.push(Extent {
            fs_id,
            visible_id,
            count: 1,
        });
        next = fs_id + 1;
    }
    if next < limit {
        extents.push(Extent {
            fs_id: next,
            visible_id: next,
            count: limit - next,
        });
    }
    Ok(extents)
}

/// An open file descriptor to a user namespace carrying an `IdMapping`.
pub struct UserNamespace {
    fd: OwnedFd,
}

impl UserNamespace {
    /// Fork a helper, `unshare(CLONE_NEWUSER)` in it, write the maps, grab the
    /// namespace fd and reap the helper.
    ///
    /// Requires CAP_SETUID and CAP_SETGID in the current (initial) user namespace
    /// to write the maps; and, because a swap map contains uid 0 (e.g. `--id
    /// me:0`), CAP_SETFCAP as well - the kernel's `verify_root_map` guard
    /// (CVE-2018-18955) refuses to write a map that maps uid 0 without it.
    /// Must be called while the process is single-threaded: `fork` in a
    /// multi-threaded process is a well-known footgun, and the child only
    /// performs async-signal-safe calls (`close`, `unshare`, `read`, `write`,
    /// `_exit`).
    pub fn create(mapping: &IdMapping) -> io::Result<Self> {
        let (ready_r, ready_w) = pipe()?; // child -> parent: unshare done (0) or failed (errno)
        let (exit_r, exit_w) = pipe()?; // parent -> child: EOF means "you may exit"

        // SAFETY: fork; the child branch below uses only async-signal-safe libc
        // calls and never returns into Rust code that could allocate or lock.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // ---- child ----
            unsafe {
                libc::close(ready_r.as_raw());
                libc::close(exit_w.as_raw());
                // A process launched with file capabilities is marked
                // non-dumpable, which makes its /proc/<pid> files (including
                // uid_map/gid_map) owned by root - so the parent, running as the
                // invoking user, could not write them. Restore dumpability so
                // the map files are owned by our uid again. Harmless under sudo.
                libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
                let status: i32 = if libc::unshare(libc::CLONE_NEWUSER) == 0 {
                    0
                } else {
                    *libc::__errno_location()
                };
                let _ = libc::write(
                    ready_w.as_raw(),
                    (&status as *const i32).cast(),
                    std::mem::size_of::<i32>(),
                );
                let mut byte = 0u8;
                // Block until the parent closes its end (or dies).
                let _ = libc::read(exit_r.as_raw(), (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }

        // ---- parent ----
        drop(ready_w);
        drop(exit_r);
        let helper = Helper { pid, exit_w };

        let mut status_buf = [0u8; 4];
        let mut ready_file = File::from(ready_r);
        io::Read::read_exact(&mut ready_file, &mut status_buf)
            .map_err(|e| io::Error::other(format!("user namespace helper died before reporting: {e}")))?;
        let status = i32::from_ne_bytes(status_buf);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }

        write_map(pid, "uid_map", &mapping.uid_map())?;
        write_map(pid, "gid_map", &mapping.gid_map())?;

        let ns_path = format!("/proc/{pid}/ns/user");
        let file = File::open(&ns_path).map_err(|e| io::Error::other(format!("open {ns_path}: {e}")))?;
        drop(helper); // closes exit_w -> child exits; waitpid reaps it
        Ok(Self { fd: file.into() })
    }
}

impl AsFd for UserNamespace {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Helper child bookkeeping: on drop, release it and reap it.
struct Helper {
    pid: libc::pid_t,
    exit_w: Fd,
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Closing our write end unblocks the child's read(); it then _exit()s.
        // SAFETY: closing an fd we own exactly once.
        unsafe { libc::close(self.exit_w.take()) };
        let mut status = 0;
        // SAFETY: waitpid on our own child.
        unsafe { libc::waitpid(self.pid, &mut status, 0) };
    }
}

fn write_map(pid: libc::pid_t, name: &str, contents: &str) -> io::Result<()> {
    let path = format!("/proc/{pid}/{name}");
    let mut f = File::options()
        .write(true)
        .open(&path)
        .map_err(|e| io::Error::other(format!("open {path}: {e}")))?;
    // The kernel requires the whole map in a single write().
    f.write_all(contents.as_bytes()).map_err(|e| {
        // Turn the two opaque errno cases into actionable messages:
        // - EINVAL: pre-5.19 kernels cap a uid_map/gid_map at 5 extents (lines),
        //   and each --id swap costs up to ~2.5, so several swaps overflow it.
        // - EPERM: a map that maps uid 0 (any swap involving root) needs
        //   CAP_SETUID/CAP_SETGID and CAP_SETFCAP over the parent namespace
        //   (the kernel's verify_root_map / CVE-2018-18955 guard).
        let extents = contents.lines().count();
        let hint = match e.raw_os_error() {
            Some(libc::EINVAL) if extents > 5 => {
                " (this map has more than 5 extents; kernels before 5.19 reject that - use fewer --id swaps or upgrade to Linux >= 5.19)"
            }
            Some(libc::EPERM) => {
                " (writing a map that maps uid 0 needs CAP_SETUID, CAP_SETGID and CAP_SETFCAP - check the installed capabilities, see the README)"
            }
            _ => "",
        };
        io::Error::other(format!(
            "write {path} ({}): {e}{hint}",
            contents.trim_end().replace('\n', "; ")
        ))
    })
}

/// Minimal owned raw fd used across fork (OwnedFd would double-close in the
/// child if dropped there, so the child closes explicitly and `_exit`s).
struct Fd(libc::c_int);

impl Fd {
    fn as_raw(&self) -> libc::c_int {
        self.0
    }
    fn take(&mut self) -> libc::c_int {
        std::mem::replace(&mut self.0, -1)
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: closing an fd we own exactly once.
            unsafe { libc::close(self.0) };
        }
    }
}

impl From<Fd> for File {
    fn from(mut fd: Fd) -> File {
        // SAFETY: ownership of the raw fd is transferred exactly once.
        unsafe { File::from_raw_fd(fd.take()) }
    }
}

fn pipe() -> io::Result<(Fd, Fd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two fds into the array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((Fd(fds[0]), Fd(fds[1])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_swap_covers_whole_range_bijectively() {
        let m = IdMapping::from_swaps(&[(1000, 0)], &[(1000, 0)], ID_LIMIT).unwrap();
        assert_eq!(
            m.uid_map(),
            "0 1000 1\n1 1 999\n1000 0 1\n1001 1001 4294966294\n",
            "left column = id in the filesystem, right column = id seen through the mount"
        );
        assert_eq!(m.uid_map(), m.gid_map());
        assert!(!m.is_identity());
        // Every id in [0, ID_LIMIT) appears exactly once in each column.
        let total: u64 = m.uids.iter().map(|e| e.count as u64).sum();
        assert_eq!(total, ID_LIMIT as u64);
        for e in &m.uids {
            assert!(e.fs_id as u64 + e.count as u64 <= ID_LIMIT as u64);
            assert!(e.visible_id as u64 + e.count as u64 <= ID_LIMIT as u64);
        }
    }

    #[test]
    fn swap_order_of_endpoints_does_not_matter() {
        // W:A and A:W describe the same swap.
        let a = IdMapping::from_swaps(&[(1000, 5000)], &[], 10_000).unwrap();
        let b = IdMapping::from_swaps(&[(5000, 1000)], &[], 10_000).unwrap();
        assert_eq!(a.uid_map(), b.uid_map());
        assert_eq!(
            a.uid_map(),
            "0 0 1000\n1000 5000 1\n1001 1001 3999\n5000 1000 1\n5001 5001 4999\n"
        );
    }

    #[test]
    fn multiple_disjoint_swaps() {
        // swap 1000<->0 and 2000<->33 (so 33->2000). Extents are sorted by
        // fs_id with identity fills between them.
        let m = IdMapping::from_swaps(&[(1000, 0), (2000, 33)], &[], 3000).unwrap();
        assert_eq!(
            m.uid_map(),
            "0 1000 1\n1 1 32\n33 2000 1\n34 34 966\n1000 0 1\n1001 1001 999\n2000 33 1\n2001 2001 999\n"
        );
        // Still a bijection: [0, 3000) covered once in each column.
        let total: u64 = m.uids.iter().map(|e| e.count as u64).sum();
        assert_eq!(total, 3000);
    }

    #[test]
    fn overlapping_swaps_are_rejected() {
        assert!(IdMapping::from_swaps(&[(1000, 0), (2000, 0)], &[], 3000).is_err()); // 0 targeted twice
        assert!(IdMapping::from_swaps(&[(1000, 0), (1000, 33)], &[], 3000).is_err()); // 1000 mapped twice
        assert!(IdMapping::from_swaps(&[(1000, 0), (0, 33)], &[], 3000).is_err()); // 0 in two swaps
    }

    #[test]
    fn adjacent_ids_produce_no_empty_extents() {
        let m = IdMapping::from_swaps(&[(1, 0)], &[], 10).unwrap();
        assert_eq!(m.uid_map(), "0 1 1\n1 0 1\n2 2 8\n");
    }

    #[test]
    fn no_swaps_is_identity() {
        let m = IdMapping::from_swaps(&[], &[], ID_LIMIT).unwrap();
        assert!(m.is_identity());
        assert_eq!(m.uid_map(), "0 0 4294967295\n");
        // A swap of an id with itself is a no-op.
        assert!(IdMapping::from_swaps(&[(5, 5)], &[], 10).unwrap().is_identity());
    }

    #[test]
    fn uid_and_gid_are_independent() {
        let m = IdMapping::from_swaps(&[(1000, 0)], &[(100, 0)], 2000).unwrap();
        assert_eq!(m.uid_map(), "0 1000 1\n1 1 999\n1000 0 1\n1001 1001 999\n");
        assert_eq!(m.gid_map(), "0 100 1\n1 1 99\n100 0 1\n101 101 1899\n");
    }

    #[test]
    fn out_of_range_is_rejected() {
        assert!(IdMapping::from_swaps(&[(5, 20)], &[], 10).is_err());
    }
}
