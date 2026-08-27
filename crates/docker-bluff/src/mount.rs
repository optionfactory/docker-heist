//! Safe wrappers around the Linux "new mount API" used to build an idmapped
//! bind mount: `open_tree(2)`, `mount_setattr(2)`, `move_mount(2)` and the
//! classic `umount2(2)`.
//!
//! The syscalls are invoked through `libc::syscall` so the binary builds
//! identically against glibc and musl (musl does not export wrappers for the
//! new mount API). Constants come from `<linux/mount.h>` / `<linux/fcntl.h>`.
//!
//! Lifecycle of a remapped volume:
//!
//! ```text
//!   DetachedTree::clone_from(host_dir)      open_tree(OPEN_TREE_CLONE)
//!       .set_idmap(userns_fd)               mount_setattr(MOUNT_ATTR_IDMAP)
//!       .attach(/run/docker-bluff/<uuid>)   move_mount()
//!   AttachedMount::lazy_unmount()           umount2(MNT_DETACH) + rmdir()
//! ```
//!
//! `AttachedMount` is an RAII guard: dropping it lazily unmounts and removes
//! the mount point, so early-return error paths never leak mounts.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// <linux/mount.h>
const OPEN_TREE_CLONE: libc::c_uint = 0x1;
const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const MOUNT_ATTR_SIZE_VER0: libc::size_t = 32;
// <linux/fcntl.h>
const AT_EMPTY_PATH: libc::c_int = 0x1000;
const AT_RECURSIVE: libc::c_int = 0x8000;

/// `struct mount_attr` from `<linux/mount.h>` (version 0 layout, 32 bytes).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const _: () = assert!(std::mem::size_of::<MountAttr>() == MOUNT_ATTR_SIZE_VER0);

fn to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains an interior NUL byte"))
}

/// Errors from the mount API, annotated with which step failed and a
/// human-readable hint for the most common errno values.
#[derive(Debug)]
pub struct MountError {
    pub step: &'static str,
    pub path: PathBuf,
    pub source: io::Error,
}

impl MountError {
    fn new(step: &'static str, path: &Path, source: io::Error) -> Self {
        Self {
            step,
            path: path.to_path_buf(),
            source,
        }
    }

    pub fn errno(&self) -> Option<i32> {
        self.source.raw_os_error()
    }

    fn hint(&self) -> &'static str {
        match (self.step, self.errno()) {
            (_, Some(libc::ENOSYS)) => " (kernel too old: the new mount API needs Linux >= 5.12)",
            ("mount_setattr", Some(libc::EINVAL)) => {
                " (the filesystem, or one of its submounts, does not support idmapped mounts)"
            }
            ("mount_setattr", Some(libc::EPERM)) => {
                " (CAP_SYS_ADMIN over the filesystem is required, and the mount must not be idmapped already)"
            }
            ("open_tree", Some(libc::EPERM)) | ("move_mount", Some(libc::EPERM)) => " (CAP_SYS_ADMIN is required)",
            ("open_tree", Some(libc::ENOENT)) => " (host path does not exist)",
            _ => "",
        }
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) failed: {}{}",
            self.step,
            self.path.display(),
            self.source,
            self.hint()
        )
    }
}

impl std::error::Error for MountError {}

/// A mount tree cloned with `OPEN_TREE_CLONE`: it lives in an anonymous mount
/// namespace, is referenced only by this file descriptor and is not visible
/// anywhere in the filesystem hierarchy until `attach`ed.
pub struct DetachedTree {
    fd: OwnedFd,
    source: PathBuf,
    recursive: bool,
}

impl DetachedTree {
    /// `open_tree(AT_FDCWD, source, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC [| AT_RECURSIVE])`.
    ///
    /// With `recursive`, submounts below `source` are cloned too (the
    /// equivalent of `mount --rbind`, which is what Docker does for `-v`).
    pub fn clone_from(source: &Path, recursive: bool) -> Result<Self, MountError> {
        let c_source = to_cstring(source).map_err(|e| MountError::new("open_tree", source, e))?;
        let mut flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
        if recursive {
            flags |= AT_RECURSIVE as libc::c_uint;
        }
        // SAFETY: plain syscall with a valid NUL-terminated path; the kernel
        // returns a new file descriptor that we immediately take ownership of.
        let ret = unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c_source.as_ptr(), flags) };
        if ret < 0 {
            return Err(MountError::new("open_tree", source, io::Error::last_os_error()));
        }
        // SAFETY: `ret` is a fresh fd returned by the kernel and owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
        Ok(Self {
            fd,
            source: source.to_path_buf(),
            recursive,
        })
    }

    pub fn is_recursive(&self) -> bool {
        self.recursive
    }

    /// `mount_setattr(fd, "", AT_EMPTY_PATH [| AT_RECURSIVE], {attr_set: MOUNT_ATTR_IDMAP, userns_fd})`.
    ///
    /// The kernel requires the tree to be detached (never attached anywhere),
    /// not already idmapped, on a filesystem with `FS_ALLOW_IDMAP`, and the
    /// caller to hold CAP_SYS_ADMIN over both the filesystem and `userns`.
    pub fn set_idmap(&self, userns: BorrowedFd<'_>) -> Result<(), MountError> {
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns.as_raw_fd() as u64,
        };
        let mut flags = AT_EMPTY_PATH;
        if self.recursive {
            flags |= AT_RECURSIVE;
        }
        // SAFETY: `attr` is a properly laid out `struct mount_attr` and we pass
        // its exact size; both fds are open for the duration of the call.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                self.fd.as_raw_fd(),
                c"".as_ptr(),
                flags,
                &attr as *const MountAttr,
                MOUNT_ATTR_SIZE_VER0,
            )
        };
        if ret < 0 {
            return Err(MountError::new(
                "mount_setattr",
                &self.source,
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// `move_mount(fd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH)`: graft
    /// the detached tree onto `target`. `MOVE_MOUNT_F_EMPTY_PATH` refers to the
    /// *source* (our fd), not the target, so `target` may be non-empty - the
    /// idmapped tree simply overmounts whatever is there, exactly like a bind.
    fn move_onto(&self, target: &Path) -> Result<(), MountError> {
        let c_target = to_cstring(target).map_err(|e| MountError::new("move_mount", target, e))?;
        // SAFETY: plain syscall; `c_target` is valid and NUL-terminated.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                self.fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_FDCWD,
                c_target.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        };
        if ret < 0 {
            return Err(MountError::new("move_mount", target, io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Attach onto a dedicated (empty) mount point and return an RAII guard
    /// that lazily unmounts and removes the directory. Used for the Docker
    /// flow, where the mount must be visible in the host mount namespace at a
    /// throwaway path that is later rewritten into `docker run`.
    pub fn attach(self, target: &Path) -> Result<AttachedMount, MountError> {
        self.move_onto(target)?;
        // The fd is no longer needed: the mount is now referenced by the mount
        // namespace. It is closed when `self` goes out of scope here.
        Ok(AttachedMount {
            path: target.to_path_buf(),
            source: self.source,
            live: true,
        })
    }

    /// Attach *in place*, overmounting `target` (typically the original source
    /// directory) with no cleanup guard. Used for the generic flow, where the
    /// caller has already entered a private mount namespace, so the overmount
    /// is invisible to the rest of the host and vanishes when that namespace is
    /// torn down at process exit - there is nothing to unmount or remove.
    pub fn attach_over(self, target: &Path) -> Result<(), MountError> {
        self.move_onto(target)
    }
}

/// `unshare(CLONE_NEWNS)`: give the calling process a private copy of the mount
/// table. Requires CAP_SYS_ADMIN. Mounts made afterwards are visible only to
/// this process (and its children) - provided the tree is first made private,
/// see [`make_rprivate`].
pub fn unshare_mount_namespace() -> io::Result<()> {
    // SAFETY: plain syscall with a constant flag.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mount(NULL, dir, NULL, MS_REC | MS_PRIVATE, NULL)`: turn off mount
/// propagation for `dir` and everything under it. Without this, overmounts we
/// make in a freshly unshared namespace would propagate back to the host,
/// because a namespace inherits its parent's shared peer groups.
pub fn make_rprivate(dir: &Path) -> Result<(), MountError> {
    let c_dir = to_cstring(dir).map_err(|e| MountError::new("mount", dir, e))?;
    // SAFETY: propagation change; source/fstype/data are unused and passed NULL.
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            c_dir.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(MountError::new("mount", dir, io::Error::last_os_error()));
    }
    Ok(())
}

/// Build an idmapped detached tree of `source`.
///
/// Tries a recursive clone first (so submounts are preserved, like Docker's
/// `rbind`). The kernel refuses to idmap a tree when *any* mount in it lives
/// on a filesystem without idmap support (or is already idmapped), so on
/// `EINVAL`/`EPERM` we retry with a single, non-recursive mount. Returns the
/// tree and whether the recursive attempt was kept.
pub fn idmapped_tree(source: &Path, userns: BorrowedFd<'_>) -> Result<DetachedTree, MountError> {
    let tree = DetachedTree::clone_from(source, true)?;
    match tree.set_idmap(userns) {
        Ok(()) => Ok(tree),
        Err(e) if matches!(e.errno(), Some(libc::EINVAL) | Some(libc::EPERM)) => {
            drop(tree);
            let tree = DetachedTree::clone_from(source, false)?;
            tree.set_idmap(userns)?;
            Ok(tree)
        }
        Err(e) => Err(e),
    }
}

/// An idmapped mount attached at `path`. Dropping it (or calling
/// `lazy_unmount`) detaches it from the host mount namespace and removes the
/// mount point directory.
pub struct AttachedMount {
    path: PathBuf,
    source: PathBuf,
    live: bool,
}

impl AttachedMount {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    /// `umount2(path, MNT_DETACH)` followed by `rmdir(path)`.
    ///
    /// `MNT_DETACH` removes the mount from *this* mount namespace immediately
    /// (even if busy) while the kernel keeps the underlying mount alive for
    /// anyone else still referencing it - notably the container's own mount
    /// namespace, which received a bind of it from runc. Idempotent.
    pub fn lazy_unmount(&mut self) -> Result<(), MountError> {
        if !self.live {
            return Ok(());
        }
        let c_path = to_cstring(&self.path).map_err(|e| MountError::new("umount2", &self.path, e))?;
        // SAFETY: plain syscall with a valid NUL-terminated path.
        let ret = unsafe { libc::umount2(c_path.as_ptr(), libc::MNT_DETACH) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // EINVAL: not a mount point (already detached by someone else).
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(MountError::new("umount2", &self.path, err));
            }
        }
        self.live = false;
        std::fs::remove_dir(&self.path).map_err(|e| MountError::new("rmdir", &self.path, e))
    }
}

impl Drop for AttachedMount {
    fn drop(&mut self) {
        let _ = self.lazy_unmount();
    }
}

/// Create `dir` (mode `mode`) if it does not exist. Existing directories are
/// left untouched.
pub fn ensure_dir(dir: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}
