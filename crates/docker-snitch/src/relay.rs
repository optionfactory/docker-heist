//! Following one log file: provision it, copy appended bytes to an output,
//! notice truncation/replacement by others, and drop what has been relayed.
//!
//! Dropping relayed data never moves or discards bytes the daemon may still be
//! writing: the daemons this is built for append with `O_APPEND`, so a write
//! racing with us lands at the end of the file whatever we do to its prefix.
//! Which mechanism the filesystem supports is probed when the file is
//! provisioned, so an unusable filesystem is refused before the command starts:
//!
//! 1. `FALLOC_FL_COLLAPSE_RANGE` (ext4, xfs, f2fs): the relayed prefix is cut out
//!    and the rest shifts down. Bounded size, bounded disk.
//! 2. `FALLOC_FL_PUNCH_HOLE` (tmpfs, btrfs, zfs, ...): the relayed prefix is
//!    deallocated in place. Bounded disk; the logical size keeps growing (sparse).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CHUNK: usize = 64 * 1024;
const FALLOC_FL_KEEP_SIZE: libc::c_int = 0x01;
const FALLOC_FL_PUNCH_HOLE: libc::c_int = 0x02;
const FALLOC_FL_COLLAPSE_RANGE: libc::c_int = 0x08;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compaction {
    /// Cut the relayed prefix out of the file; what follows shifts down.
    Collapse,
    /// Deallocate the relayed prefix in place; the file becomes sparse.
    Punch,
}

pub struct Relay {
    path: PathBuf,
    file: File,
    dev: u64,
    ino: u64,
    offset: u64,
    blksize: u64,
    compaction: Compaction,
    /// `Punch` only: end of the range already deallocated.
    punched: u64,
}

impl Relay {
    /// Create the file if needed (its directory must exist) and start following
    /// it from its current end, like `tail -n 0 -F`.
    pub fn provision(path: &Path) -> Result<Relay, String> {
        let file = open(path).map_err(|e| format!("Failed to open '{}': {e}", path.display()))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("Failed to stat '{}': {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("'{}' is not a regular file", path.display()));
        }
        let blksize = blksize(&meta);
        let compaction = probe(path, blksize)?;
        Ok(Relay {
            path: path.to_path_buf(),
            file,
            dev: meta.dev(),
            ino: meta.ino(),
            offset: meta.len(),
            blksize,
            compaction,
            punched: 0,
        })
    }

    /// Copy everything appended since the last call to `out`, then drop what has
    /// been relayed from the file. Handles the file being truncated, replaced or
    /// removed by someone else (re-provisioning it in the last case).
    pub fn pump(&mut self, out: &mut dyn Write) -> io::Result<()> {
        match fs::metadata(&self.path) {
            Ok(meta) if meta.dev() == self.dev && meta.ino() == self.ino => {
                if meta.len() < self.offset {
                    // truncated by someone else: start over
                    self.offset = 0;
                    self.punched = 0;
                }
            }
            Ok(_) => {
                // replaced (rotated by rename + recreate): finish the old inode, switch to the new one
                self.drain(out)?;
                self.reopen()?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // removed: finish the old inode, recreate the file so the daemon can reopen it
                self.drain(out)?;
                self.reopen()?;
            }
            Err(e) => return Err(e),
        }
        self.drain(out)?;
        self.compact()
    }

    /// Drop the relayed prefix with the mechanism chosen at provisioning.
    fn compact(&mut self) -> io::Result<()> {
        match self.compaction {
            Compaction::Collapse => self.collapse_consumed(),
            Compaction::Punch => self.punch_consumed(),
        }
    }

    /// Final cleanup once the writer is gone: relay what is left and empty the file.
    pub fn finish(&mut self, out: &mut dyn Write) -> io::Result<()> {
        self.drain(out)?;
        self.file.set_len(0)?;
        self.offset = 0;
        self.punched = 0;
        Ok(())
    }

    #[cfg(test)]
    pub fn force_compaction(&mut self, c: Compaction) {
        self.compaction = c;
    }

    /// Open (creating if needed) whatever is at our path now and take our identity
    /// from that handle, so what we record is always the inode we read from, even
    /// if the path changed again between the caller's `stat` and this `open`.
    fn reopen(&mut self) -> io::Result<()> {
        self.file = open(&self.path)?;
        let meta = self.file.metadata()?;
        self.dev = meta.dev();
        self.ino = meta.ino();
        self.offset = 0;
        self.punched = 0;
        self.blksize = blksize(&meta);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn compaction(&self) -> Compaction {
        self.compaction
    }

    /// Remove the relayed prefix of the file, rounded down to whole blocks.
    fn collapse_consumed(&mut self) -> io::Result<()> {
        let mut aligned = (self.offset / self.blksize) * self.blksize;
        // The collapsed range must end before EOF: when the relayed data ends exactly on
        // a block boundary and nothing follows, keep the last block for now.
        if aligned >= self.file.metadata()?.len() {
            aligned = aligned.saturating_sub(self.blksize);
        }
        if aligned == 0 {
            return Ok(());
        }
        match collapse(&self.file, aligned) {
            Ok(()) => {
                self.offset -= aligned;
                Ok(())
            }
            // The range was invalidated under us (someone else truncated the file); the
            // next pump re-syncs the offset. Anything else propagates.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Deallocate the relayed prefix not yet punched, rounded down to whole blocks.
    fn punch_consumed(&mut self) -> io::Result<()> {
        let aligned = (self.offset / self.blksize) * self.blksize;
        if aligned <= self.punched {
            return Ok(());
        }
        punch(&self.file, self.punched, aligned - self.punched)?;
        self.punched = aligned;
        Ok(())
    }

    /// Copy appended bytes to `out`; returns whether there were any.
    fn drain(&mut self, out: &mut dyn Write) -> io::Result<bool> {
        let len = self.file.metadata()?.len();
        if len <= self.offset {
            return Ok(false);
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = vec![0u8; CHUNK];
        let mut remaining = len - self.offset;
        while remaining > 0 {
            let want = remaining.min(CHUNK as u64) as usize;
            let n = self.file.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            // A closed stdio pipe must not take the daemon down with us: keep consuming.
            let _ = out.write_all(&buf[..n]);
            self.offset += n as u64;
            remaining -= n as u64;
        }
        let _ = out.flush();
        Ok(true)
    }
}

fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn blksize(meta: &fs::Metadata) -> u64 {
    match meta.blksize() {
        0 => 4096,
        n => n,
    }
}

/// `fallocate(FALLOC_FL_COLLAPSE_RANGE, 0, len)`: cut `len` bytes off the front.
fn collapse(file: &File, len: u64) -> io::Result<()> {
    // SAFETY: fallocate on a valid fd with constant mode flags.
    let rc = unsafe { libc::fallocate(file.as_raw_fd(), FALLOC_FL_COLLAPSE_RANGE, 0, len as libc::off_t) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, start, len)`: deallocate a range in place.
fn punch(file: &File, start: u64, len: u64) -> io::Result<()> {
    // SAFETY: fallocate on a valid fd with constant mode flags.
    let rc = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            start as libc::off_t,
            len as libc::off_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Find out what the filesystem holding `path` supports, using a scratch file next
/// to it, so an unusable filesystem is refused before the command starts.
fn probe(path: &Path, blksize: u64) -> Result<Compaction, String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let scratch = dir.join(format!(".docker-snitch-probe-{}", std::process::id()));
    let result = (|| -> io::Result<Compaction> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&scratch)?;
        file.set_len(2 * blksize)?;
        let unsupported = |e: &io::Error| matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS));
        match collapse(&file, blksize) {
            Ok(()) => return Ok(Compaction::Collapse),
            Err(e) if unsupported(&e) => {}
            Err(e) => return Err(e),
        }
        match punch(&file, 0, blksize) {
            Ok(()) => Ok(Compaction::Punch),
            Err(e) if unsupported(&e) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem supports neither collapse-range nor punch-hole; use a directory on ext4, xfs, btrfs or tmpfs",
            )),
            Err(e) => Err(e),
        }
    })();
    let _ = fs::remove_file(&scratch);
    result.map_err(|e| format!("Cannot compact logs in '{}': {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("docker-snitch-test-{}-{n}", std::process::id()))
            .join(name)
    }

    fn ready(name: &str) -> PathBuf {
        let path = temp_path(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    fn cleanup(path: &Path) {
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    fn append(path: &Path, data: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(data)
            .unwrap();
    }

    fn size(path: &Path) -> u64 {
        fs::metadata(path).unwrap().len()
    }

    fn blocks(path: &Path) -> u64 {
        fs::metadata(path).unwrap().blocks()
    }

    /// The tier the temp filesystem is probed to (ext4/xfs: Collapse, tmpfs: Punch).
    fn native_tier() -> Compaction {
        let path = ready("probe.log");
        let tier = Relay::provision(&path).unwrap().compaction();
        cleanup(&path);
        tier
    }

    #[test]
    fn provisions_file_and_starts_at_end() {
        let path = ready("x.log");
        assert!(!path.exists());
        let mut relay = Relay::provision(&path).unwrap();
        assert!(path.is_file());
        let mut out = Vec::new();
        relay.pump(&mut out).unwrap();
        assert!(out.is_empty());
        append(&path, b"one\n");
        relay.pump(&mut out).unwrap();
        assert_eq!(out, b"one\n");
        cleanup(&path);
    }

    #[test]
    fn missing_directory_is_an_error_not_created() {
        let path = temp_path("missing/dir/x.log");
        let err = match Relay::provision(&path) {
            Err(e) => e,
            Ok(_) => panic!("provisioning must fail when the directory is missing"),
        };
        assert!(err.contains("Failed to open"), "{err}");
        assert!(!path.parent().unwrap().exists(), "directories must not be created");
    }

    #[test]
    fn existing_content_is_not_replayed() {
        let path = ready("y.log");
        fs::write(&path, b"old\n").unwrap();
        let mut relay = Relay::provision(&path).unwrap();
        append(&path, b"new\n");
        let mut out = Vec::new();
        relay.pump(&mut out).unwrap();
        assert_eq!(out, b"new\n");
        cleanup(&path);
    }

    #[test]
    fn collapse_removes_relayed_prefix_losslessly() {
        if native_tier() != Compaction::Collapse {
            eprintln!("skipping: temp filesystem does not support FALLOC_FL_COLLAPSE_RANGE");
            return;
        }
        let path = ready("c.log");
        let mut relay = Relay::provision(&path).unwrap();
        let bs = relay.blksize as usize;
        let (mut out, mut expected) = (Vec::new(), Vec::new());
        for round in 0..20u8 {
            let data = vec![b'a' + round; bs / 2 + 7];
            append(&path, &data);
            expected.extend_from_slice(&data);
            relay.pump(&mut out).unwrap();
            assert!(
                size(&path) < 2 * bs as u64,
                "file stays within a couple of blocks: {}",
                size(&path)
            );
        }
        assert_eq!(out, expected, "every byte relayed exactly once, in order");
        assert_eq!(size(&path), relay.offset);
        cleanup(&path);
    }

    #[test]
    fn collapse_leaves_last_block_when_data_ends_on_a_boundary() {
        if native_tier() != Compaction::Collapse {
            return;
        }
        let path = ready("b.log");
        let mut relay = Relay::provision(&path).unwrap();
        let bs = relay.blksize as usize;
        append(&path, &vec![b'x'; 2 * bs]);
        let mut out = Vec::new();
        relay.pump(&mut out).unwrap();
        assert_eq!(out.len(), 2 * bs);
        assert_eq!(
            size(&path),
            bs as u64,
            "one block collapsed, the last one kept (range must end before EOF)"
        );
        append(&path, b"more\n");
        relay.pump(&mut out).unwrap();
        assert!(out.ends_with(b"more\n"));
        cleanup(&path);
    }

    #[test]
    fn punch_deallocates_relayed_prefix_losslessly() {
        // Supported by every filesystem we may run the tests on (ext4, xfs, tmpfs, btrfs).
        let path = ready("p.log");
        let mut relay = Relay::provision(&path).unwrap();
        relay.force_compaction(Compaction::Punch);
        let bs = relay.blksize as usize;
        let (mut out, mut expected) = (Vec::new(), Vec::new());
        for round in 0..20u8 {
            let data = vec![b'a' + round; bs / 2 + 7];
            append(&path, &data);
            expected.extend_from_slice(&data);
            relay.pump(&mut out).unwrap();
        }
        assert_eq!(out, expected, "every byte relayed exactly once, in order");
        assert_eq!(relay.compaction(), Compaction::Punch, "punching stayed supported");
        assert_eq!(size(&path), expected.len() as u64, "logical size untouched");
        // 20 * (bs/2 + 7) bytes were written; all but the last (partial) block are deallocated.
        assert!(
            blocks(&path) * 512 <= 2 * bs as u64,
            "at most a couple of blocks allocated, got {} bytes",
            blocks(&path) * 512
        );
        cleanup(&path);
    }

    #[test]
    fn tmpfs_is_probed_to_punch() {
        let shm = Path::new("/dev/shm");
        if !shm.is_dir() {
            eprintln!("skipping: no /dev/shm");
            return;
        }
        let path = shm.join(format!("docker-snitch-test-{}.log", std::process::id()));
        let mut relay = Relay::provision(&path).unwrap();
        assert_eq!(relay.compaction(), Compaction::Punch);
        let mut out = Vec::new();
        let bs = relay.blksize as usize;
        append(&path, &vec![b'z'; 3 * bs + 1]);
        relay.pump(&mut out).unwrap();
        assert_eq!(out.len(), 3 * bs + 1);
        assert_eq!(size(&path), (3 * bs + 1) as u64, "sparse: apparent size kept");
        assert!(blocks(&path) * 512 <= 2 * bs as u64, "but only the tail is allocated");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn finish_relays_remainder_and_empties_the_file() {
        let path = ready("f.log");
        let mut relay = Relay::provision(&path).unwrap();
        append(&path, b"last words\n");
        let mut out = Vec::new();
        relay.finish(&mut out).unwrap();
        assert_eq!(out, b"last words\n");
        assert_eq!(size(&path), 0);
        assert!(path.is_file(), "the file is emptied, not removed");
        cleanup(&path);
    }

    #[test]
    fn follows_external_truncation() {
        let path = ready("t.log");
        let mut relay = Relay::provision(&path).unwrap();
        let mut out = Vec::new();
        append(&path, b"first\n");
        relay.pump(&mut out).unwrap();
        fs::write(&path, b"").unwrap(); // truncated by someone else
        append(&path, b"x\n");
        relay.pump(&mut out).unwrap();
        assert_eq!(out, b"first\nx\n");
        cleanup(&path);
    }

    #[test]
    fn follows_rename_rotation_and_removal() {
        let path = ready("r.log");
        let mut relay = Relay::provision(&path).unwrap();
        let mut out = Vec::new();
        append(&path, b"a\n");
        let rotated = path.with_extension("log.1");
        fs::rename(&path, &rotated).unwrap();
        append(&rotated, b"b\n"); // written to the old inode after the rename, before we noticed
        fs::write(&path, b"c\n").unwrap(); // new file at the same name
        relay.pump(&mut out).unwrap();
        assert_eq!(out, b"a\nb\nc\n");
        fs::remove_file(&path).unwrap();
        relay.pump(&mut out).unwrap();
        assert!(path.is_file(), "removed file is re-provisioned");
        append(&path, b"d\n");
        relay.pump(&mut out).unwrap();
        assert_eq!(out, b"a\nb\nc\nd\n");
        cleanup(&path);
    }
}
