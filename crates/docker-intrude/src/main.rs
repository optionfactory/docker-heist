mod cli;
mod docker;

use docker::DockerClient;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, exit};

fn main() {
    let config = match cli::parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("docker-intrude: {e}");
            exit(1);
        }
    };

    match execute_in_namespace(config) {
        Ok(code) => {
            if code != 0 {
                exit(code);
            }
        }
        Err(e) => {
            eprintln!("docker-intrude: {e}");
            exit(1);
        }
    }
}

fn execute_in_namespace(config: cli::Config) -> Result<i32, String> {
    let docker = DockerClient::new(config.verbose)?;
    docker.ping()?;

    if config.verbose {
        println!(":: Preparing Docker network holder ({}) ::", config.name);
    }

    let _cleanup_guard = docker.provision_network_holder(&config.name, &config.net, &config.ip)?;
    let pid = docker.get_container_pid(&config.name)?;

    let ns_path = format!("/proc/{pid}/ns/net");
    let ns_file = File::open(&ns_path).map_err(|e| format!("Failed to open namespace file {ns_path}: {e}"))?;

    let meta = ns_file
        .metadata()
        .map_err(|e| format!("Failed to read namespace file descriptor metadata: {e}"))?;
    let pid_owner_uid = meta.uid();

    if pid_owner_uid != docker.socket_uid {
        return Err(format!(
            "Target namespace is owned by UID {pid_owner_uid}, but the Docker socket is owned by UID {}. Aborting due to potential privilege escalation.",
            docker.socket_uid
        ));
    }

    let post_open_pid = docker.get_container_pid(&config.name)?;
    if pid != post_open_pid {
        return Err(format!(
            "Container state changed while attaching to namespace (PID changed from {pid} to {post_open_pid}). The container may have restarted or terminated."
        ));
    }

    if config.verbose {
        println!(":: Entering namespace ::");
    }

    // SAFETY: fork; the child branch does its work and never returns into code
    // that could deadlock on a lock held at fork time (single-threaded here).
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("Process fork failed: {}", std::io::Error::last_os_error()));
    }

    if child == 0 {
        // ---- child ----
        let run_child = move || -> Result<(), String> {
            enter_net_namespace(&ns_file)?;
            mount_resolve_conf()?;
            drop_capabilities(config.strict, config.lax)?;
            let (program, args) = config.cmd.split_first().ok_or("No command specified to execute")?;
            let err = Command::new(program).args(args).exec();
            Err(format!("Failed to exec target command: {err}"))
        };
        match run_child() {
            Ok(()) => unsafe { libc::_exit(0) },
            Err(e) => fail_fast(&e),
        }
    }

    // ---- parent ----
    drop(ns_file);
    drop_parent_capabilities()?;
    // Ignore the terminal signals the child handles itself, and catch SIGTERM so
    // the waitpid loop below (interrupted by EINTR) can forward it to the child.
    signals::install(&[libc::SIGINT, libc::SIGQUIT, libc::SIGHUP]);

    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid on our own child with a valid status pointer.
        let r = unsafe { libc::waitpid(child, &mut status, 0) };
        if r == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                if signals::terminate_requested() {
                    return terminate_child_gracefully(child);
                }
                continue;
            }
            return Err(format!("Failed to harvest child process exit status: {err}"));
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Err(format!(
                "Child process terminated by signal: {}",
                libc::WTERMSIG(status)
            ));
        }
        // stopped/continued: keep waiting.
    }
}

/// `setns(2)` the open network-namespace file into CLONE_NEWNET.
fn enter_net_namespace(ns_file: &File) -> Result<(), String> {
    // SAFETY: valid fd; CLONE_NEWNET selects the network namespace type.
    let rc = unsafe { libc::setns(ns_file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(format!(
            "Failed to setns. Ensure binary has CAP_SYS_ADMIN and CAP_SYS_PTRACE: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn fail_fast(msg: &str) -> ! {
    unsafe {
        for part in [b"docker-intrude: ".as_slice(), msg.as_bytes(), b"\n".as_slice()] {
            let _ = libc::write(libc::STDERR_FILENO, part.as_ptr() as *const libc::c_void, part.len());
        }
        libc::_exit(1);
    }
}

const SECBIT_NOROOT: libc::c_ulong = 0x01;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 0x02;
const SECBIT_NO_CAP_AMBIENT_RAISE: libc::c_ulong = 0x40;
const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: libc::c_ulong = 0x80;

// NOROOT must be LOCKED: any process can clear securebits via prctl without
// requiring any capability, so an unlocked NOROOT is advisory only. Ambient
// raise is locked as well since we clear the Ambient set below.
const SECUREBITS_MASK: libc::c_ulong =
    SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;

fn drop_capabilities(strict: bool, lax: bool) -> Result<(), String> {
    if !lax {
        // SAFETY: plain prctl setting the securebits mask.
        let res = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, SECUREBITS_MASK, 0, 0, 0) };
        if res != 0 {
            return Err(format!(
                "Failed to set securebits (NOROOT+ambient-raise, locked) via prctl: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    // Bounding first (it needs CAP_SETPCAP, which the effective set still holds).
    if strict {
        privileges::clear_bounding()?;
    }
    privileges::clear_eff_perm_inh()?;
    privileges::clear_ambient()?;
    Ok(())
}

fn drop_parent_capabilities() -> Result<(), String> {
    privileges::drop_all()
}

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| format!("path contains an interior NUL byte: {s:?}"))
}

/// `mount(source, target, NULL, flags, NULL)`.
fn do_mount(source: Option<&str>, target: &str, flags: libc::c_ulong, what: &str) -> Result<(), String> {
    let c_source = source.map(cstr).transpose()?;
    let c_target = cstr(target)?;
    let src_ptr = c_source.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
    // SAFETY: valid NUL-terminated pointers (or NULL); fstype/data unused.
    let rc = unsafe { libc::mount(src_ptr, c_target.as_ptr(), std::ptr::null(), flags, std::ptr::null()) };
    if rc != 0 {
        return Err(format!("Failed to {what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn mount_resolve_conf() -> Result<(), String> {
    // Unshare the mount namespace so our changes don't touch the host.
    // SAFETY: plain unshare with a constant flag.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "Failed to unshare mount namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Prevent mount propagation back to the host.
    do_mount(None, "/", libc::MS_REC | libc::MS_PRIVATE, "make root mount private")?;

    let tmp_path = format!(
        "/dev/shm/docker-intrude-resolv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    );

    let mut tmp_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create secure shm file: {e}"))?;

    tmp_file
        .write_all(b"nameserver 127.0.0.11\noptions ndots:0\n")
        .map_err(|e| format!("Failed to write to shm file: {e}"))?;

    // Bind-mount the memory file over resolv.conf, then unlink the source.
    let mount_res = do_mount(
        Some(&tmp_path),
        "/etc/resolv.conf",
        libc::MS_BIND,
        "bind mount resolv.conf",
    );
    let _ = std::fs::remove_file(Path::new(&tmp_path));
    mount_res
}

fn terminate_child_gracefully(child: libc::pid_t) -> Result<i32, String> {
    const EXIT_CODE_SIGTERM: i32 = 143;
    // SAFETY: signalling our own child.
    unsafe { libc::kill(child, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid on our own child.
        let r = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if r == 0 {
            std::thread::sleep(std::time::Duration::from_millis(50)); // still alive
            continue;
        }
        if r < 0 {
            return Ok(0); // already reaped / error
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(EXIT_CODE_SIGTERM);
        }
        return Ok(0);
    }
    // child ignored SIGTERM: escalate to SIGKILL and reap.
    // SAFETY: signalling / reaping our own child.
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status: libc::c_int = 0;
        libc::waitpid(child, &mut status, 0);
    }
    Err("Child process unresponsive to SIGTERM; forcefully terminated with SIGKILL".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: we assert on the composed mask rather than calling prctl, because
    // SECBIT_*_LOCKED is irreversible for the lifetime of the process - actually
    // invoking drop_capabilities() would poison the test runner. The mask IS the
    // security property, so guarding its composition is the meaningful check.

    #[test]
    fn securebits_locks_noroot() {
        assert_ne!(
            SECUREBITS_MASK & SECBIT_NOROOT_LOCKED,
            0,
            "SECBIT_NOROOT must be locked; an unlocked NOROOT is advisory only \
             (any process can clear it via prctl without a capability)."
        );
        assert_ne!(SECUREBITS_MASK & SECBIT_NOROOT, 0);
    }

    #[test]
    fn securebits_locks_ambient_raise() {
        assert_ne!(SECUREBITS_MASK & SECBIT_NO_CAP_AMBIENT_RAISE, 0);
        assert_ne!(SECUREBITS_MASK & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED, 0);
    }

    #[test]
    fn securebits_does_not_touch_unrelated_flags() {
        // KEEPCAPS and NO_SETUID_FIXUP are intentionally not set: the target is
        // not expected to perform UID transitions.
        const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 0x04;
        const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 0x08;
        const SECBIT_KEEP_CAPS: libc::c_ulong = 0x10;
        const SECBIT_KEEP_CAPS_LOCKED: libc::c_ulong = 0x20;
        let unused =
            SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
        assert_eq!(SECUREBITS_MASK & unused, 0);
    }

    #[test]
    fn securebits_values_match_kernel_constants() {
        // Guards against bit-value drift if someone rewrites these consts.
        assert_eq!(SECBIT_NOROOT, 0x01);
        assert_eq!(SECBIT_NOROOT_LOCKED, 0x02);
        assert_eq!(SECBIT_NO_CAP_AMBIENT_RAISE, 0x40);
        assert_eq!(SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED, 0x80);
    }
}
