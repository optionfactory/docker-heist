mod cli;
mod relay;

use relay::Relay;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, exit};

/// Signals forwarded to the child. SIGCHLD is handled by reaping; SIGKILL/SIGSTOP can't be caught.
const FORWARDED: [c_int; 6] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGHUP,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

fn main() {
    let config = match cli::parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("docker-snitch: {e}");
            exit(1);
        }
    };
    match run(config) {
        Ok(code) => exit(code),
        Err(e) => {
            eprintln!("docker-snitch: {e}");
            exit(1);
        }
    }
}

fn run(config: cli::Config) -> Result<i32, String> {
    // Files exist before the daemon starts, so it can open them right away.
    let mut relays = config
        .files
        .iter()
        .map(|p| Relay::provision(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut sparse_dirs: Vec<&std::path::Path> = relays
        .iter()
        .filter(|r| r.compaction() == relay::Compaction::Punch)
        .filter_map(|r| r.path().parent())
        .collect();
    sparse_dirs.sort();
    sparse_dirs.dedup();
    for dir in sparse_dirs {
        eprintln!(
            "docker-snitch: '{}': filesystem does not support collapse-range, punching holes instead (files stay small on disk but sparse: their apparent size keeps growing)",
            dir.display()
        );
    }
    // One entry per relay: the last error reported for it, to avoid repeating it every interval.
    let mut reported: Vec<Option<String>> = vec![None; relays.len()];

    // Orphans of the child get reparented to us even when we are not PID 1.
    // SAFETY: plain prctl with constant arguments.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };

    signals::install_forwarding(&FORWARDED);

    let (program, args) = config.cmd.split_first().ok_or("Missing command to execute")?;
    let mut command = Command::new(program);
    command.args(args);
    // SAFETY: only async-signal-safe calls (signal(2)) before exec.
    unsafe {
        command.pre_exec(|| {
            signals::reset_to_default(&FORWARDED);
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|e| format!("Failed to exec '{program}': {e}"))?;
    let child_pid = child.id() as libc::pid_t;

    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out: Box<dyn Write> = if config.to_stdout {
        Box::new(stdout.lock())
    } else {
        Box::new(stderr.lock())
    };

    let mut exit_status = None;
    while exit_status.is_none() {
        signals::forward_pending(child_pid);
        exit_status = reap(child_pid)?;
        pump(&mut relays, out.as_mut(), &mut reported);
        if exit_status.is_none() {
            std::thread::sleep(config.interval);
        }
    }
    // Whatever the daemon logged while shutting down is still relayed, then the files are emptied.
    for relay in relays.iter_mut() {
        if let Err(e) = relay.finish(out.as_mut()) {
            eprintln!("docker-snitch: '{}': {e}", relay.path().display());
        }
    }

    let status = std::process::ExitStatus::from_raw(exit_status.unwrap_or(0));
    Ok(match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        (None, None) => 1,
    })
}

/// Reap every finished descendant (init duty); return the raw wait status if the
/// one that finished is our child.
fn reap(child: libc::pid_t) -> Result<Option<c_int>, String> {
    let mut child_status = None;
    loop {
        let mut status: c_int = 0;
        // SAFETY: waitpid on any child with a valid status pointer, non-blocking.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            return Ok(child_status);
        }
        if pid < 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => Ok(child_status),
                _ => Err(format!("waitpid failed: {err}")),
            };
        }
        if pid == child && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            child_status = Some(status);
        }
    }
}

/// Pump every relay. Losing a log tail must never take the daemon down, so errors
/// are reported and swallowed; a persistent one is reported once, not every interval.
fn pump(relays: &mut [Relay], out: &mut dyn Write, reported: &mut [Option<String>]) {
    for (relay, last) in relays.iter_mut().zip(reported.iter_mut()) {
        match relay.pump(out) {
            Ok(()) => {
                if last.take().is_some() {
                    eprintln!("docker-snitch: '{}': recovered", relay.path().display());
                }
            }
            Err(e) => {
                let msg = format!("'{}': {e}", relay.path().display());
                if last.as_deref() != Some(msg.as_str()) {
                    eprintln!("docker-snitch: {msg}");
                    *last = Some(msg);
                }
            }
        }
    }
}
