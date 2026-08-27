//! Small shared helpers for the docker-heist tools' parent-side signal handling.
//!
//! A wrapper wants to ignore the terminal signals its child handles itself, but
//! catch `SIGTERM` so it can forward it to the child (rather than being ignored
//! or leaving it orphaned). This crate owns that fiddly bit - the flag, the
//! non-restarting `sigaction`, and the handler cast - so both tools share one
//! correct implementation. Each tool keeps its own wait/forward loop (they reap
//! their child differently).

use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: c_int) {
    TERMINATED.store(true, Ordering::Relaxed);
}

/// In the parent: ignore `ignored`, and catch `SIGTERM` with a *non-restarting*
/// handler (so a blocking `waitpid` returns `EINTR`) that sets a flag readable
/// via [`terminate_requested`].
pub fn install(ignored: &[c_int]) {
    // SAFETY: installing SIG_IGN and a sigaction with a valid handler are sound.
    unsafe {
        for &sig in ignored {
            libc::signal(sig, libc::SIG_IGN);
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_term as extern "C" fn(c_int) as *const libc::c_void as libc::sighandler_t;
        sa.sa_flags = 0; // no SA_RESTART, so waitpid returns EINTR
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Reset `signals` to their default disposition. Async-signal-safe, so it is
/// safe to call in a child before exec (e.g. from `Command::pre_exec`) to give
/// the target normal signal dispositions.
pub fn reset_to_default(signals: &[c_int]) {
    for &sig in signals {
        // SAFETY: installing SIG_DFL is always sound.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    }
}

/// Returns `true` exactly once after each `SIGTERM`: it reads and clears the flag
/// the [`install`]ed handler sets.
pub fn terminate_requested() -> bool {
    TERMINATED.swap(false, Ordering::Relaxed)
}

/// Returns whether a `SIGTERM` is pending *without* clearing the flag, so a
/// later [`terminate_requested`] still sees it. Useful to break an intermediate
/// poll loop early and let the main wait loop do the actual forwarding.
pub fn terminate_pending() -> bool {
    TERMINATED.load(Ordering::Relaxed)
}
