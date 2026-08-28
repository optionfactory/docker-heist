//! Small shared helpers for the docker-heist tools' parent-side signal handling.
//!
//! Two flavours, for two kinds of wrapper:
//!
//! - A wrapper that wants to ignore the terminal signals its child handles
//!   itself, but catch `SIGTERM` so it can forward it to the child (rather than
//!   being ignored or leaving it orphaned): [`install`] + [`terminate_requested`].
//! - A wrapper that forwards a whole set of signals to its child as they arrive
//!   (an init-like parent): [`install_forwarding`] + [`forward_pending`].
//!
//! This crate owns the fiddly bits - the flags, the `sigaction` setup, the
//! handler casts - so the tools share one correct implementation. Each tool
//! keeps its own wait loop (they reap their child differently).

use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static TERMINATED: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU64 = AtomicU64::new(0);

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

extern "C" fn on_forwarded(sig: c_int) {
    PENDING.fetch_or(1 << sig, Ordering::Relaxed);
}

/// In the parent: catch each of `signals` with a *restarting* handler (our own
/// blocking syscalls are not disturbed) that records it in a pending mask, to be
/// delivered to the child by [`forward_pending`]. Signal numbers must be below 64.
pub fn install_forwarding(signals: &[c_int]) {
    for &sig in signals {
        assert!(
            (0..64).contains(&sig),
            "signal number out of range for the pending mask"
        );
        // SAFETY: sigaction with a valid handler and an empty mask.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_forwarded as extern "C" fn(c_int) as *const libc::c_void as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Send `child` every signal recorded by the [`install_forwarding`] handler since
/// the last call, then clear them. Each distinct signal is delivered once, in
/// numeric order, mirroring the kernel's own coalescing of standard signals.
pub fn forward_pending(child: libc::pid_t) {
    let mut pending = PENDING.swap(0, Ordering::Relaxed);
    while pending != 0 {
        let sig = pending.trailing_zeros() as c_int;
        pending &= !(1u64 << sig);
        // SAFETY: signalling the caller's own child.
        unsafe { libc::kill(child, sig) };
    }
}

/// Returns whether a `SIGTERM` is pending *without* clearing the flag, so a
/// later [`terminate_requested`] still sees it. Useful to break an intermediate
/// poll loop early and let the main wait loop do the actual forwarding.
pub fn terminate_pending() -> bool {
    TERMINATED.load(Ordering::Relaxed)
}
