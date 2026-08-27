//! Linux capability operations via raw `libc`/`prctl`, shared by the
//! docker-heist tools. All-or-nothing: a whole set is dropped at once, since
//! that is all these tools need.

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `CAP_SYS_ADMIN`'s capability number.
pub const CAP_SYS_ADMIN: u8 = 21;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// True if `cap` is in the process's current *effective* set.
pub fn has_effective(cap: u8) -> bool {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    // Version 3 uses two 32-bit data blocks (capabilities 0..63).
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget fills `data` for the header we provide; both are valid pointers.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut hdr as *mut CapHeader, data.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    let (idx, bit) = ((cap / 32) as usize, cap % 32);
    idx < data.len() && data[idx].effective & (1 << bit) != 0
}

/// Zero the effective, permitted and inheritable capability sets in one
/// `capset(2)`. Dropping capabilities is always permitted, so this needs no
/// privilege - but it also removes `CAP_SETPCAP`, so if you also want to drop
/// the bounding set, call [`clear_bounding`] *before* this.
pub fn clear_eff_perm_inh() -> Result<(), String> {
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset reads a valid header and two data blocks we own.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(format!("capset(clear all sets): {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Clear the ambient capability set.
pub fn clear_ambient() -> Result<(), String> {
    // SAFETY: plain prctl.
    let rc = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if rc != 0 {
        return Err(format!(
            "prctl(PR_CAP_AMBIENT_CLEAR_ALL): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Drop every capability from the bounding set. Requires `CAP_SETPCAP` in the
/// effective set, so call this *before* [`clear_eff_perm_inh`]. Iterates cap
/// numbers until the kernel reports one past `CAP_LAST_CAP` (`EINVAL`).
pub fn clear_bounding() -> Result<(), String> {
    for cap in 0..64 {
        // SAFETY: plain prctl with a capability number.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                break; // past CAP_LAST_CAP
            }
            return Err(format!("prctl(PR_CAPBSET_DROP, {cap}): {err}"));
        }
    }
    Ok(())
}

/// Drop *everything*: the bounding set, then the effective/permitted/inheritable
/// sets, then the ambient set. The bounding step needs `CAP_SETPCAP`; if the
/// process was not granted it, use [`clear_eff_perm_inh`] + [`clear_ambient`]
/// instead (which still removes every capability the process can act on).
pub fn drop_all() -> Result<(), String> {
    clear_bounding()?;
    clear_eff_perm_inh()?;
    clear_ambient()?;
    Ok(())
}
