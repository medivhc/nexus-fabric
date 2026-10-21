//! Safe, nonblocking Linux advisory file leases for composition roots.

use std::{fs::File, io, os::unix::io::AsRawFd};

/// Acquires an exclusive advisory lease without waiting for another owner.
///
/// `WouldBlock` means another independently opened file description holds the
/// lease. The caller must retain `file` for its entire protected operation;
/// closing all descriptors for this file description releases the lease. A
/// cloned `File` shares its lease; a separate `File::open` competes for it.
///
/// This primitive does not validate paths, permissions, or file identity, and
/// an advisory lease cannot prevent non-cooperating processes from writing.
pub fn try_lock_exclusive(file: &File) -> io::Result<()> {
    const LOCK_EX: std::ffi::c_int = 2;
    const LOCK_NB: std::ffi::c_int = 4;
    flock_operation(file, LOCK_EX | LOCK_NB)
}

/// Releases the advisory lease on this open file description.
///
/// This also releases the lease shared by cloned or inherited descriptors.
/// Call only when their logical owner has finished its protected operation;
/// another independently opened description's lease is unaffected. Ordinary
/// `File` drop and clone semantics are unchanged.
pub fn unlock_exclusive(file: &File) -> io::Result<()> {
    const LOCK_UN: std::ffi::c_int = 8;
    flock_operation(file, LOCK_UN)
}

fn flock_operation(file: &File, operation: std::ffi::c_int) -> io::Result<()> {
    unsafe extern "C" {
        fn flock(fd: std::ffi::c_int, op: std::ffi::c_int) -> std::ffi::c_int;
    }
    loop {
        // SAFETY: `file` owns a live descriptor throughout this call. Linux
        // flock accepts these integer operation flags and retains no pointers.
        if unsafe { flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
