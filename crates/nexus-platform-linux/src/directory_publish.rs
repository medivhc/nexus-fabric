//! Atomic no-replace publication; callers own private parent validation and
//! file/directory fsync.

use std::{
    ffi::{CString, c_char, c_int, c_uint},
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
};

/// Atomically moves source to a previously absent destination. Linux's
/// primitive supports files and directories. An existing target is preserved.
/// Callers validate parent scope/permissions and synchronize files/directories.
/// `Unsupported` means the kernel or filesystem cannot guarantee no-replace;
/// this function never falls back to an overwriting rename.
pub fn publish_directory_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    publish_directory_no_replace_inner(
        source,
        destination,
        #[cfg(test)]
        None,
    )
}

// Both entrypoints share the syscall/error handling path. The test
// argument belongs to one call and will replace only that call's OS result;
// it must not bypass the shared error mapping or choose a separate fallback.
fn publish_directory_no_replace_inner(
    source: &Path,
    destination: &Path,
    #[cfg(test)] syscall_error: Option<i32>,
) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    unsafe extern "C" {
        fn renameat2(
            olddirfd: c_int,
            oldpath: *const c_char,
            newdirfd: c_int,
            newpath: *const c_char,
            flags: c_uint,
        ) -> c_int;
    }
    const AT_FDCWD: c_int = -100;
    const RENAME_NOREPLACE: c_uint = 1;
    let syscall = || {
        // SAFETY INVARIANT: both CStrings contain terminated path bytes and
        // remain alive throughout renameat2. AT_FDCWD and RENAME_NOREPLACE are
        // Linux ABI constants; the kernel reads but does not retain pointers.
        if unsafe {
            renameat2(
                AT_FDCWD,
                source.as_ptr(),
                AT_FDCWD,
                destination.as_ptr(),
                RENAME_NOREPLACE,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    #[cfg(test)]
    let result = match syscall_error {
        Some(errno) => Err(io::Error::from_raw_os_error(errno)),
        None => syscall(),
    };
    #[cfg(not(test))]
    let result = syscall();
    result.map_err(|error| match error.raw_os_error() {
        Some(22 | 38) => io::Error::new(io::ErrorKind::Unsupported, error),
        _ => error,
    })
}

#[cfg(test)]
fn publish_with_test_error(source: &Path, destination: &Path, errno: i32) -> io::Result<()> {
    publish_directory_no_replace_inner(source, destination, Some(errno))
}

#[cfg(test)]
#[path = "directory_publish_tests.rs"]
mod tests;

#[cfg(test)]
mod error_regressions {
    use super::*;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    #[test]
    fn no_replace_embedded_nul_is_invalid_before_syscall() {
        let invalid = Path::new(OsStr::from_bytes(b"not-a-path\0tail"));
        let valid = Path::new("valid-path");
        for (source, destination) in [(invalid, valid), (valid, invalid)] {
            assert_eq!(
                publish_directory_no_replace(source, destination)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn no_replace_other_os_errors_preserve_raw_diagnostic() {
        for errno in [2, 13, 18, 28] {
            let error = publish_with_test_error(Path::new("source"), Path::new("target"), errno)
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert_eq!(error.kind(), io::Error::from_raw_os_error(errno).kind());
        }
    }
}
