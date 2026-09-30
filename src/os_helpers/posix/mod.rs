// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use anyhow::anyhow;
use libc::{geteuid, getpwuid_r, strerror};
use log::warn;

use super::PlatformStringDecoder;


#[cfg(feature = "native-decode")]
mod decode_native;

#[cfg(feature = "native-decode")]
pub use decode_native::CodeSetDecoder as NativeDecoder;


#[cfg(not(feature = "native-decode"))]
mod decode_simple;

#[cfg(not(feature = "native-decode"))]
pub use decode_simple::SimpleDecoder as NativeDecoder;

/// Get the current user's home directory
pub fn get_posix_user_home_dir() -> anyhow::Result<Option<PathBuf>> {
    // NOTE: Although the $HOME environment variable is *common*, it isn't
    // universally available (e.g., systemd units on Linux don't expose it by
    // default). So we use POSIX-standardized methods instead.

    // This value is deliberately huge to minimize the chance of needing re-allocation.
    const FALLBACK_INITIAL_PASSWD_ENTRY_BUFFER_SIZE: usize = 4096;
    const MAXIMUM_PASSWD_ENTRY_BUFFER_SIZE: usize = 65536;

    // Try to get system-provided recommended size for a passwd entry, with fallback if not available.
    let mut buf_size = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        -1 => FALLBACK_INITIAL_PASSWD_ENTRY_BUFFER_SIZE,
        size => size as usize
    };

    let uid = unsafe { geteuid() };

    let mut passwd_entry_buffer = Vec::<i8>::with_capacity(buf_size);
    let mut passwd_entry = libc::passwd {
        pw_name: null_mut(),
        pw_passwd: null_mut(),
        pw_uid: 0,
        pw_gid: 0,
        pw_gecos: null_mut(),
        pw_dir: null_mut(),
        pw_shell: null_mut(),
    };

    loop {
        let mut getpwuid_result: *mut libc::passwd = null_mut();
        let rc = unsafe {
            getpwuid_r(
                uid,
                &mut passwd_entry,
                passwd_entry_buffer.as_mut_ptr(),
                passwd_entry_buffer.len(),
                &mut getpwuid_result,
            )
        };

        match rc {
            0 => {
                if getpwuid_result.is_null() || unsafe { (*getpwuid_result).pw_dir.is_null() } {
                    break;
                }
                else {
                    let home_dir_cptr = unsafe { CStr::from_ptr((*getpwuid_result).pw_dir) };
                    if home_dir_cptr.is_empty() {
                        break;
                    }
                    let home_dir_osstr = OsStr::from_bytes(home_dir_cptr.to_bytes());
                    let home_dir = PathBuf::from(home_dir_osstr);
                    if !home_dir.is_dir() {
                        break;
                    }
                    return Ok(Some(home_dir));
                }
            }
            libc::ERANGE => {
                let next_buf_size = std::cmp::min(buf_size * 2, MAXIMUM_PASSWD_ENTRY_BUFFER_SIZE);
                if buf_size == next_buf_size {
                    warn!("Ignoring user's homedir: required size exceeds maximum ({MAXIMUM_PASSWD_ENTRY_BUFFER_SIZE}B)");
                    break;
                }
                else {
                    buf_size = next_buf_size;
                    passwd_entry_buffer.resize(buf_size, 0i8);
                    continue;
                }
            }
            libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => {
                break;
            }
            libc::EINTR => {
                // Ignore and try again
            }
            _ => {
                let error_msg_cptr = unsafe { CStr::from_ptr(strerror(rc)) };
                let error_str = String::from_utf8_lossy(error_msg_cptr.to_bytes());
                return Err(anyhow!(
                    "Failed to retrieve user information for UID={}: {}",
                    uid,
                    error_str
                ));
            }
        }
    }
    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::env::var_os;


    #[test]
    fn test_get_home_dir_returns_users_homedir_when_available() {
        let maybe_home_dir = get_posix_user_home_dir();
        assert!(
            maybe_home_dir.is_ok(),
            "Expected get_posix_user_home_dir to succeed: {:?}",
            maybe_home_dir.unwrap_err()
        );

        let home_dir = maybe_home_dir.unwrap();
        let env_home_dir = var_os("HOME").map(|oss| PathBuf::from(oss));
        assert_eq!(home_dir, env_home_dir);
    }
}
