// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

#[cfg(unix)]
pub mod posix {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    use anyhow::anyhow;
    use libc::{geteuid, getpwuid_r, strerror};


    pub fn get_posix_user_home_dir() -> anyhow::Result<Option<PathBuf>> {
        let uid = unsafe { geteuid() };
        
        let mut buf = [0i8; 16374];
        let result: anyhow::Result<Option<PathBuf>>;
        let mut passwd = libc::passwd {
            pw_name: null_mut(),
            pw_passwd: null_mut(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: null_mut(),
            pw_dir: null_mut(),
            pw_shell: null_mut()
        };

        let mut getpwuid_result: *mut libc::passwd = null_mut();
        let rc = unsafe {
            getpwuid_r(uid, &mut passwd, buf.as_mut_ptr(), buf.len(), &mut getpwuid_result)
        };

        if rc == 0 {
            if getpwuid_result == null_mut() {
                result = Ok(None);
            }
            else {
                let home_dir_cptr = unsafe {
                    CStr::from_ptr((*getpwuid_result).pw_dir)
                };
                let home_dir = OsStr::from_bytes(home_dir_cptr.to_bytes());
                result = Ok(Some(PathBuf::from(home_dir)));
            }
        }
        else {
            let error_msg_cptr = unsafe {
                CStr::from_ptr(strerror(rc))
            };
            let error_str = String::from_utf8_lossy(error_msg_cptr.to_bytes());
            result = Err(anyhow!("{}", error_str));
        }

        result
    }
}


#[cfg(windows)]
pub mod windows {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{LocalFree, E_INVALIDARG, HLOCAL, S_OK};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
        FORMAT_MESSAGE_IGNORE_INSERTS,
    };
    use windows_sys::Win32::System::SystemServices::{LANG_NEUTRAL, SUBLANG_DEFAULT};
    use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_LocalAppData, FOLDERID_ProgramData};


    #[inline]
    unsafe fn wstr_len(ptr: *const u16) -> usize {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        len
    }


    #[inline]
    fn make_lang_id(primaryId: u32, sublangId: u32) -> u32 {
        (sublangId << 10) | primaryId
    }


    pub fn WindowsFormatMessage(hr: HRESULT) -> String {
        let result: String;

        unsafe {
            let mut buffer: *mut u16 = null_mut();
            
            let length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                hr,
                make_lang_id(LANG_NEUTRAL, SUBLANG_DEFAULT),
                &mut buffer as *mut *mut u16 as _, // Cast to PWSTR/LPTSTR
                0,
                null_mut()
            );

            if length == 0 {
                result = format!("Error code: {}", hr);
            }
            else {
                let slice = std::slice::from_raw_parts(buffer, length as usize);
                result = String::from_utf16_lossy(slice).trim().to_string();
                LocalFree(buffer as HLOCAL);
            }
        }

        result
    }


    pub fn get_windows_known_folder(guid: GUID) -> anyhow::Result<Option<PathBuf>> {
        let mut ptr: PWSTR = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(guid, 0, null, &ptr);

        let result: anyhow::Result<PathBuf>;
        if hr == S_OK {
            let ptr_len = wstr_len(ptr as *const u16);
            let ptr_slice = std::slice::from_raw_parts(ptr as *const u16, ptr_len);
            let path_osstr = OsString::from_wide(ptr_slice);
            result = Ok(Some(PathBuf::from(path_osstr)));
        }
        else if hr == E_INVALIDARG {
            result = Ok(None);  // No such known-folder on *this* system.
        }
        else {
            result = Err(anyhow!("{}", WindowsFormatMessage(hr)));
        }

        if ptr != std::ptr::null_mut() {
            CoTaskMemFree(ptr as *const c_void);
        }

        result
    }


    pub fn get_user_local_app_data_folder() -> anyhow::Result<Option<PathBuf>> {
        get_windows_known_folder(FOLDERID_LocalAppData)
    }


    pub fn get_program_data_folder() -> anyhow::Result<Option<PathBuf>> {
        get_windows_known_folder(FOLDERID_ProgramData)
    }
}
