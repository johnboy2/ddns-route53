// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

#[cfg(unix)]
pub mod posix {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    use anyhow::anyhow;
    use libc::{geteuid, getpwuid_r, nl_langinfo, strerror, CHARSET};
    use log::warn;

    #[cfg(feature = "native-decode")]
    pub fn get_active_code_set() -> Option<String> {
        let ptr = libc::nl_langinfo(CHARSET);

        if ptr.is_null() {
            panic!("nl_langinfo() returned NULL - which should be impossible");
        }

        let c_str = CStr::from_ptr(ptr);
        let result = if c_str.is_empty() {
            String::from_utf8("C")
        }
        else {
            c_str.to_string_lossy().into_owned()
        };

        log::debug!("Using codeset {}", result.as_str());
        Some(result)
    }

    /// Converts a byte slice to a UTF8 string using the active locale/codeset.
    #[cfg(feature = "native-decode")]
    pub fn convert_slice_to_string(
        input: &[u8],
    ) -> anyhow::Result<String> {
        let ptr = libc::nl_langinfo(CHARSET);
        if ptr.is_null() {
            convert_c_locale_slice_to_string(input)
        }
        else {
            convert_code_set_slice_to_string(input, CStr::from_ptr(ptr))
        }
    }

    /// Converts a codeset byte slice to a UTF8 string.
    #[inline]
    pub fn convert_code_set_slice_to_string(data: &[u8], code_set: CStr)  -> anyhow::Result<String> {
        if let Some(s) = code_set.to_str() {
            iconv_native::decode(input, s)
                .map_err(|e| anyhow!("Decoding error for code-set '{code_set}': {e}, got {} bytes", data.len()))
        }
        else {
            let code_set_escaped =
                code_set
                .to_bytes()
                .iter()
                .flat_map(|b| b.escape_ascii())
                .map(char::from)
                .collect::<string>()
            ;
            Err(anyhow!("Decoding error for code-set '{}': Not found", code_set_escaped.as_str()))
        }
    }

    /// Converts a C (Posix) locale byte slice to a UTF8 string.
    #[inline]
    pub fn convert_c_locale_slice_to_string(data: &[u8]) -> anyhow::Result<String> {
        if !data.is_ascii() {
            Err(anyhow!("C locale requires ASCII-only data"))
        }
        else {
            // Safety: This is okay because data is ASCII only at this point
            Ok(unsafe { String::from_utf8_unchecked(data) })
        }
    }

    /// Get the current user's home directory
    pub fn get_posix_user_home_dir() -> anyhow::Result<Option<PathBuf>> {
        const PASSWD_ENTRY_BUFFER_SIZE: usize = 16384;

        let uid = unsafe { geteuid() };

        let mut passwd_entry_buffer = [0i8; PASSWD_ENTRY_BUFFER_SIZE];
        let mut passwd_entry = libc::passwd {
            pw_name: null_mut(),
            pw_passwd: null_mut(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: null_mut(),
            pw_dir: null_mut(),
            pw_shell: null_mut(),
        };

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

        if rc != 0 {
            let error_msg_cptr = unsafe { CStr::from_ptr(strerror(rc)) };
            let error_str = String::from_utf8_lossy(error_msg_cptr.to_bytes());
            Err(anyhow!(
                "Failed to retrieve user information for UID={}: {}",
                uid,
                error_str
            ))
        } else if !getpwuid_result.is_null() {
            let home_dir_cptr = unsafe { CStr::from_ptr((*getpwuid_result).pw_dir) };
            let home_dir = OsStr::from_bytes(home_dir_cptr.to_bytes());
            Ok(Some(PathBuf::from(home_dir)))
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::env::var_os;

        #[test]
        fn test_get_home_dir() {
            let maybe_home_dir = get_posix_user_home_dir();
            assert!(
                maybe_home_dir.is_ok(),
                "err={:?}",
                maybe_home_dir.unwrap_err()
            );

            let home_dir = maybe_home_dir.unwrap();
            let env_home_dir = var_os("HOME").map(|oss| PathBuf::from(oss));
            assert_eq!(home_dir, env_home_dir);
        }

        #[test]
        #[cfg(feature = "native-decode")]
        fn test_get_encoding_for_code_set() {
            // We can't reliably predict what code-set the test environment will be configured to use, but we can at
            // least verify that the function doesn't crash and returns a consistent result.

            let data = "Test data";
            let data_utf8 = data.as_bytes();

            for code_set in ["UTF-8", "WINDOWS-1252"] {
                let maybe_result = convert_code_set_slice_to_string(code_set, data_utf8);
                assert!(
                    maybe_result.is_ok(),
                    "code_set={code_set} err={:?}",
                    maybe_result.unwrap_err()
                );
                let result = maybe_result.unwrap();
                assert_eq!(result, data, "code_set={code_set}");
            }

            let data_utf16be: Vec<u8> = data.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
            let data_utf16le: Vec<u8> = data.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            for (code_set, data_encoded) in [("UTF-16BE", data_utf16be), ("UTF-16lE", data_utf16le)]
            {
                let maybe_result =
                    convert_code_set_slice_to_string(code_set, data_encoded.as_slice());
                assert!(
                    maybe_result.is_ok(),
                    "codeset={code_set} err={:?}",
                    maybe_result.unwrap_err()
                );
                let result = maybe_result.unwrap();
                assert_eq!(result, data, "codeset={code_set}");
            }
        }
    }
}

#[cfg(windows)]
pub mod windows {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    use anyhow::anyhow;
    use windows_sys::core::{GUID, PWSTR};
    use windows_sys::Win32::Foundation::{LocalFree, E_INVALIDARG, HLOCAL, S_OK};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemServices::{LANG_NEUTRAL, SUBLANG_DEFAULT};
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath,
    };

    #[cfg(feature = "native-decode")]
    pub fn convert_code_page_slice_to_string(
        code_page: u32,
        input: &[u8],
    ) -> anyhow::Result<String> {
        use windows_sys::Win32::Globalization::{MultiByteToWideChar, MB_ERR_INVALID_CHARS};

        if code_page == 65001 {
            // Fast path for UTF-8, which is the most common code-page and doesn't require any transcoding.
            return String::from_utf8(input.to_vec())
                .map_err(|e| anyhow!("UTF-8 decoding error: {e}"));
        }

        let flags: u32 = match code_page {
            // These code-pages specifically disallow any non-zero dwFlags value
            50220..=50225 | 50227 | 50229 | 57002..=57011 | 65000 => 0,

            // For everything else, we want to detect bad sequences.
            _ => MB_ERR_INVALID_CHARS,
        };

        let mut buf = vec![0u16; input.len()];
        let hr: i32 = unsafe {
            MultiByteToWideChar(
                code_page,
                flags,
                input.as_ptr(),
                input.len() as i32,
                buf.as_mut_ptr(),
                buf.capacity() as i32,
            )
        };
        if hr == 0 {
            let error_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(anyhow!(
                "MultiByteToWideChar failed: {}",
                convert_hresult_to_error_message_string(error_code)
            ));
        }

        let converted = String::from_utf16(&buf.as_slice()[0..(hr as usize)])
            .map_err(|e| anyhow!("UTF-16 decoding error: {e}"));
        converted
    }

    #[inline]
    #[cfg(feature = "native-decode")]
    pub fn get_active_code_page() -> u32 {
        unsafe { windows_sys::Win32::Globalization::GetACP() }
    }

    #[inline]
    unsafe fn wcstr_len(ptr: *const u16) -> usize {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        len
    }

    #[inline]
    pub unsafe fn wcstr_to_slice<'a>(ptr: *const u16) -> &'a [u16] {
        let ptr_len = wcstr_len(ptr);
        std::slice::from_raw_parts(ptr, ptr_len)
    }

    #[inline]
    fn make_lang_id(primary_id: u32, sublang_id: u32) -> u32 {
        (sublang_id << 10) | primary_id
    }

    pub fn convert_hresult_to_error_message_string(message_id: u32) -> String {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
            FORMAT_MESSAGE_IGNORE_INSERTS,
        };

        let result: String;
        unsafe {
            let mut buffer: *mut u16 = null_mut();

            let length = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER
                    | FORMAT_MESSAGE_FROM_SYSTEM
                    | FORMAT_MESSAGE_IGNORE_INSERTS,
                null_mut(),
                message_id,
                make_lang_id(LANG_NEUTRAL, SUBLANG_DEFAULT),
                &mut buffer as *mut *mut u16 as *mut u16, // Cast to PWSTR/LPTSTR
                0,
                null_mut(),
            );

            if length == 0 || buffer.is_null() {
                result = format!("Error code: {message_id:08X}");
            } else {
                let slice = std::slice::from_raw_parts(buffer, length as usize);
                result = String::from_utf16_lossy(slice).trim().to_string();
                LocalFree(buffer as HLOCAL);
            }
        }

        result
    }

    // Our production code doesn't use environment variables to determine the paths of these folders because
    // they might not be passed through correctly in all contexts. So this uses the Windows API instead.
    #[inline]
    pub fn get_program_data_folder() -> anyhow::Result<Option<PathBuf>> {
        get_known_folder(FOLDERID_ProgramData)
    }

    // Our production code doesn't use environment variables to determine the paths of these folders because
    // they might not be passed through correctly in all contexts. So this uses the Windows API instead.
    #[inline]
    pub fn get_user_local_app_data_folder() -> anyhow::Result<Option<PathBuf>> {
        get_known_folder(FOLDERID_LocalAppData)
    }

    pub fn get_known_folder(guid: GUID) -> anyhow::Result<Option<PathBuf>> {
        let mut ptr: PWSTR = std::ptr::null_mut();
        let hr = unsafe { SHGetKnownFolderPath(&guid, 0, null_mut(), &mut ptr) };

        let result: anyhow::Result<Option<PathBuf>>;
        if hr == S_OK {
            let result_slice = unsafe { wcstr_to_slice(ptr) };
            let result_os = OsString::from_wide(result_slice);
            result = Ok(Some(PathBuf::from(result_os)));
        } else if hr == E_INVALIDARG {
            result = Ok(None); // No such known-folder on *this* system.
        } else {
            result = Err(anyhow!(
                "{}",
                convert_hresult_to_error_message_string(hr as u32)
            ));
        }

        if !ptr.is_null() {
            unsafe { CoTaskMemFree(ptr as *const c_void) };
        }

        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::env::var_os;

        #[repr(align(2))]
        struct AlignedSlice<T>(T);

        #[test]
        fn test_wcstr_len() {
            for (slice, expected_len) in [
                (AlignedSlice(*b"\x00\x00").0.as_slice(), 0),
                (AlignedSlice(*b"\xFF\xFF\x00\x00").0.as_slice(), 1),
                (AlignedSlice(*b"\x00\xFF\x00\x00").0.as_slice(), 1),
                (AlignedSlice(*b"\xFF\x00\x00\x00").0.as_slice(), 1),
                (AlignedSlice(*b"\xFF\xFF\xFF\xFF\x00\x00").0.as_slice(), 2),
                (AlignedSlice(*b"H\x00e\x00l\x00l\x00o\x00,\x00 \x00W\x00o\x00r\x00l\x00d\x00!\x00\x00\x00").0.as_slice(), 13),
                (AlignedSlice(*b"\x01\x01\x00\x00\xFF\xFF").0.as_slice(), 1)  // Extra content should be ignored!
            ] {
                let actual_size = unsafe { wcstr_len(slice.as_ptr() as *const u16) };
                assert_eq!(actual_size, expected_len, "input={:?}", slice);
            }
        }

        #[test]
        fn test_wcstr_to_slice() {
            for (slice, expected) in [
                (AlignedSlice(*b"\x00\x00").0.as_slice(), Vec::<u16>::new()),
                (AlignedSlice(*b"\x00\x00\x00\x00").0.as_slice(), Vec::<u16>::new()),  // Extra null bytes
                (AlignedSlice(*b"\xFF\xFF\x00\x00").0.as_slice(), vec!(0xFFFFu16)),
                (AlignedSlice(*b"\x00\xFF\x00\x00").0.as_slice(), vec!(0xFF00u16)),
                (AlignedSlice(*b"\xFF\x00\x00\x00").0.as_slice(), vec!(0x00FFu16)),
                (AlignedSlice(*b"\xFF\xFF\xFF\xFF\x00\x00").0.as_slice(), vec!(0xFFFFu16, 0xFFFFu16)),
                (
                    AlignedSlice(*b"H\x00e\x00l\x00l\x00o\x00,\x00 \x00W\x00o\x00r\x00l\x00d\x00!\x00\x00\x00").0.as_slice(),
                    vec!(0x48u16, 0x65u16, 0x6Cu16, 0x6Cu16, 0x6Fu16, 0x2Cu16, 0x20u16, 0x57u16, 0x6Fu16, 0x72u16, 0x6Cu16, 0x64u16, 0x21u16)
                )
            ] {
                let ptr = slice.as_ptr() as *const u16;
                let result_wcstr: &[u16] = unsafe { wcstr_to_slice(ptr) };
                assert_eq!(result_wcstr, expected.as_slice(), "input={:?}", slice);
            }
        }

        #[test]
        fn test_get_known_folder() {
            // Our production code doesn't use environment variables to determine the paths of these folders because
            // they might not be passed through correctly in all contexts; but our test-code does run in a normal user
            // context -- where they should be present and correct. That creates a validation opportunity for our
            // (Windows API) approach.

            let maybe_local_app_data: anyhow::Result<Option<PathBuf>> =
                get_user_local_app_data_folder();
            assert!(
                maybe_local_app_data.is_ok(),
                "err={:?}",
                maybe_local_app_data.unwrap_err()
            );

            let local_app_data = maybe_local_app_data.unwrap();
            let env_local_app_data = var_os("LOCALAPPDATA").map(|oss| PathBuf::from(oss));
            assert_eq!(local_app_data, env_local_app_data);

            let maybe_program_data = get_program_data_folder();
            assert!(
                maybe_program_data.is_ok(),
                "err={:?}",
                maybe_program_data.unwrap_err()
            );

            let program_data = maybe_program_data.unwrap();
            let env_program_data = var_os("ProgramData").map(|oss| PathBuf::from(oss));
            assert_eq!(program_data, env_program_data);
        }

        #[test]
        #[cfg(feature = "native-decode")]
        fn test_get_encoding_for_code_page() {
            // We can't reliably predict what code-page the test environment will be configured to use, but we can at least
            // verify that the function doesn't crash and returns a consistent result.

            let data = b"Test data";

            let maybe_result = convert_code_page_slice_to_string(0, data.as_slice());
            assert!(maybe_result.is_ok());

            for code_page in [
                1252,  // Western European (Windows Latin1)
                65001, // UTF-8
            ] {
                let maybe_result = convert_code_page_slice_to_string(code_page, data.as_slice());
                assert!(
                    maybe_result.is_ok(),
                    "code_page={code_page} err={:?}",
                    maybe_result.unwrap_err()
                );
                let result = maybe_result.unwrap();
                assert_eq!(result, "Test data", "code_page={code_page}");
            }
        }
    }
}
