// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null_mut;

use anyhow::anyhow;
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{LocalFree, E_INVALIDARG, HLOCAL, S_OK};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows_sys::Win32::System::SystemServices::{LANG_NEUTRAL, SUBLANG_DEFAULT};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath,
};

use super::PlatformStringDecoder;

#[cfg(feature = "native-decode")]
mod decode_native;

#[cfg(feature = "native-decode")]
pub use decode_native::CodePageDecoder as NativeDecoder;

#[cfg(not(feature = "native-decode"))]
mod decode_simple;

#[cfg(not(feature = "native-decode"))]
pub use decode_simple::SimpleDecoder as NativeDecoder;

#[inline]
fn make_lang_id(primary_id: u32, sublang_id: u32) -> u32 {
    (sublang_id << 10) | primary_id
}

#[inline]
unsafe fn wcstr_len(ptr: *const u16) -> usize {
    let mut current = ptr;
    while *current != 0 {
        current = current.add(1);
    }
    current.offset_from(ptr) as usize
}

#[inline]
pub unsafe fn wcstr_to_slice<'a>(ptr: *const u16) -> &'a [u16] {
    let ptr_len = wcstr_len(ptr);
    std::slice::from_raw_parts(ptr, ptr_len)
}

#[allow(dead_code)]
pub enum LengthMode {
    Auto,
    Bytes(usize),
    Chars(usize),
}

#[inline]
#[allow(dead_code)]
pub unsafe fn wcstr_to_string(ptr: *const u16, length_mode: LengthMode) -> String {
    let ptr_len = match length_mode {
        LengthMode::Auto => wcstr_len(ptr),
        LengthMode::Bytes(_len) => _len / 2,
        LengthMode::Chars(_len) => _len,
    };
    let u16_slice = std::slice::from_raw_parts(ptr, ptr_len);
    String::from_utf16_lossy(u16_slice)
}

#[allow(dead_code)]
pub fn convert_hresult_to_error_message_string(message_id: u32) -> String {
    let result: String;
    unsafe {
        let mut buffer: *mut u16 = null_mut();

        let num_chars = FormatMessageW(
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

        if num_chars == 0 || buffer.is_null() {
            // We didn't get an error message; so make one with the error code that we have.
            result = format!("Error code: {message_id:08X}");
        } else {
            // We got an error message; parse it out.
            let slice = std::slice::from_raw_parts(buffer, num_chars as usize);

            // Windows error messages often have trailing whitespace (e.g., newlines); strip them.
            let num_trailing_whitespaces = slice
                .iter()
                .rev()
                .map(|ord| *ord)
                .take_while(|ord| {
                    (*ord < 0x7F) && matches!(*ord as u8, b'\n' | b'\r' | b'\t' | b' ')
                })
                .count();
            let truncated_slice = &slice[0..(slice.len() - num_trailing_whitespaces)];

            result = String::from_utf16_lossy(truncated_slice).to_string();
        }

        if !buffer.is_null() {
            LocalFree(buffer as HLOCAL);
        }
    }

    result
}

#[inline]
#[allow(dead_code)]
pub fn get_last_error_message() -> String {
    let error_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    convert_hresult_to_error_message_string(error_code)
}

// Our production code doesn't use environment variables to determine the paths of these folders because
// they might not be passed through correctly in all contexts. So this uses the Windows API instead.
#[inline]
#[allow(dead_code)]
pub fn get_program_data_folder() -> anyhow::Result<Option<PathBuf>> {
    get_known_folder(FOLDERID_ProgramData)
}

// Our production code doesn't use environment variables to determine the paths of these folders because
// they might not be passed through correctly in all contexts. So this uses the Windows API instead.
#[inline]
#[allow(dead_code)]
pub fn get_user_local_app_data_folder() -> anyhow::Result<Option<PathBuf>> {
    get_known_folder(FOLDERID_LocalAppData)
}

#[allow(dead_code)]
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
        let guid_str = format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        );
        result = Err(anyhow!(
            "Error getting known folder for {{{}}}: {}",
            guid_str.as_str(),
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
            (
                AlignedSlice(
                    *b"H\x00e\x00l\x00l\x00o\x00,\x00 \x00W\x00o\x00r\x00l\x00d\x00!\x00\x00\x00",
                )
                .0
                .as_slice(),
                13,
            ),
            (AlignedSlice(*b"\x01\x01\x00\x00\xFF\xFF").0.as_slice(), 1), // Extra content should be ignored!
        ] {
            let actual_size = unsafe { wcstr_len(slice.as_ptr() as *const u16) };
            assert_eq!(actual_size, expected_len, "input={:?}", slice);
        }
    }

    #[test]
    fn test_wcstr_to_slice() {
        for (slice, expected) in [
            (AlignedSlice(*b"\x00\x00").0.as_slice(), Vec::<u16>::new()),
            (
                AlignedSlice(*b"\x00\x00\x00\x00").0.as_slice(),
                Vec::<u16>::new(),
            ), // Extra null bytes
            (
                AlignedSlice(*b"\xFF\xFF\x00\x00").0.as_slice(),
                vec![0xFFFFu16],
            ),
            (
                AlignedSlice(*b"\x00\xFF\x00\x00").0.as_slice(),
                vec![0xFF00u16],
            ),
            (
                AlignedSlice(*b"\xFF\x00\x00\x00").0.as_slice(),
                vec![0x00FFu16],
            ),
            (
                AlignedSlice(*b"\xFF\xFF\xFF\xFF\x00\x00").0.as_slice(),
                vec![0xFFFFu16, 0xFFFFu16],
            ),
            (
                AlignedSlice(
                    *b"H\x00e\x00l\x00l\x00o\x00,\x00 \x00W\x00o\x00r\x00l\x00d\x00!\x00\x00\x00",
                )
                .0
                .as_slice(),
                vec![
                    0x48u16, 0x65u16, 0x6Cu16, 0x6Cu16, 0x6Fu16, 0x2Cu16, 0x20u16, 0x57u16,
                    0x6Fu16, 0x72u16, 0x6Cu16, 0x64u16, 0x21u16,
                ],
            ),
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
        assert_eq!(
            local_app_data, env_local_app_data,
            "Expected %LOCALAPPDATA% API result to match envvar"
        );

        let maybe_program_data = get_program_data_folder();
        assert!(
            maybe_program_data.is_ok(),
            "Error getting programdata folder: err={:?}",
            maybe_program_data.unwrap_err()
        );

        let program_data = maybe_program_data.unwrap();
        let env_program_data = var_os("ProgramData").map(|oss| PathBuf::from(oss));
        assert_eq!(
            program_data, env_program_data,
            "Expected %PROGRAMDATA% API result to match envvar"
        );
    }
}
