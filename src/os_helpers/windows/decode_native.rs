// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::borrow::Cow;

use anyhow::anyhow;
use windows_sys::Win32::Globalization::{GetCPInfoExW, CPINFOEXW, CP_ACP};

use super::{get_last_error_message, wcstr_to_string, LengthMode, PlatformStringDecoder};

pub struct CodePageDecoder {
    code_page: u32,
}

impl CodePageDecoder {
    pub fn new() -> Self {
        Self {
            code_page: unsafe { windows_sys::Win32::Globalization::GetACP() },
        }
    }
}

impl PlatformStringDecoder for CodePageDecoder {
    fn description(&self) -> Cow<'_, str> {
        unsafe {
            let mut cp_info: CPINFOEXW = std::mem::zeroed();
            let cp_info_result = GetCPInfoExW(CP_ACP, 0, &mut cp_info);
            if cp_info_result != 0 {
                Cow::Owned(format!(
                    "code page {} ({})",
                    self.code_page,
                    wcstr_to_string(cp_info.CodePageName.as_ptr(), LengthMode::Auto)
                ))
            } else {
                Cow::Owned(format!("code page {} (<name unknown>)", self.code_page))
            }
        }
    }

    fn name(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{}", self.code_page))
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<String> {
        use windows_sys::Win32::Globalization::{MultiByteToWideChar, MB_ERR_INVALID_CHARS};

        if self.code_page == 65001 || data.is_ascii() {
            // Fast path for UTF-8 and pure-ASCII content, which don't require any transcoding.
            return String::from_utf8(data.to_vec())
                .map_err(|e| anyhow!("Error decoding from codepage {}: {e}", self.code_page));
        }

        let flags: u32 = match self.code_page {
            // These code-pages specifically disallow any non-zero dwFlags value
            50220..=50225 | 50227 | 50229 | 57002..=57011 | 65000 => 0,

            // For everything else, we want to detect and fail on bad sequences.
            _ => MB_ERR_INVALID_CHARS,
        };

        // Using twice the #bytes as the input (plus some extra to allow for NULL-termination),
        // satisfies all possible cases EXCEPT if using flags to enable normalization decomposition.
        let mut buf = vec![0u16; data.len() + 1];
        let hr: i32 = unsafe {
            MultiByteToWideChar(
                self.code_page,
                flags,
                data.as_ptr(),
                data.len() as i32,
                buf.as_mut_ptr(),
                buf.capacity() as i32,
            )
        };
        if hr == 0 {
            return Err(anyhow!(
                "Error decoding from codepage {}: {}",
                self.code_page,
                get_last_error_message().as_str()
            ));
        }

        let converted = String::from_utf16(&buf.as_slice()[0..(hr as usize)])
            .map_err(|e| anyhow!("UTF-16 decoding error: {e}"));
        converted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_code_page_decoder() {
        let decoder = CodePageDecoder::new();

        let name_cow = decoder.name();
        let name = name_cow.as_ref();
        let is_ascii_digits = !name.is_empty() && name.chars().all(|c| c.is_ascii_digit());

        assert!(
            is_ascii_digits,
            "Non-digit code-page found: '{}'",
            decoder.name().as_ref()
        );
    }

    #[test]
    fn test_common_code_pages() {
        let test_data = "Test data";
        let test_data_utf8 = b"Test data";

        for code_page in [
            1252,  // Western European (Windows Latin1)
            65001, // UTF-8
        ] {
            let decoder = CodePageDecoder { code_page };
            let converted = decoder.decode(test_data_utf8);
            assert!(
                converted.is_ok(),
                "decode error: {}",
                converted.unwrap_err()
            );
            assert_eq!(converted.unwrap(), test_data);
        }
    }

    #[test]
    fn test_code_page_850() {
        let test_data = b"\xDA\xBF \xC0\xD9";
        let expected = "┌┐ └┘";

        let decoder = CodePageDecoder { code_page: 850 };
        let converted = decoder.decode(test_data);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), expected);
    }
}
