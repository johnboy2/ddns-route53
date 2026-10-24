// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::borrow::Cow;
use std::ffi::CStr;

use anyhow::anyhow;

use super::PlatformStringDecoder;

pub struct CodeSetDecoder {
    code_set: Option<Cow<'static, str>>,
}

impl CodeSetDecoder {
    pub fn new() -> Self {
        const CSTR_C: &[u8] = b"C";
        const CSTR_POSIX: &[u8] = b"POSIX"; // Official alias for 'C' locale
        const CSTR_ANSI: &[u8] = b"ANSI_X3.4";

        // Look up the currently-active code set using POSIX-standard means.
        let c_str = unsafe {
            let ptr = libc::nl_langinfo(libc::CODESET);
            if ptr.is_null() {
                panic!("nl_langinfo() returned NULL - which should be impossible");
            }
            CStr::from_ptr(ptr)
        };

        let code_set = if c_str.is_empty()
            || c_str.to_bytes() == CSTR_C
            || c_str.to_bytes() == CSTR_POSIX
            || c_str.to_bytes() == CSTR_ANSI
        {
            log::debug!("Using 'C' locale");
            None
        } else {
            let result = c_str.to_string_lossy();
            log::debug!("Using codeset '{}'", result.as_ref());
            Some(result)
        };

        Self { code_set }
    }
}

impl PlatformStringDecoder for CodeSetDecoder {
    fn name(&self) -> Cow<'_, str> {
        match self.code_set.as_ref() {
            Some(code_set) => Cow::Borrowed(code_set),
            None => Cow::Borrowed("C"),
        }
    }

    fn description(&self) -> Cow<'_, str> {
        match self.code_set.as_ref() {
            Some(code_set) => Cow::Owned(format!("code set '{}'", code_set.as_ref())),
            None => Cow::Borrowed("C locale"),
        }
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<String> {
        match self.code_set.as_ref() {
            Some(code_set) => iconv_native::decode(data, code_set.as_ref()).map_err(|e| {
                anyhow!(
                    "Decoding error for code-set '{}': {e}, got {} bytes",
                    code_set.as_ref(),
                    data.len()
                )
            }),
            None => {
                if !data.is_ascii() {
                    Err(anyhow!("C locale requires ASCII-only data"))
                } else {
                    // Safety: This is okay because data is ASCII only at this point
                    Ok(unsafe { String::from_utf8_unchecked(data.into()) })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_code_set() {
        let decoder = CodeSetDecoder::new();
        assert!(decoder.name().len() != 0);

        if decoder.name() == "C" {
            assert!(decoder.code_set.is_none(), "{}", decoder.code_set.unwrap());
        } else {
            assert!(decoder.code_set.is_some());
        }
    }

    #[test]
    fn test_code_set_c() {
        let test_data = "Test data";
        let test_data_utf8 = test_data.as_bytes();

        let decoder = CodeSetDecoder { code_set: None };
        assert!(decoder.name() == "C");
        assert!(decoder.description() == "C locale");
        assert!(decoder.code_set.is_none(), "{}", decoder.code_set.unwrap());

        let converted = decoder.decode(test_data_utf8);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), test_data);
    }

    #[test]
    fn test_code_set_ascii_compat() {
        let test_data = "Test data";
        let test_data_utf8 = test_data.as_bytes();

        for code_set in ["ANSI_X3.4", "UTF-8", "WINDOWS-1252"] {
            let decoder = CodeSetDecoder {
                code_set: Some(Cow::Borrowed(code_set)),
            };
            assert_eq!(
                decoder.name().as_ref(),
                code_set,
                "expect code_set input to match name output"
            );

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
    fn test_code_set_utf16() {
        let data = "Test data";
        let data_utf16be: Vec<u8> = data.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        let data_utf16le: Vec<u8> = data.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        for (code_set, data_encoded) in [("UTF-16BE", data_utf16be), ("UTF-16lE", data_utf16le)] {
            let decoder = CodeSetDecoder {
                code_set: Some(Cow::Borrowed(code_set)),
            };
            assert_eq!(
                decoder.name().as_ref(),
                code_set,
                "expect code_set input to match name output"
            );

            let converted = decoder.decode(&data_encoded);
            assert!(
                converted.is_ok(),
                "decode error: {}",
                converted.unwrap_err()
            );
            assert_eq!(converted.unwrap(), data);
        }
    }

    #[test]
    fn test_code_set_iso_8859_1() {
        let data_iso8859_1 = b"In for a \xA2, in for a \xA3.";
        let data = "In for a ¢, in for a £.";
        let converted = decoder.decode(&data_iso8859_1);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), data);
    }

    #[test]
    fn test_code_set_iso_8859_15() {
        let data_iso8859_15 = b"In for a \xA2, in for a \xA4.";
        let data = "In for a ¢, in for a €.";
        let converted = decoder.decode(&data_iso8859_15);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), data);
    }
}
