// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::borrow::Cow;

use anyhow::anyhow;

use super::PlatformStringDecoder;

pub struct SimpleDecoder {}

impl SimpleDecoder {
    pub fn new() -> Self {
        Self {}
    }
}

impl PlatformStringDecoder for SimpleDecoder {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("ANSI")
    }

    fn description(&self) -> Cow<'_, str> {
        Cow::Borrowed("ANSI")
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<String> {
        if !data.is_ascii() {
            Err(anyhow!("ANSI content requires ASCII-only data"))
        } else {
            // Safety: This is okay because data is ASCII only at this point
            Ok(unsafe { String::from_utf8_unchecked(data.into()) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_decoder() {
        let test_data = "Test data";
        let test_data_utf8 = test_data.as_bytes();

        let decoder = SimpleDecoder::new();
        assert!(decoder.name() == "ANSI");
        assert!(decoder.description() == "ANSI");

        let converted = decoder.decode(test_data_utf8);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), test_data);
    }
}
