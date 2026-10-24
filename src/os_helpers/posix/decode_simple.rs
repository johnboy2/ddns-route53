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
        Cow::Borrowed("C")
    }

    fn description(&self) -> Cow<'_, str> {
        Cow::Borrowed("C locale")
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<String> {
        if !data.is_ascii() {
            Err(anyhow!("C locale requires ASCII-only data"))
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
        assert!(decoder.name() == "C");
        assert!(decoder.description() == "C locale");

        let converted = decoder.decode(test_data_utf8);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), test_data);
    }
}
