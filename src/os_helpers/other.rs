use std::borrow::Cow;

use super::PlatformStringDecoder;
use anyhow::anyhow;

pub struct Utf8Decoder {}

impl Utf8Decoder {
    pub fn new() -> Self {
        Self {}
    }
}

impl PlatformStringDecoder for Utf8Decoder {
    fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("UTF-8")
    }

    fn description(&self) -> Cow<'_, str> {
        Cow::Borrowed("UTF-8")
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<String> {
        String::from_utf8(data.to_vec()).map_err(|e| anyhow!("Error decoding value as UTF-8: {e}"))
    }
}

// Define the alias
pub use Utf8Decoder as NativeDecoder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_decoder() {
        let test_data = "Test data";
        let test_data_utf8 = test_data.as_bytes();

        let decoder = Utf8Decoder::new();
        assert!(decoder.name() == "UTF-8");
        assert!(decoder.description() == "UTF-8");

        let converted = decoder.decode(test_data_utf8);
        assert!(
            converted.is_ok(),
            "decode error: {}",
            converted.unwrap_err()
        );
        assert_eq!(converted.unwrap(), test_data);
    }
}
