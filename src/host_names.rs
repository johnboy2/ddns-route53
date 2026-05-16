// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::borrow::Cow;

use anyhow::anyhow;
use idna::{domain_to_ascii_cow, AsciiDenyList};

fn get_char_representation(ch: char) -> Cow<'static, str> {
    let ch_ord = ch as i32;
    match ch_ord {
        0x27 /* '\'' */ => Cow::Borrowed("\"'\""),
        0x5C /* '\\' */ => Cow::Borrowed("'\\'"),
        0x20..0x7F => Cow::Owned(format!("'{0}'", ch)),
        0x0A /* '\n' */ => Cow::Borrowed("'\\n'"),
        0x0D /* '\r' */ => Cow::Borrowed("'\\r'"),
        0x09 /* '\t' */ => Cow::Borrowed("'\\t'"),
        0x00..0x20 | 0x7F..=0xFF => Cow::Owned(format!("'\\x{0:02X}'", ch_ord)),
        0x80..=0xFFFF => Cow::Owned(format!("'\\u+{0:04X}'", ch_ord)),
        _ => Cow::Owned(format!("'\\U+{0:08X}'", ch_ord))
    }
}

pub fn host_is_in_domain(host_fqdn_normalized: &str, domain: &str) -> bool {
    if let Ok(domain_normalized) = normalize_host_name(domain) {
        if host_fqdn_normalized == domain_normalized {
            return true;
        }
        if host_fqdn_normalized.ends_with(domain_normalized.as_ref()) {
            // While this would match "host.domain.com" in "domain.com" (which we want),
            // it would also match "mydomain.com" against "domain.com" (which we don't want).
            // So we must check that a dot ('.') immediately precedes the domain portion.
            let host_lc_bytes = host_fqdn_normalized.as_bytes();
            let domain_lc_bytes = domain_normalized.as_bytes();
            let maybe_separator = host_lc_bytes[host_lc_bytes.len() - domain_lc_bytes.len() - 1];
            if maybe_separator == b'.' {
                return true;
            }
        }
    }

    false
}

pub fn normalize_host_name(host_name: &str) -> anyhow::Result<Cow<'_, str>> {
    let name_lower_idna = domain_to_ascii_cow(host_name.as_bytes(), AsciiDenyList::URL)?;
    validate_idna_host_name(name_lower_idna.as_ref())?;

    if name_lower_idna.ends_with(".") {
        Ok(name_lower_idna)
    } else {
        Ok(Cow::Owned(name_lower_idna.to_string() + "."))
    }
}

fn validate_idna_host_name(name: &str) -> anyhow::Result<()> {
    const MAX_DNS_FQDN_LENGTH: usize = 255;
    const MAX_DNS_LABEL_LENGTH: u32 = 64;

    if name.is_empty() {
        return Err(anyhow!("invalid host_name: cannot be empty"));
    }
    if MAX_DNS_FQDN_LENGTH < name.len() {
        return Err(
            anyhow!(
                "invalid host_name: total length cannot exceed {MAX_DNS_FQDN_LENGTH} characters (got: {0})",
                name.len()
            )
        );
    }

    let mut itr = name.chars().enumerate();
    let mut label_len: u32;
    let mut label_num = 0u32;
    let mut last_ch: char;
    let mut last_ch_idx: usize;

    loop {
        label_num += 1;

        // Get the first/leading character of the current label
        if let Some((idx, ch)) = itr.next() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' => {}
                _ => {
                    return Err(anyhow!(
                        "invalid host_name: character at offset {0} must be one of a-z, A-Z, or 0-9 (got: {1})",
                        idx, get_char_representation(ch)
                    ));
                }
            }
            last_ch = ch;
            last_ch_idx = idx;
            label_len = 1;
        } else {
            // Since we know the host-name wasn't completely empty (since we checked at the very top), having
            // nothing (end of string) after a dot (separator) means it was a final, trailing dot. That is OK.
            return Ok(());
        }

        let mut got_label_terminator = false;
        for (idx, ch) in itr.by_ref() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {
                    last_ch = ch;
                    last_ch_idx = idx;
                    label_len += 1;
                }
                '.' => {
                    last_ch_idx = idx - 1;
                    got_label_terminator = true;
                    break;
                }
                _ => {
                    return Err(anyhow!(
                        "invalid host_name: character at offset {0} must be one of a-z, A-Z, 0-9, -, or . (got: {1})",
                        idx, get_char_representation(ch)
                    ));
                }
            }
        }

        if MAX_DNS_LABEL_LENGTH <= label_len {
            return Err(anyhow!(
                "invalid host_name: label {label_num} is too long (length {label_len} exceeds maximum of {MAX_DNS_LABEL_LENGTH})"
            ));
        }
        if last_ch == '-' {
            return Err(anyhow!(
                "invalid host_name: character at offset {last_ch_idx} ('-'): hyphens are not allowed as the final character in a label"
            ));
        }

        if !got_label_terminator {
            // We broke out of the loop (above) due to end-of-string (NOT due to a '.')
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_in_domain() {
        let tests = [
            ("example.com", "example.com"),
            ("example.com", "com"),
            ("www.example.com", "com"),
            ("a.b.c.d.e.example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("example.com", "EXAMPLE.COM"),
            ("example.com", "COM"),
            ("www.example.com", "COM"),
            ("www.example.com", "EXAMPLE.COM"),
        ];
        for (hostname, domain) in tests {
            let hostname_normalized = normalize_host_name(hostname).unwrap();
            assert!(
                host_is_in_domain(hostname_normalized.as_ref(), domain),
                "host=\"{0}\", domain=\"{1}\"",
                hostname,
                domain
            );
        }
    }

    #[test]
    fn test_host_not_in_domain() {
        let tests = [
            ("com", "example.com"),
            ("wwwwww.example.com", "www.example.com"),
            ("myexample.com", "example.com"),
            ("www.example.com", "some_domain.org"),
        ];
        for (hostname, domain) in tests {
            assert!(
                !host_is_in_domain(hostname, domain),
                "host=\"{0}\", domain=\"{1}\"",
                hostname,
                domain
            );
        }
    }

    #[test]
    fn test_validate_idna_host_name() {
        let tests = [
            ("localhost", true),
            ("www.google.com", true),
            ("domain.", true),
            ("xn--jxalpdlp.test", true),
            (".", false),
            ("-example", false),
            ("example-", false),
            ("example.-test", false),
            ("example.-test.", false),
            ("example.test-", false),
            ("example.test-.", false),
            ("*.wildcard.domain", false),
            ("*.wildcard.domain.", false),
            ("wildcard.*.domain", false),
            (
                "123456789012345678901234567890123456789012345678901234567890123",
                true,
            ),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                false,
            ),
        ];
        for (host_name, expect_valid) in tests {
            let result = validate_idna_host_name(host_name);
            if expect_valid {
                assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
            } else {
                assert!(result.is_err(), "host_name: {:?}", host_name);
                let err = result.unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.starts_with("invalid host_name: "),
                    "e: {:?}",
                    msg.as_str()
                );
            }
        }
    }

    #[test]
    fn test_normalize_host_name() {
        let tests = [
            ("example.com", "example.com."),
            ("EXAMPLE.COM", "example.com."),
            ("España.Example.Com", "xn--espaa-rta.example.com."),
        ];

        for (host_name, expected_normlization) in tests {
            let result = normalize_host_name(host_name).unwrap();
            assert_eq!(result, expected_normlization, "{:?}", host_name);
        }
    }
}
