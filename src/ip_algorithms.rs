// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::cmp::Eq;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::marker::Send;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use std::vec::Vec;

use anyhow::{anyhow, Context};
use encoding_rs::{DecoderResult, Encoding, WINDOWS_1252};
use igd_next::{aio::tokio::search_gateway, SearchOptions};
use log::{debug, error, trace, warn};
use mime::Mime;
use netdev::{get_default_interface, Interface};
use reqwest::{Client, ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::sleep;
use tokio_stream::StreamExt;

static DEFAULT_INTERFACE: LazyLock<Result<Interface, String>> =
    LazyLock::new(get_default_interface);
static WEB_CLIENT: LazyLock<Result<Client, reqwest::Error>> =
    LazyLock::new(|| ClientBuilder::new().build());

const DEFAULT_ALGO_TIMEOUT_SECS: u64 = 10;
const MAX_WEB_SERVICE_DOCUMENT_LENGTH: u64 = 65536;
const MAX_PLUGIN_DOCUMENT_LENGTH: u64 = 65535;

fn serde_default_algo_timeout() -> Duration {
    Duration::from_secs(DEFAULT_ALGO_TIMEOUT_SECS)
}

mod serde_duration_f64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = f64::deserialize(deserializer)?;
        if v < 0.0 {
            Err(D::Error::custom(format!("value cannot be negative: {v}")))
        } else {
            Ok(Duration::from_secs_f64(v))
        }
    }

    pub fn serialize<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(d.as_secs_f64())
    }
}

mod serde_encoding {
    use encoding_rs::Encoding;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<&'static Encoding>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if let Some(s) = Option::<String>::deserialize(deserializer)? {
            let sb = s.trim_ascii().as_bytes();

            // encoding_rs seems not to recognize some common UTF-16 aliases, so we
            // give it a hand here with a few of our own, custom translations.
            let sb: &[u8] = match sb.to_ascii_lowercase().as_slice() {
                b"utf16" => b"utf-16",
                b"utf16le" | b"utf-16-le" => b"utf-16le",
                b"utf16be" | b"utf-16-be" => b"utf-16be",
                _ => sb,
            };

            Encoding::for_label(sb)
                .map(Some)
                .ok_or(D::Error::custom(format!("unknown encoding: \"{s}\"")))
        } else {
            Ok(None)
        }
    }

    pub fn serialize<S>(
        encoding: &Option<&'static Encoding>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(e) = encoding {
            serializer.serialize_str(e.name())
        } else {
            serializer.serialize_none()
        }
    }
}

mod serde_url {
    use reqwest::Url;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(|e| D::Error::custom(format!("could not parse url: \"{s}\": {}", e)))
    }

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(url.as_str())
    }
}

pub trait IpAddressV4orV6: Copy + Debug + Display + Eq + FromStr + Hash + Send {
    fn is_global(&self) -> bool;
    fn type_name() -> &'static str;
    async fn get_default_public_ip() -> anyhow::Result<Vec<Self>>;
    async fn get_igd_public_ip(timeout: &Duration) -> anyhow::Result<Vec<Self>>;
}

impl IpAddressV4orV6 for Ipv4Addr {
    // Adapted from https://doc.rust-lang.org/1.87.0/src/core/net/ip_addr.rs.html#836-855
    // (The std::net::Ipv4Addr.is_global() function requires an unstable std library; hence we made our own instead.)
    fn is_global(&self) -> bool {
        !(self.octets()[0] == 0 // "This network"
        || self.is_private()
        || (
            // self.is_shared()
            self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
        )
        || self.is_loopback()
        || self.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        // .9 and .10 are documented as globally reachable so they're excluded
        || (
            self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0
            && self.octets()[3] != 9 && self.octets()[3] != 10
        )
        || self.is_documentation()
        || (
            // self.is_benchmarking()
            self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
        )
        || (
            // self.is_reserved()
            self.octets()[0] & 240 == 240 && !self.is_broadcast()
        )
        || self.is_broadcast())
    }

    fn type_name() -> &'static str {
        "IPv4"
    }

    async fn get_default_public_ip() -> anyhow::Result<Vec<Self>> {
        let default_interface = (*DEFAULT_INTERFACE)
            .as_ref()
            .map_err(anyhow::Error::msg)
            .context("failed to determine default network interface")?;

        let mut result = Vec::<Self>::new();
        for network in &default_interface.ipv4 {
            let ip_net_addr = network.addr();
            if IpAddressV4orV6::is_global(&ip_net_addr) {
                result.push(ip_net_addr);
            } else {
                debug!(
                    "Ignoring address [{}] on default interface: address is non-global",
                    ip_net_addr
                );
            }
        }
        Ok(result)
    }

    async fn get_igd_public_ip(timeout: &Duration) -> anyhow::Result<Vec<Self>> {
        let search_option = SearchOptions {
            timeout: Some(*timeout),
            ..Default::default()
        };
        let gateway = search_gateway(search_option).await?;
        let ip = gateway
            .get_external_ip()
            .await
            .context("error parsing external IP from internet gateway")?;
        if let IpAddr::V4(v4) = ip {
            if <Ipv4Addr as IpAddressV4orV6>::is_global(&v4) {
                return Ok(vec![v4]);
            } else {
                debug!(
                    "Ignoring address [{}] reported by internet gateway: address is non-global",
                    v4
                );
                
            }
        }
        Ok(Vec::<Ipv4Addr>::new())
    }
}

impl IpAddressV4orV6 for Ipv6Addr {
    // Adapted from https://doc.rust-lang.org/1.87.0/src/core/net/ip_addr.rs.html#1595-1630
    // (The std::net::Ipv6Addr.is_global() function requires an unstable std library; hence we made our own instead.)
    fn is_global(&self) -> bool {
        !(self.is_unspecified()
        || self.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
            ))
        // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
        // IANA says N/A.
        || matches!(self.segments(), [0x2002, _, _, _, _, _, _, _])
        || (
            // ip.is_documentation()
            matches!(self.segments(), [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..])
        )
        // Segment Routing (SRv6) SIDs (`5f00::/16`)
        || matches!(self.segments(), [0x5f00, ..])
        || (
            // ip.is_unique_local()
            (self.segments()[0] & 0xfe00) == 0xfc00
        )
        || (
            // ip.is_unicast_link_local()
            (self.segments()[0] & 0xffc0) == 0xfe80
        ))
    }

    fn type_name() -> &'static str {
        "IPv6"
    }

    async fn get_default_public_ip() -> anyhow::Result<Vec<Self>> {
        let default_interface = (*DEFAULT_INTERFACE)
            .as_ref()
            .map_err(anyhow::Error::msg)
            .context("failed to determine default network interface")?;

        let mut result = Vec::<Self>::new();
        for network in &default_interface.ipv6 {
            let ip_net_addr = network.addr();
            if IpAddressV4orV6::is_global(&ip_net_addr) {
                result.push(ip_net_addr);
            } else {
                debug!(
                    "Ignoring address [{}] on default interface: address is non-global",
                    ip_net_addr
                );
            }
        }
        Ok(result)
    }

    async fn get_igd_public_ip(_timeout: &Duration) -> anyhow::Result<Vec<Self>> {
        Err(anyhow!(
            "internet_gateway_protocol algorithm cannot be used with IPv6"
        ))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum AlgorithmSpecification {
    #[serde(rename = "none")]
    None,

    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol {
        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,
    },

    #[serde(rename = "web_service")]
    WebService {
        #[serde(with = "serde_url")]
        url: Url,

        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,

        #[serde(default, with = "serde_encoding")]
        default_encoding: Option<&'static Encoding>,
    },

    #[serde(rename = "plugin")]
    Plugin {
        command: StringOrStringVec,

        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,

        #[serde(default, with = "serde_encoding")]
        encoding: Option<&'static Encoding>,
    },
}

impl AlgorithmSpecification {
    // This identifier is used for various purposes, such as ensuring that the same algorithm isn't specified
    // multiple times within a given IP version's algorithms, and for logging. It should be unique for each distinct
    // algorithm configuration, but it doesn't need to be particularly human-friendly.
    pub fn get_name(&self) -> String {
        format!("{self}")
    }

    pub fn validate_combination(
        algos: &[AlgorithmSpecification],
        for_ipv6: bool,
    ) -> anyhow::Result<()> {
        let mut unique_algo_names = HashSet::<String>::new();
        for algo in algos {
            let algo_name = algo.get_name();

            if unique_algo_names.contains(algo_name.as_str()) {
                return Err(anyhow!(
                    "algorithm '{algo_name}' cannot be specified more than once"
                ));
            }

            match algo {
                AlgorithmSpecification::None => {
                    if algos.len() != 1 {
                        return Err(anyhow!(
                            "algorithm '{algo_name}' must be alone in any given IP version's algorithms -- it cannot be combined with any others"
                        ));
                    }
                }
                AlgorithmSpecification::InternetGatewayProtocol { timeout: _ } => {
                    if for_ipv6 {
                        return Err(anyhow!("algorithm '{algo_name}' cannot be used with IPv6"));
                    }
                }
                _ => {}
            }

            unique_algo_names.insert(algo_name);
        }

        Ok(())
    }

    pub async fn get_public_ip_address<T>(&self) -> anyhow::Result<Vec<T>>
    where
        T: IpAddressV4orV6,
        <T as FromStr>::Err: Display,
    {
        match self {
            AlgorithmSpecification::None => {
                panic!("Unreachable code was somehow reached")
            }
            AlgorithmSpecification::DefaultPublicIp => T::get_default_public_ip().await,
            AlgorithmSpecification::InternetGatewayProtocol { timeout } => {
                T::get_igd_public_ip(timeout).await
            }
            AlgorithmSpecification::WebService {
                url,
                timeout,
                default_encoding,
            } => get_web_service_ip::<T>(url, timeout, *default_encoding).await,
            AlgorithmSpecification::Plugin {
                command,
                timeout,
                encoding,
            } => get_plugin_ip::<T>(command, timeout, *encoding).await,
        }
    }

    pub async fn get_public_ip_address_for_algos<T>(algos: &[AlgorithmSpecification]) -> HashSet<T>
    where
        T: IpAddressV4orV6,
        <T as FromStr>::Err: Display,
    {
        let ip_version = T::type_name().to_ascii_lowercase();

        for (idx, algo) in algos.iter().enumerate() {
            debug!("{ip_version}_algorithms[{idx}]: Trying algorithm: {algo}");

            let algo_result = algo.get_public_ip_address::<T>().await;
            match algo_result {
                Ok(ips) => {
                    debug!("{ip_version}_algorithms[{idx}]: got addresses: {:?}", &ips);
                    if ips.is_empty() {
                        debug!("{ip_version}_algorithms[{idx}]: skipping empty result");
                    } else {
                        let ips_set: HashSet<_> = ips.into_iter().collect();
                        return ips_set;
                    }
                }
                Err(msg) => {
                    warn!("{ip_version}_algorithms[{idx}] ({algo}): returned error: {msg}");
                }
            };
        }

        if !algos.is_empty() {
            warn!("{ip_version}_algorithms: none of the configured algorithms found any results; returning empty-set.");
        }

        HashSet::<T>::new()
    }

    #[cfg(test)]
    pub fn supports_ipv4(&self) -> bool {
        true
    }

    #[cfg(test)]
    pub fn supports_ipv6(&self) -> bool {
        match self {
            AlgorithmSpecification::InternetGatewayProtocol { timeout: _ } => false,
            _ => true,
        }
    }
}

impl Debug for AlgorithmSpecification {
    // For debugging purposes, we want a concise description of each algorithm with all the details.
    // Serializing to (compact) TOML gives us that.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        toml::to_string(&self)
            .map_err(|e| {
                error!("Failed to serialize AlgorithmSpecification: {e}");
                std::fmt::Error
            })
            .and_then(|s| f.write_str(s.as_str()))
    }
}

impl Display for AlgorithmSpecification {
    // For display purposes, we want a *simple* description of each algorithm, without unnecessary details.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::None => f.write_str("none"),
            Self::DefaultPublicIp => f.write_str("default_public_ip"),
            Self::InternetGatewayProtocol { timeout: _ } => write!(f, "internet_gateway_protocol"),
            Self::WebService {
                url,
                timeout: _,
                default_encoding: _,
            } => write!(f, "web_service:\"{}\"", url.as_str()),
            Self::Plugin {
                command,
                timeout: _,
                encoding: _,
            } => write!(f, "plugin:\"{command}\""),
        }
    }
}

// Helper to download a document from a URL
async fn get_web_service_document(
    client: &Client,
    url: &Url,
    timeout: &Duration,
    default_encoding: Option<&'static Encoding>,
) -> anyhow::Result<String> {
    let request = client.get(url.clone()).timeout(*timeout).send();
    let response = request.await.context("error fetching url")?;
    let mut content_length: u64 = 0;

    if let Some(cl) = response.content_length() {
        if MAX_WEB_SERVICE_DOCUMENT_LENGTH < cl {
            return Err(anyhow!(
                "url \"{}\": Content-Length ({}) too long (max={})",
                url.as_str(),
                cl,
                MAX_WEB_SERVICE_DOCUMENT_LENGTH
            ));
        }
        content_length = cl;
    }

    // Stream the data back and decode it.

    // Why not just use `response.text()`? We want this code to be able to run
    // effectively even in low-memory environments or in the presence of
    // possibly malicious web service hosts spewing back an unlimited amount of
    // data. Streaming the content first (to ensure it isn't too large) is a
    // reasonable mitigation.

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Mime>().ok());
    let encoding_name = content_type
        .as_ref()
        .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()));

    let encoding = if let Some(name) = encoding_name {
        match Encoding::for_label(name.as_bytes()) {
            Some(e) => e,
            None => {
                return Err(anyhow!("unknown encoding: \"{name}\""))?;
            }
        }
    } else {
        debug!("No Content-Type header found, or did not contain a charset");
        match default_encoding {
            Some(e) => {
                debug!(
                    "Using configuration-provided default_encoding: {}",
                    e.name()
                );
                e
            }
            None => {
                debug!("Using HTTP default encoding: iso-8859-1");
                WINDOWS_1252
            }
        }
    };

    let mut body_binary = Vec::<u8>::new();
    if content_length != 0 {
        body_binary.reserve(content_length as usize);
    }
    let mut stream = response.bytes_stream();
    while let Some(item) = stream.next().await {
        let item = item.context("error reading from stream")?;
        let len_after_append = item.len() + body_binary.len();
        if MAX_WEB_SERVICE_DOCUMENT_LENGTH < (len_after_append as u64) {
            return Err(anyhow!(
                "url \"{}\": body length ({}) too long (max={})",
                url.as_str(),
                len_after_append,
                MAX_WEB_SERVICE_DOCUMENT_LENGTH
            ));
        }
        body_binary.extend_from_slice(item.as_ref());
    }

    match encoding
        .decode_without_bom_handling_and_without_replacement(body_binary.as_slice())
        .map(|s| s.into_owned())
    {
        Some(decoded) => Ok(decoded),
        None => {
            error!(
                "web-service response could not be decoded; value: {:X?}",
                body_binary.as_slice()
            );
            Err(anyhow!(
                "failed to decode output with \"{}\"",
                encoding.name()
            ))
        }
    }
}

pub async fn get_web_service_ip<T>(
    url: &Url,
    timeout: &Duration,
    default_encoding: Option<&'static Encoding>,
) -> anyhow::Result<Vec<T>>
where
    T: IpAddressV4orV6,
    <T as FromStr>::Err: ToString,
{
    let client = (*WEB_CLIENT)
        .as_ref()
        .context("failed to initialize web client")?;

    let body = get_web_service_document(client, url, timeout, default_encoding).await?;

    let mut result = Vec::<T>::new();
    for line in body.as_str().lines() {
        trace!("web service result: {:?}", line);
        let ip = match T::from_str(line) {
            Ok(result) => result,
            Err(e) => {
                return Err(anyhow!(
                    "failed to parse address from web service: {}",
                    e.to_string()
                ))
            }
        };

        if ip.is_global() {
            result.push(ip)
        } else {
            debug!(
                "Ignoring address [{}] reported by web-service:{}: address is non-global",
                ip,
                url.as_str()
            );
        }
    }

    Ok(result)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum StringOrStringVec {
    String(String),
    Vec(Vec<String>),
}

impl Display for StringOrStringVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        const MAX_STR_LEN: usize = 32;

        match self {
            StringOrStringVec::String(s) => {
                if s.len() <= MAX_STR_LEN {
                    f.write_str(s.as_str())?;
                } else {
                    let substr: String = s.chars().take(MAX_STR_LEN - 1).collect();
                    f.write_str(substr.as_str())?;
                    f.write_str("…")?;
                }
            }
            StringOrStringVec::Vec(v) => {
                if !v.is_empty() {
                    if v[0].len() <= MAX_STR_LEN {
                        f.write_str(v[0].as_str())?;
                        if v.len() > 1 {
                            f.write_str(" …")?;
                        }
                    } else {
                        let substr: String = v[0].chars().take(MAX_STR_LEN - 1).collect();
                        f.write_str(substr.as_str())?;
                        f.write_str("…")?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl From<&str> for StringOrStringVec {
    fn from(s: &str) -> Self {
        StringOrStringVec::String(s.to_string())
    }
}

impl From<Vec<&str>> for StringOrStringVec {
    fn from(v: Vec<&str>) -> Self {
        StringOrStringVec::Vec(v.iter().map(|s| (*s).to_string()).collect())
    }
}

fn build_command_object(plugin_command: &StringOrStringVec) -> anyhow::Result<Command> {
    let mut command_obj: Command;

    match plugin_command {
        StringOrStringVec::String(s) => {
            if s.is_empty() {
                return Err(anyhow!("command cannot be empty"));
            }
            #[cfg(windows)]
            {
                let shell =
                    std::env::var_os("ComSpec").unwrap_or(std::ffi::OsString::from("cmd.exe"));
                command_obj = Command::new(shell);
                command_obj.arg("/C");
                command_obj.raw_arg(std::ffi::OsString::from(s));
            }
            #[cfg(unix)]
            {
                let shell =
                    std::env::var_os("SHELL").unwrap_or(std::ffi::OsString::from("/bin/sh"));
                command_obj = Command::new(shell);
                command_obj.arg("-c");
                command_obj.arg(s);
            }
            // TODO: Are there any other platforms with a different way to invoke a shell command?
            #[cfg(not(any(windows, unix)))]
            {
                // Ultimate fall-back: Just run the string as-is. (If this is ever "wrong", the
                // caller can always specify using the list syntax instead, or file a bug report.)
                command_obj = Command::new(s);
            }
        }
        StringOrStringVec::Vec(v) => {
            if v.is_empty() || v[0].is_empty() {
                return Err(anyhow!("command cannot be empty"));
            }
            command_obj = Command::new(&v[0]);
            command_obj.args(&v[1..]);
        }
    }

    command_obj.stdout(Stdio::piped());
    #[cfg(windows)]
    {
        command_obj.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    Ok(command_obj)
}

fn decode_bytes_with_encoding(data: &[u8], encoding: &'static Encoding) -> anyhow::Result<String> {
    let mut decoder = encoding.new_decoder_without_bom_handling();

    let mut string_buffer = String::with_capacity(
        decoder.max_utf8_buffer_length_without_replacement(data.len())
        .expect("buffer size calculation overflowed"))  // Should be impossible (MAX_PLUGIN_DOCUMENT_LENGTH)
    ;

    let (decode_result, num_bytes_consumed) =
        decoder.decode_to_string_without_replacement(data, &mut string_buffer, true);

    match decode_result {
        DecoderResult::InputEmpty => Ok(string_buffer),
        DecoderResult::OutputFull => {
            // Since we preallocate a worst-case string, this *should* be impossible.
            error!("plugin output could not be decoded: output buffer was too small");
            Err(anyhow!(
                "failed to decode plugin output with encoding \"{}\": output buffer was too small",
                encoding.name()
            ))
        }
        DecoderResult::Malformed(sequence_len, sequence_len_consumed) => {
            error!(
                "plugin output could not be decoded: malformed sequence at byte index {} ({} bytes long, {} bytes consumed)",
                num_bytes_consumed, sequence_len, sequence_len_consumed
            );
            Err(anyhow!(
                "failed to decode plugin output with encoding \"{}\": bad input error",
                encoding.name()
            ))
        }
    }
}

fn decode_bytes_with_encoding_fallback(
    data: &[u8],
    configuration_encoding: Option<&'static Encoding>,
) -> anyhow::Result<String> {
    const HIGH_BYTE_IDX: usize = if cfg!(target_endian = "little") { 1 } else { 0 };

    if data.is_empty() {
        Ok(String::new())
    } else if let Some(encoding) = configuration_encoding {
        debug!(
            "Using configuration-specified encoding: {}",
            encoding.name()
        );
        decode_bytes_with_encoding(data, encoding)
    } else if let Some((encoding, bom_len_bytes)) = Encoding::for_bom(data) {
        debug!(
            "Found byte-order mark at start of plugin output; using encoding: {}",
            encoding.name()
        );
        decode_bytes_with_encoding(&data[bom_len_bytes..], encoding)
    } else if HIGH_BYTE_IDX < data.len() && data[HIGH_BYTE_IDX] == 0 {
        if cfg!(target_endian = "little") {
            debug!(
                "Found NULL-byte offset {HIGH_BYTE_IDX} in plugin output; using encoding: UTF_16LE"
            );
            decode_bytes_with_encoding(data, encoding_rs::UTF_16LE)
        } else {
            debug!(
                "Found NULL-byte offset {HIGH_BYTE_IDX} in plugin output; using encoding: UTF_16BE"
            );
            decode_bytes_with_encoding(data, encoding_rs::UTF_16BE)
        }
    } else {
        #[cfg(feature = "native-decode")]
        {
            #[cfg(unix)]
            {
                debug!("No encoding could be detected from plugin output; trying current locale (code set) instead");
                if let Some(active_code_set) = crate::os_helpers::posix::get_active_code_set() {
                    crate::os_helpers::posix::convert_code_set_slice_to_string(
                        active_code_set.as_str(),
                        data,
                    )
                } else {
                    crate::os_helpers::posix::convert_c_locale_slice_to_string(data)
                }
            }

            #[cfg(windows)]
            {
                debug!("No encoding could be detected from plugin output; trying active code page instead");
                let active_code_page = crate::os_helpers::windows::get_active_code_page();
                crate::os_helpers::windows::convert_code_page_slice_to_string(
                    active_code_page,
                    data,
                )
            }

            #[cfg(not(any(unix, windows)))]
            {
                let fallback_encoding = encoding_rs::UTF_8;
                debug!("No encoding could be detected from plugin output, and no native encoding detection available on this platform; trying fallback {0} instead", fallback_encoding.name());
                decode_bytes_with_encoding(data, fallback_encoding)
            }
        }

        #[cfg(not(feature = "native-decode"))]
        {
            #[cfg(unix)]
            {
                debug!("No encoding could be detected from plugin output; trying C locale instead");
                crate::os_helpers::posix::convert_c_locale_slice_to_string(data)
            }

            #[cfg(not(unix))]
            {
                let fallback_encoding = encoding_rs::UTF_8;
                debug!(
                    "No encoding could be detected from plugin output; trying fallback {0} instead",
                    fallback_encoding.name()
                );
                decode_bytes_with_encoding(data, fallback_encoding)
            }
        }
    }
}

async fn get_plugin_output(
    command: &StringOrStringVec,
    timeout: &Duration,
    configuration_encoding: Option<&'static Encoding>,
) -> anyhow::Result<String> {
    let mut command_obj = build_command_object(command)?;

    let mut child = command_obj.spawn().expect("plugin failed to start");
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("failed to unwrap stdout pipe");
    let read_stdout_fut = tokio::spawn(async move {
        let mut buff = Vec::new();
        let _ = stdout
            .take(MAX_PLUGIN_DOCUMENT_LENGTH)
            .read_to_end(&mut buff)
            .await;

        if buff.len() == (MAX_PLUGIN_DOCUMENT_LENGTH as usize) {
            return Err(anyhow!(
                "plugin output must be less than {MAX_PLUGIN_DOCUMENT_LENGTH} bytes"
            ));
        }

        Ok(buff)
    });

    let mut succeeded = true;
    tokio::select! {
        es = child.wait() => {
            let child_exit_status = es.expect("failed to unwrap exit status");
            if let Some(code) = child_exit_status.code() {
                if code == 0 {
                    debug!("plugin exitted with RC={code}");
                }
                else {
                    error!("plugin exitted with RC={code}");
                    succeeded = false;
                }
            }
            else {
                error!("plugin exitted abnormally");
                succeeded = false;
            }
        }
        _ = sleep(*timeout) => {
            drop(read_stdout_fut);
            child.kill().await.expect("failed to kill child after timeout");
            return Err(anyhow!("plugin timed out"));
        }
    }

    let stdout_binary = read_stdout_fut
        .await
        .expect("failed to unwrap stdout buffer content")?;

    let stdout_decoded =
        decode_bytes_with_encoding_fallback(stdout_binary.as_slice(), configuration_encoding)?;
    trace!("plugin output: {:?}", stdout_decoded.as_str());
    if succeeded {
        Ok(stdout_decoded)
    } else {
        Err(anyhow!("plugin failed"))
    }
}

pub async fn get_plugin_ip<T>(
    command: &StringOrStringVec,
    timeout: &Duration,
    encoding: Option<&'static Encoding>,
) -> anyhow::Result<Vec<T>>
where
    T: IpAddressV4orV6,
    <T as FromStr>::Err: ToString,
{
    let output = get_plugin_output(command, timeout, encoding).await?;

    let mut result = Vec::<T>::new();
    for line in output.as_str().lines() {
        let ip = match T::from_str(line) {
            Ok(result) => result,
            Err(e) => {
                return Err(anyhow!(
                    "failed to parse IP address from plugin: {}",
                    e.to_string()
                ))
            }
        };

        if <T as IpAddressV4orV6>::is_global(&ip) {
            result.push(ip);
        } else {
            debug!("Ignoring address [{ip}] reported by plugin: address is non-global");
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeDuration {
        #[serde(with = "serde_duration_f64")]
        timeout: Duration,
    }

    #[test]
    fn test_serialize_duration_to_toml() {
        let test_struct = SerdeDuration {
            timeout: Duration::from_secs_f64(1.5),
        };
        let maybe_toml = toml::to_string(&test_struct);
        assert!(maybe_toml.is_ok(), "err: {:?}", maybe_toml.unwrap_err());
        let toml_result = maybe_toml.unwrap();
        assert_eq!(toml_result.as_str().trim_end(), "timeout = 1.5");
    }

    #[test]
    fn test_parse_negative_duration_from_toml() {
        let toml_value: &str = "timeout = -1";
        let maybe_struct = toml::from_str::<SerdeDuration>(toml_value);
        assert!(maybe_struct.is_err(), "struct: {:?}", maybe_struct.unwrap());
        let err = maybe_struct.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("value cannot be negative: "), "{:?}", msg);
    }

    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeEncoding {
        #[serde(with = "serde_encoding")]
        encoding: Option<&'static Encoding>,
    }

    #[test]
    fn test_serialize_encoding_utf8() {
        let test_struct = SerdeEncoding {
            encoding: Some(encoding_rs::UTF_8),
        };
        let toml_value = toml::to_string(&test_struct);
        assert!(toml_value.is_ok(), "err: {:?}", toml_value.unwrap_err());
        let value_string = toml_value.unwrap();
        assert_eq!(value_string.as_str().trim_end(), "encoding = \"UTF-8\"");
    }

    #[test]
    fn test_serialize_encoding_none() {
        let test_struct = SerdeEncoding { encoding: None };
        let toml_value = toml::to_string(&test_struct);
        assert!(toml_value.is_ok(), "err: {:?}", toml_value.unwrap_err());
        let value_string = toml_value.unwrap();
        assert_eq!(value_string.as_str().trim_end(), "");
    }

    #[test]
    fn test_deserialize_encoding_utf8() {
        let toml_value: &str = "encoding = \"utf-8\"";
        let maybe_struct = toml::from_str::<SerdeEncoding>(toml_value);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(
            result.encoding,
            Some(encoding_rs::UTF_8),
            "{:?}",
            toml_value
        );

        let toml_value: &str = "encoding = \"UTF-8\"";
        let maybe_struct = toml::from_str::<SerdeEncoding>(toml_value);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(
            result.encoding,
            Some(encoding_rs::UTF_8),
            "{:?}",
            toml_value
        );

        let toml_value: &str = "encoding = \"utf8\"";
        let maybe_struct = toml::from_str::<SerdeEncoding>(toml_value);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(
            result.encoding,
            Some(encoding_rs::UTF_8),
            "{:?}",
            toml_value
        );
    }

    // #[test]
    // fn test_deserialize_encoding_none() {
    //     let toml_value: &str = "{}";
    //     let maybe_struct = toml::from_str::<SerdeEncoding>(toml_value);
    //     assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
    //     let result = maybe_struct.unwrap();
    //     assert_eq!(result.encoding, None, "{:?}", toml_value);
    // }

    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeUrl {
        #[serde(with = "serde_url")]
        url: Url,
    }

    #[test]
    fn test_serialize_url() {
        let test_struct = SerdeUrl {
            url: Url::parse("https://www.google.com/").unwrap(),
        };
        let maybe_toml = toml::to_string(&test_struct);
        assert!(maybe_toml.is_ok(), "err: {:?}", maybe_toml.unwrap_err());
        let toml_value = maybe_toml.unwrap();
        assert_eq!(
            toml_value.as_str().trim_end(),
            "url = \"https://www.google.com/\""
        );
    }

    #[test]
    fn test_deserialize_url() {
        let toml_value: &str = "url = \"http://localhost/\"";
        let maybe_struct = toml::from_str::<SerdeUrl>(toml_value);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(
            result.url,
            Url::parse("http://localhost/").unwrap(),
            "{:?}",
            toml_value
        );
    }

    #[test]
    fn test_get_web_services_document() {
        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        let client = (*WEB_CLIENT).as_ref().unwrap();

        // TODO: It would be better to use a mock web server here instead of an actual external service;
        // however, this is still better than nothing, and captive.apple.com is a reasonably stable endpoint
        // to use for this purpose.
        let url = "http://captive.apple.com";

        let tests = [
            None,
            Some(encoding_rs::WINDOWS_1252),
            Some(encoding_rs::UTF_8),
        ];
        for encoding in tests {
            let content = async_runtime
                .block_on(get_web_service_document(
                    client,
                    &Url::parse(url).unwrap(),
                    &Duration::from_secs(30),
                    encoding,
                ))
                .unwrap();

            assert_eq!(
                content,
                "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n"
            );
        }
    }

    #[test]
    fn test_get_plugin_output() {
        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        let content = async_runtime
            .block_on(get_plugin_output(
                &StringOrStringVec::String("echo Hello!".to_string()),
                &Duration::from_secs(10),
                None,
            ))
            .unwrap();

        // Trim off trailing newline - regardless of specific format.
        let content_rstripped = content.trim_end_matches(&['\r', '\n'][..]);

        assert_eq!(content_rstripped, "Hello!");
    }

    #[test]
    fn test_algorithm_combos_empty() {
        let vec = Vec::<AlgorithmSpecification>::new();
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_ok(),
                "ipVersion={}, err={:?}",
                if is_ipv6 { '6' } else { '4' },
                r.unwrap_err()
            );
        }
    }

    static ALGO_DEFAULT_PUB_IP: LazyLock<AlgorithmSpecification> =
        LazyLock::new(|| AlgorithmSpecification::DefaultPublicIp {});
    static ALGO_IGP: LazyLock<AlgorithmSpecification> =
        LazyLock::new(|| AlgorithmSpecification::InternetGatewayProtocol {
            timeout: Duration::from_secs(10),
        });
    static ALGO_PLUGIN_SIMPLE: LazyLock<AlgorithmSpecification> =
        LazyLock::new(|| AlgorithmSpecification::Plugin {
            command: StringOrStringVec::String("/bin/false".to_string()),
            timeout: Duration::from_secs(10),
            encoding: None,
        });
    static ALGO_WEB_SERVICE_SIMPLE: LazyLock<AlgorithmSpecification> =
        LazyLock::new(|| AlgorithmSpecification::WebService {
            url: Url::parse("http://whatismyipaddress.com/").unwrap(),
            timeout: Duration::from_secs(10),
            default_encoding: None,
        });

    #[test]
    fn test_algorithm_standard_algos_okay_on_their_own() {
        for algo in [
            &*ALGO_DEFAULT_PUB_IP,
            &*ALGO_PLUGIN_SIMPLE,
            &*ALGO_WEB_SERVICE_SIMPLE,
        ] {
            let vec = vec![algo.clone()];
            for is_ipv6 in [false, true] {
                let supports_ip_version = if is_ipv6 {
                    algo.supports_ipv6()
                } else {
                    algo.supports_ipv4()
                };
                if supports_ip_version {
                    let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
                    assert!(
                        r.is_ok(),
                        "algo={}, ipVersion={}, err={:?}",
                        algo,
                        if is_ipv6 { '6' } else { '4' },
                        r.unwrap_err()
                    );
                } else {
                    let r = std::panic::catch_unwind(|| {
                        let _ = AlgorithmSpecification::validate_combination(vec.as_slice(), true);
                    });
                    assert!(
                        r.is_err(),
                        "algo={}, ipVersion={}",
                        algo,
                        if is_ipv6 { '6' } else { '4' }
                    );
                }
            }
        }
    }

    #[test]
    fn test_algorithm_combos_none_always_panics() {
        let vec = vec![AlgorithmSpecification::None];
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_ok(),
                "none alone should be okay; ipVersion={0}",
                if is_ipv6 { '6' } else { '4' }
            );
        }

        for algo in [
            &*ALGO_DEFAULT_PUB_IP,
            &*ALGO_IGP,
            &*ALGO_PLUGIN_SIMPLE,
            &*ALGO_WEB_SERVICE_SIMPLE,
        ] {
            let vec_none_first = vec![AlgorithmSpecification::None, algo.clone()];
            let vec_none_last = vec![algo.clone(), AlgorithmSpecification::None];
            for is_ipv6 in [false, true] {
                let supports_ip_version = if is_ipv6 {
                    algo.supports_ipv6()
                } else {
                    algo.supports_ipv4()
                };
                if supports_ip_version {
                    let r = AlgorithmSpecification::validate_combination(
                        vec_none_first.as_slice(),
                        is_ipv6,
                    );
                    assert!(
                        r.is_err(),
                        "None before valid item should not validate; algo={}, ipVersion={}",
                        algo,
                        if is_ipv6 { '6' } else { '4' }
                    );

                    let r = AlgorithmSpecification::validate_combination(
                        vec_none_last.as_slice(),
                        is_ipv6,
                    );
                    assert!(
                        r.is_err(),
                        "None after valid item should not validate; algo={}, ipVersion={}",
                        algo,
                        if is_ipv6 { '6' } else { '4' }
                    );
                }
            }
        }
    }

    #[test]
    fn test_algorithm_combos_different_urls_okay() {
        let other = AlgorithmSpecification::WebService {
            url: Url::parse("http://example.com/").unwrap(),
            timeout: Duration::from_secs(1),
            default_encoding: None,
        };
        let vec = vec![other, ALGO_WEB_SERVICE_SIMPLE.clone()];
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_ok(),
                "algos={:?}, ipVersion={}, err={:?}",
                vec,
                if is_ipv6 { '6' } else { '4' },
                r.unwrap_err()
            );
        }
    }

    #[test]
    fn test_algorithm_combos_same_url_not_okay() {
        // Make another WebService algo -- same url, but other options all differ
        let other = if let AlgorithmSpecification::WebService {
            url,
            timeout,
            default_encoding,
        } = &*ALGO_WEB_SERVICE_SIMPLE
        {
            AlgorithmSpecification::WebService {
                url: url.clone(),
                timeout: timeout.clone() + Duration::from_mins(1),
                default_encoding: if default_encoding.is_some() {
                    None
                } else {
                    Some(encoding_rs::UTF_8)
                },
            }
        } else {
            panic!("It should not be possible to get here.");
        };

        let vec = vec![other, ALGO_WEB_SERVICE_SIMPLE.clone()];
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_err(),
                "algos={:?}, ipVersion={}",
                vec,
                if is_ipv6 { '6' } else { '4' }
            );
        }
    }

    #[test]
    fn test_algorithm_combos_different_plugins_okay() {
        let other = AlgorithmSpecification::Plugin {
            command: StringOrStringVec::String("/not/a/real/command".to_string()),
            timeout: Duration::from_secs(1),
            encoding: None,
        };
        let vec = vec![other, ALGO_PLUGIN_SIMPLE.clone()];
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_ok(),
                "algos={:?}, ipVersion={}, err={:?}",
                vec,
                if is_ipv6 { '6' } else { '4' },
                r.unwrap_err()
            );
        }
    }

    #[test]
    fn test_algorithm_combos_same_plugin_not_okay() {
        // Make another WebService algo -- same url, but other options all differ
        let other = if let AlgorithmSpecification::Plugin {
            command,
            timeout,
            encoding,
        } = &*ALGO_PLUGIN_SIMPLE
        {
            AlgorithmSpecification::Plugin {
                command: command.clone(),
                timeout: timeout.clone() + Duration::from_mins(1),
                encoding: if encoding.is_some() {
                    None
                } else {
                    Some(encoding_rs::UTF_8)
                },
            }
        } else {
            panic!("It should not be possible to get here.");
        };

        let vec = vec![other, ALGO_PLUGIN_SIMPLE.clone()];
        for is_ipv6 in [false, true] {
            let r = AlgorithmSpecification::validate_combination(vec.as_slice(), is_ipv6);
            assert!(
                r.is_err(),
                "algos={:?}, ipVersion={}",
                vec,
                if is_ipv6 { '6' } else { '4' }
            );
        }
    }
}
