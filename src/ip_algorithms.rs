use std::cmp::Eq;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::Send;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use std::vec::Vec;

use anyhow::{anyhow, Context};
use encoding_rs::{Encoding, mem::convert_latin1_to_utf8};
use igd_next::{search_gateway, SearchOptions};
use log::{debug, error, trace, warn};
use mime::Mime;
use netdev::{get_default_interface, Interface};
use reqwest::{Client, ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::task::spawn_blocking;
use tokio::time::sleep;
use tokio_stream::StreamExt;

static DEFAULT_INTERFACE: LazyLock<Result<Interface, String>> =
    LazyLock::new(get_default_interface);
static WEB_CLIENT: LazyLock<Result<Client, reqwest::Error>> =
    LazyLock::new(|| ClientBuilder::new().build());

const MAX_WEB_SERVICE_DOCUMENT_LENGTH: u64 = 65536;
const MAX_PLUGIN_DOCUMENT_LENGTH: u64 = 65535;

pub trait IpAddressV4orV6: Copy + Debug + Display + Eq + FromStr + Hash + Send {
    fn is_global(&self) -> bool;
}

impl IpAddressV4orV6 for Ipv4Addr {
    // Adapted from https://doc.rust-lang.org/1.80.1/src/core/net/ip_addr.rs.html#763-779
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
}

impl IpAddressV4orV6 for Ipv6Addr {
    // Adapted from https://doc.rust-lang.org/1.80.1/src/core/net/ip_addr.rs.html#763-779
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
            (self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
        )
        || (
            // ip.is_unique_local()
            (self.segments()[0] & 0xfe00) == 0xfc00
        )
        || (
            // ip.is_unicast_link_local()
            (self.segments()[0] & 0xffc0) == 0xfe80
        ))
    }
}

pub async fn get_default_public_ipv4() -> anyhow::Result<Vec<Ipv4Addr>> {
    let default_interface = (*DEFAULT_INTERFACE)
        .as_ref()
        .map_err(anyhow::Error::msg)
        .context("failed to determine default network interface")?;

    let mut result = Vec::<Ipv4Addr>::new();
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

pub async fn get_default_public_ipv6() -> anyhow::Result<Vec<Ipv6Addr>> {
    let default_interface = (*DEFAULT_INTERFACE)
        .as_ref()
        .map_err(anyhow::Error::msg)
        .context("failed to determine default network interface")?;

    let mut result = Vec::<Ipv6Addr>::new();
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

pub async fn get_igd_ipv4(timeout: &Duration) -> anyhow::Result<Vec<Ipv4Addr>> {
    let timeout = *timeout; // Make local copy prior to move

    // Spawn this into a thread (since it is blocking code)
    spawn_blocking(move || {
        let search_option = SearchOptions {
            timeout: Some(timeout),
            ..Default::default()
        };
        let gateway = search_gateway(search_option).context("error finding internet gateway")?;

        let ip = gateway
            .get_external_ip()
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
    })
    .await?
}

// Helper to download a document from a URL
async fn get_web_service_document(
    client: &Client,
    url: &Url,
    timeout: &Duration,
    default_encoding: Option<&'static Encoding>
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
        let e = Encoding::for_label(name.as_bytes());
        if e.is_none() {
            Err(anyhow!("unknown encoding: \"{name}\""))?
        }
        debug!("Found encoding={name} from Content-Type header");
        e
    } else {
        debug!("No Content-Type header found, or did not contain a charset");
        match default_encoding {
            Some(e) => debug!("Using configuration-provided default_encoding: {}", e.name()),
            None => debug!("Using HTTP default encoding: iso-8859-1")
        }
        default_encoding
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

    if let Some(e) = encoding {
        let rr =
            e.decode_without_bom_handling_and_without_replacement(body_binary.as_slice())
            .map(|s| s.into_owned())
        ;
        if rr.is_none() {
            error!("web-service response could not be decoded; value: {:X?}", body_binary.as_slice());
            return Err(anyhow!("failed to decode output with \"{}\"", e.name()));
        }
        Ok(rr.unwrap())
    } else {
        let mut buf = Vec::<u8>::with_capacity(body_binary.len() * 2);
        let num_bytes = convert_latin1_to_utf8(body_binary.as_slice(), buf.as_mut_slice());
        let rr = unsafe { String::from_raw_parts(buf.as_mut_ptr(), num_bytes, num_bytes) };
        Ok(rr)
    }
}

pub async fn get_web_service_ip<T>(url: &Url, timeout: &Duration, default_encoding: Option<&'static Encoding>) -> anyhow::Result<Vec<T>>
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
        trace!("Received result: {}", serde_json::to_string(line)?);
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

struct PluginEncoding<'a> {
    data: &'a [u8],
    encoding: &'static Encoding
}

impl<'a> PluginEncoding<'a> {
    fn find_encoding(data: &'a [u8], caller_encoding: Option<&'static Encoding>, default_encoding_name: &str) -> Self {
        if let Some(e) = caller_encoding {
            debug!("Using configuration-specified encoding: {0}", e.name());
            return Self {data, encoding: e};
        }

        #[cfg(windows)]
        {
            // If there is a NULL-byte near the start, assume UTF-16
            let high_byte_idx = if cfg!(target_endian = "little") {1} else {0};
            if high_byte_idx < data.len() && data[high_byte_idx] == 0 {
                debug!("Found NULL-byte in output; using encoding: UTF-16");
                return Self {data, encoding: Encoding::for_label(b"utf-16".as_slice()).unwrap()};
            }

            // If BOM-sniffing finds something, go with whatever it found
            if let Some(r) = Encoding::for_bom(data) {
                let e = r.0;
                let d = &data[(r.1)..];
                debug!("Found byte-order mark; using encoding: {}", e.name());
                return Self {data: d, encoding: e};
            }

            // Try the (Windows) OEM code page
            let code_page = unsafe { windows_sys::Win32::Globalization::GetACP() };
            let encoding_name = match code_page {
                // These conversions were extracted from the encoding_rs documentation
                950 => "Big5",
                951 => "Big5",
                20932 => "EUC-JP",
                949 => "EUC-KR",
                936 => "GBK",
                866 => "IBM866",
                50220 => "ISO-2022-JP",
                28603 => "ISO-8859-13",
                28605 => "ISO-8859-15",
                28592 => "ISO-8859-2",
                28593 => "ISO-8859-3",
                28594 => "ISO-8859-4",
                28595 => "ISO-8859-5",
                28596 => "ISO-8859-6",
                28597 => "ISO-8859-7",
                38598 => "ISO-8859-8-I",
                28598 => "ISO-8859-8",
                20866 => "KOI8-R",
                21866 => "KOI8-U",
                932 => "Shift_JIS",
                1201 => "UTF-16BE",
                1200 => "UTF-16LE",
                65001 => "UTF-8",
                54936 => "gb18030",
                10000 => "macintosh",
                1250 => "windows-1250",
                1251 => "windows-1251",
                1252 => "windows-1252",
                1253 => "windows-1253",
                1254 => "windows-1254",
                1255 => "windows-1255",
                1256 => "windows-1256",
                1257 => "windows-1257",
                1258 => "windows-1258",
                874 => "windows-874",
                10017 => "x-mac-cyrillic",
                _ => ""
            };
            if let Some(encoding) = Encoding::for_label(encoding_name.as_bytes()) {
                debug!("Using system OEM code-page ({code_page:0>3}) -> encoding: {}", encoding.name());
                return Self {data, encoding};
            } else {
                warn!("System OEM code-page ({code_page:0>3}) is unsupported; trying {default_encoding_name} instead");
            }
        }
        #[cfg(unix)]
        {
            // Use the first envvar to specify a codeset that we support
            let vars_to_try = ["LC_ALL", "LC_CTYPE", "LANG"];
            for var_to_try in vars_to_try.iter() {
                if let Some(os_value) = std::env::var_os(var_to_try) {
                    let os_value_bytes = os_value.as_os_str().as_encoded_bytes();
                    if let Some(start_offset) = os_value_bytes.iter().position(|b| *b == b'.') {
                        let codeset_name = if let Some(length) = os_value_bytes[start_offset..].iter().position(|b| *b == b'@') {
                            &os_value_bytes[start_offset..(start_offset + length)]
                        }
                        else {
                            &os_value_bytes[start_offset..]
                        };

                        if codeset_name.len() == 0 {
                            continue;
                        }

                        if let Some(encoding) = Encoding::for_label(codeset_name) {
                            debug!(
                                "Found env:{var_to_try}='{}'; using encoding: {}",
                                String::from_utf8_lossy(os_value_bytes),
                                encoding.name()
                            );
                            return Self { data, encoding };
                        }

                        debug!("Found env:{var_to_try}='{}'", String::from_utf8_lossy(os_value_bytes));
                        warn!(
                            "Codeset ({0}) is unsupported; ignoring",
                            String::from_utf8_lossy(codeset_name)
                        );
                    }
                }
            }
            debug!("No usable system locale codeset found; trying {0} instead", default_encoding_name);
        }

        Self {
            data,
            encoding: Encoding::for_label(default_encoding_name.as_bytes())
                .expect(format!("failed to load default encoding ({default_encoding_name})").as_str())
        }
    }
}

async fn get_plugin_output(
    command: &StringOrStringVec,
    timeout: &Duration,
    encoding: Option<&'static Encoding>
) -> anyhow::Result<String> {
    let mut command_obj: Command;

    match command {
        StringOrStringVec::String(s) => {
            if s.len() == 0 {
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
            if v.len() == 0 || v[0].len() == 0 {
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

    let mut child = command_obj.spawn().expect("plugin failed to start");
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("failed to unwrap stdout pipe");
    let read_stdout_fut = tokio::spawn(async move {
        let mut buff = Vec::new();
        let _ = stdout.take(MAX_PLUGIN_DOCUMENT_LENGTH).read_to_end(&mut buff).await;
        
        if buff.len() == (MAX_PLUGIN_DOCUMENT_LENGTH as usize) {
            return Err(anyhow!("plugin output must be less than {MAX_PLUGIN_DOCUMENT_LENGTH} bytes"));
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

    let stdout_content = read_stdout_fut
        .await
        .expect("failed to unwrap stdout buffer content")?;

    let stdout_decoded = {
        if stdout_content.len() == 0 {
            String::new()
        }
        else {
            let e = PluginEncoding::find_encoding(stdout_content.as_slice(), encoding, "UTF-8");
            if let Some(r) = e.encoding.decode_without_bom_handling_and_without_replacement(e.data) {
                r.into_owned()
            }
            else {
                error!("plugin output could not be decoded; value: {stdout_content:X?}");
                return Err(anyhow!("failed to decode plugin output (encoding=\"{0}\")", e.encoding.name()));
            }
        }
    };
    trace!("plugin output: {}", serde_json::to_string(stdout_decoded.as_str())?);
    if succeeded {
        return Ok(stdout_decoded);
    }
    else {
        return Err(anyhow!("plugin failed"));
    } 
}

pub async fn get_plugin_ip<T>(
    command: &StringOrStringVec,
    timeout: &Duration,
    encoding: Option<&'static Encoding>
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
