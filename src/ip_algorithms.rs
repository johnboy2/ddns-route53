use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::string::ToString;
use std::sync::LazyLock;
use std::time::Duration;
use std::vec::Vec;

use igd_next::{search_gateway, SearchOptions};
use log::debug;
use netdev::{get_default_interface, Interface};
use reqwest::{Client, ClientBuilder, Url};
use tokio::task::{spawn_blocking, JoinError};

static DEFAULT_INTERFACE: LazyLock<Result<Interface, String>> =
    LazyLock::new(get_default_interface);

static WEB_CLIENT: LazyLock<Result<Client, String>> =
    LazyLock::new(|| match ClientBuilder::new().build() {
        Ok(client) => Ok(client),
        Err(e) => Err(e.to_string()),
    });

const MAX_WEB_SERVICE_DOCUMENT_LENGTH: u64 = 65536;

// Adapted from https://doc.rust-lang.org/1.80.1/src/core/net/ip_addr.rs.html#763-779
fn ipv4_is_global(ip: &Ipv4Addr) -> bool {
    !(ip.octets()[0] == 0 // "This network"
    || ip.is_private()
    || (
        // ip.is_shared()
        ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000)
    )
    || ip.is_loopback()
    || ip.is_link_local()
    // addresses reserved for future protocols (`192.0.0.0/24`)
    // .9 and .10 are documented as globally reachable so they're excluded
    || (
        ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0
        && ip.octets()[3] != 9 && ip.octets()[3] != 10
    )
    || ip.is_documentation()
    || (
        // ip.is_benchmarking()
        ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18
    )
    || (
        // ip.is_reserved()
        ip.octets()[0] & 240 == 240 && !ip.is_broadcast()
    )
    || ip.is_broadcast())
}

// Adapted from https://doc.rust-lang.org/1.80.1/src/core/net/ip_addr.rs.html#763-779
fn ipv6_is_global(ip: &Ipv6Addr) -> bool {
    !(ip.is_unspecified()
    || ip.is_loopback()
    // IPv4-mapped Address (`::ffff:0:0/96`)
    || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
    // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
    || matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
    // Discard-Only Address Block (`100::/64`)
    || matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _])
    // IETF Protocol Assignments (`2001::/23`)
    || (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
        && !(
            // Port Control Protocol Anycast (`2001:1::1`)
            u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
            // Traversal Using Relays around NAT Anycast (`2001:1::2`)
            || u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
            // AMT (`2001:3::/32`)
            || matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _])
            // AS112-v6 (`2001:4:112::/48`)
            || matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
            // ORCHIDv2 (`2001:20::/28`)
            // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
            || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
        ))
    // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
    // IANA says N/A.
    || matches!(ip.segments(), [0x2002, _, _, _, _, _, _, _])
    || (
        // ip.is_documentation()
        (ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)
    )
    || (
        // ip.is_unique_local()
        (ip.segments()[0] & 0xfe00) == 0xfc00
    )
    || (
        // ip.is_unicast_link_local()
        (ip.segments()[0] & 0xffc0) == 0xfe80
    ))
}

// Helper to download a document from a URL
async fn get_web_service_document(
    client: &Client,
    url: Url,
    url_string: &String,
    timeout: Duration,
) -> Result<String, String> {
    let request = client.get(url).timeout(timeout).send();

    let response = match request.await {
        Ok(r) => r,
        Err(e) => return Err(format!("Failed to fetch from URL \"{url_string}\": {e}")),
    };

    if let Some(cl) = response.content_length() {
        if MAX_WEB_SERVICE_DOCUMENT_LENGTH < cl {
            return Err(format!(
                "Result body from URL \"{}\": Content-Length ({}) too large (max={})",
                url_string, cl, MAX_WEB_SERVICE_DOCUMENT_LENGTH
            ));
        }
    }

    // TODO: implement a maximum read size for a streaming response

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return Err(format!(
                "Failed to read result body from URL \"{url_string}\": {e}"
            ))
        }
    };
    Ok(body)
}

pub async fn get_default_public_ip_v4() -> Result<Vec<Ipv4Addr>, String> {
    let default_interface = match &*DEFAULT_INTERFACE {
        Ok(interface) => interface,
        Err(e) => return Err(e.to_owned()),
    };

    let mut result = Vec::<Ipv4Addr>::new();
    for ip_net in &default_interface.ipv4 {
        let ip_net_addr = ip_net.addr();
        if ipv4_is_global(&ip_net_addr) {
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

pub async fn get_igd_ip_v4(timeout: Duration) -> Result<Vec<Ipv4Addr>, String> {
    // This algorithm blocks, so we spin it off into its own thread.
    let thread_result: Result<Result<Vec<Ipv4Addr>, String>, JoinError> = spawn_blocking(move || {
        let search_option = SearchOptions {
            timeout: Some(timeout),
            ..Default::default()
        };
        let gateway = match search_gateway(search_option) {
            Ok(gw) => gw,
            Err(e) => {
                return Err(
                    format!("Failed to find internet gateway: {e}")
                );
            }
        };

        match gateway.get_external_ip() {
            Ok(ip) => {
                if let IpAddr::V4(v4) = ip {
                    if ipv4_is_global(&v4) {
                        return Ok(vec![v4]);
                    } else {
                        debug!(
                            "Ignoring address [{}] reported by internet gateway: address is non-global",
                            v4
                        );
                    }
                }
                Ok(Vec::<Ipv4Addr>::new())
            },
            Err(e) => {
                Err(
                    format!("Failed to determine internet gateway external IP address: {e}")
                )
            }
        }
    }).await;

    match thread_result {
        Ok(result) => result,
        Err(e) => Err(format!(
            "Error joining thread searching for internet gateway device: {e}"
        )),
    }
}

pub async fn get_web_service_ip_v4(
    url: Url,
    url_string: String,
    timeout: Duration,
) -> Result<Vec<Ipv4Addr>, String> {
    let client = (*WEB_CLIENT).as_ref()?;

    let body = get_web_service_document(client, url, &url_string, timeout).await?;

    let mut result = Vec::<Ipv4Addr>::new();
    for line in body.as_str().lines() {
        match Ipv4Addr::from_str(line) {
            Ok(ip) => {
                if ipv4_is_global(&ip) {
                    result.push(ip)
                } else {
                    debug!(
                        "Ignoring address [{}] reported by web-service:{}: address is non-global",
                        ip, url_string
                    );
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to parse result as IPv4 address: \"{}\": {}",
                    line,
                    e.to_string().as_str()
                ))
            }
        }
    }

    Ok(result)
}

pub async fn get_default_public_ip_v6() -> Result<Vec<Ipv6Addr>, String> {
    let default_interface = match &*DEFAULT_INTERFACE {
        Ok(interface) => interface,
        Err(e) => return Err(e.to_owned()),
    };

    let mut result = Vec::<Ipv6Addr>::new();
    for ip_net in &default_interface.ipv6 {
        let ip_net_addr = ip_net.addr();
        if ipv6_is_global(&ip_net_addr) {
            result.push(ip_net_addr)
        } else {
            debug!(
                "Ignoring address [{}] on default interface: address is non-global",
                ip_net_addr
            );
        }
    }

    Ok(result)
}

pub async fn get_web_service_ip_v6(
    url: Url,
    url_string: String,
    timeout: Duration,
) -> Result<Vec<Ipv6Addr>, String> {
    let client = (*WEB_CLIENT).as_ref()?;

    let body = get_web_service_document(client, url, &url_string, timeout).await?;

    let mut result = Vec::<Ipv6Addr>::new();
    for line in body.as_str().lines() {
        match Ipv6Addr::from_str(line) {
            Ok(ip) => {
                if ipv6_is_global(&ip) {
                    result.push(ip)
                } else {
                    debug!(
                        "Ignoring address [{}] reported by web-service:{}: address is non-global",
                        ip, url_string
                    );
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to parse result as IPv6 address: \"{}\": {}",
                    line,
                    e.to_string().as_str()
                ))
            }
        }
    }

    Ok(result)
}
