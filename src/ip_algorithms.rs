use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::string::ToString;
use std::sync::LazyLock;
use std::vec::Vec;

use netdev::Interface;


static DEFAULT_INTERFACE: LazyLock<Result<Interface, String>> = LazyLock::new(||
    netdev::get_default_interface()
);


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
            || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x3F)
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


pub async fn get_default_public_ip_v4() -> Result::<Vec::<Ipv4Addr>, String> {
    let default_interface = match &*DEFAULT_INTERFACE {
        Ok(interface) => interface,
        Err(e) => { return Err(e.to_owned()) }
    };

    let mut result = std::vec::Vec::<Ipv4Addr>::new();
    for ip_net in &default_interface.ipv4 {
        if ipv4_is_global(&ip_net.addr) {
            result.push(ip_net.addr.to_owned())
        }
    }

    Ok(result)
}


pub async fn get_default_public_ip_v6() -> Result::<Vec::<Ipv6Addr>, String> {
    let default_interface = match &*DEFAULT_INTERFACE {
        Ok(interface) => interface,
        Err(e) => { return Err(e.to_owned()) }
    };

    let mut result = std::vec::Vec::<Ipv6Addr>::new();
    for ip_net in &default_interface.ipv6 {
        if ipv6_is_global(&ip_net.addr) {
            result.push(ip_net.addr.to_owned())
        }
    }

    Ok(result)
}


struct WebServiceInvocation {
    uri_string: String,
    uri_parsed: reqwest::Url,
    timeout: std::time::Duration,
    client: reqwest::Client,
}

trait Ipv4OrIpv6 : FromStr + ToString {}
impl Ipv4OrIpv6 for Ipv4Addr {}
impl Ipv4OrIpv6 for Ipv6Addr {}


impl WebServiceInvocation {
    pub fn new(url: &String, timeout_seconds: f64) -> Result::<Self, String> {
        let uri = match reqwest::Url::parse(url) {
            Ok(uri) => uri,
            Err(e) => { return Err(e.to_string()); }
        };
        
        Ok(Self {
            uri_string: url.to_owned(),
            uri_parsed: uri,
            timeout: std::time::Duration::from_secs_f64(timeout_seconds),
            client: reqwest::Client::new(),
        })
    }

    pub async fn get_ip_address<T: Ipv4OrIpv6>(&self) -> Result<Vec::<T>, String>
    where <T as FromStr>::Err: ToString
    {
        let request = self.client.get(self.uri_parsed.to_owned())
            .timeout(self.timeout)
            .send()
        ;
        let response = match request.await {
            Ok(r) => r,
            Err(e) => {
                return Err(format!(
                    "Failed to fetch from URL \"{}\": {}",
                    self.uri_string, 
                    e.to_string()
                ))
            }
        };
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return Err(format!(
                    "Failed to read result body from URL \"{}\": {}",
                    self.uri_string, 
                    e.to_string()
                ))
            }
        };

        let mut result = Vec::<T>::new();
        for line in body.as_str().lines() {
            match T::from_str(line) {
                Ok(ip) => { result.push(ip) },
                Err(e) => {
                    return Err(format!(
                        "Failed to parse result as IPv4 address: \"{}\": {}",
                        line, e.to_string().as_str()
                    ))
                }
            }
        }

        Ok(result)
    }
}


struct IgdSearchInvocation {
    timeout: std::time::Duration,
}


impl IgdSearchInvocation {
    pub fn new(timeout_seconds: f64) -> Self {
        Self {
            timeout: std::time::Duration::from_secs_f64(timeout_seconds),
        }
    }

    pub async fn get_ip_address_v4(&self) -> Result<Vec::<Ipv4Addr>, String> {
        let timeout = Some(self.timeout);

        let thread_result: Result<Result<Vec<Ipv4Addr>, String>, tokio::task::JoinError> = tokio::task::spawn_blocking(move || {
            let search_option = igd_next::SearchOptions {
                timeout: timeout,
                ..Default::default()
            };
            let gateway = match igd_next::search_gateway(search_option) {
                Ok(gw) => gw,
                Err(e) => {
                    return Err(
                        format!("Failed to find internet gateway: {}", e.to_string())
                    );
                }
            };

            match gateway.get_external_ip() {
                Ok(ip) => {
                    match ip {
                        std::net::IpAddr::V4(v4) => {
                            return Ok(vec![v4]);
                        },
                        _ => {
                            // Silently ignore this case
                            return Ok(Vec::<Ipv4Addr>::new())
                        }
                    }
                },
                Err(e) => {
                    return Err(
                        format!("Failed to determine internet gateway external IP address: {}", e.to_string())
                    );
                }
            }
        }).await;

        match thread_result {
            Ok(result) => result,
            Err(e) => {
                return Err(format!(
                    "Error joining thread searching for internet gateway device: {}",
                    e.to_string()
                ))
            }
        }
    }
}
