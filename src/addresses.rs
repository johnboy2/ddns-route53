use std::collections::HashSet;
use std::convert::From;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use aws_sdk_route53::types::ResourceRecordSet;

#[derive(Debug)]
pub struct Addresses {
    pub v4: HashSet<Ipv4Addr>,
    pub v6: HashSet<Ipv6Addr>,
}

pub struct Route53AddressRecords {
    pub v4: Option<ResourceRecordSet>,
    pub v6: Option<ResourceRecordSet>,
}

impl From<&Route53AddressRecords> for Addresses {
    fn from(item: &Route53AddressRecords) -> Self {
        let mut ipv4addr_set = HashSet::<Ipv4Addr>::new();
        item.v4.as_ref().map(|rrs| {
            for rr in rrs.resource_records() {
                ipv4addr_set
                    .insert(Ipv4Addr::from_str(rr.value.as_str()).expect("valid IPv4 address"));
            }
        });

        let mut ipv6addr_set = HashSet::<Ipv6Addr>::new();
        item.v6.as_ref().map(|rrs| {
            for rr in rrs.resource_records() {
                ipv6addr_set
                    .insert(Ipv6Addr::from_str(rr.value.as_str()).expect("valid IPv6 address"));
            }
        });

        Addresses {
            v4: ipv4addr_set,
            v6: ipv6addr_set,
        }
    }
}
