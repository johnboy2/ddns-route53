// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::collections::HashSet;
use std::convert::From;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::aws_route53::get_ip_addresses_from_resource_record_set;
use aws_sdk_route53::types::ResourceRecordSet;

#[derive(Debug, Default)]
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
        let ipv4addr_set = item
            .v4
            .as_ref()
            .map(|rrs| get_ip_addresses_from_resource_record_set::<Ipv4Addr>(rrs))
            .unwrap_or_default();

        let ipv6addr_set = item
            .v6
            .as_ref()
            .map(|rrs| get_ip_addresses_from_resource_record_set::<Ipv6Addr>(rrs))
            .unwrap_or_default();

        Addresses {
            v4: ipv4addr_set,
            v6: ipv6addr_set,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_route53::types::{ResourceRecord, RrType};

    use std::str::FromStr;

    // Helper to create a simple ResourceRecordSet for testing
    fn create_rrs(ip: &str, r_type: RrType) -> ResourceRecordSet {
        ResourceRecordSet::builder()
            .name("example.com")
            .r#type(r_type)
            .resource_records(ResourceRecord::builder().value(ip).build().unwrap())
            .build()
            .unwrap()
    }

    // Helper to create a more complex ResourceRecordSet for testing
    fn create_rrs_multiple(ips: &[&str], r_type: RrType) -> ResourceRecordSet {
        let mut builder = ResourceRecordSet::builder()
            .name("example.com")
            .r#type(r_type);

        for ip in ips {
            builder =
                builder.resource_records(ResourceRecord::builder().value(*ip).build().unwrap());
        }

        builder.build().unwrap()
    }

    #[test]
    fn test_from_null_record_set() {
        let empty = Route53AddressRecords { v4: None, v6: None };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 0, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 0, "{:?}", addresses.v6);
    }

    #[test]
    fn test_from_empty_record_set() {
        let empty = Route53AddressRecords {
            v4: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::A)
                    .build()
                    .unwrap(),
            ),
            v6: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::Aaaa)
                    .build()
                    .unwrap(),
            ),
        };
        let addresses = Addresses::from(&empty);
        assert!(addresses.v4.is_empty(), "{:?}", addresses.v4);
        assert!(addresses.v6.is_empty(), "{:?}", addresses.v6);
    }

    #[test]
    fn test_from_single_v4_record_set() {
        let ip_addr = "192.168.0.1";
        let rrs = create_rrs(ip_addr, RrType::A);

        let records = Route53AddressRecords {
            v4: Some(rrs),
            v6: None,
        };
        let addresses = Addresses::from(&records);

        assert_eq!(addresses.v4.len(), 1, "{:?}", addresses.v4);
        assert!(
            addresses.v4.contains(&Ipv4Addr::from_str(ip_addr).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(addresses.v6.is_empty(), "{:?}", addresses.v6);
    }

    #[test]
    fn test_from_multiple_v4_record_set() {
        let ips = [
            "192.168.0.1",
            "192.168.0.2",
            "192.168.0.3",
            "192.168.0.4",
            "192.168.0.5",
        ];
        let rrs = create_rrs_multiple(&ips, RrType::A);

        let records = Route53AddressRecords {
            v4: Some(rrs),
            v6: None,
        };
        let addresses = Addresses::from(&records);

        assert_eq!(addresses.v4.len(), 5, "{:?}", addresses.v4);
        assert!(addresses.v6.is_empty(), "{:?}", addresses.v6);
        for ip in ips {
            assert!(
                addresses.v4.contains(&Ipv4Addr::from_str(ip).unwrap()),
                "{:?}",
                addresses.v4
            );
        }
    }

    #[test]
    fn test_from_single_v6_record_set() {
        let ip_addr = "::1";
        let rrs = create_rrs(ip_addr, RrType::Aaaa);

        let records = Route53AddressRecords {
            v4: None,
            v6: Some(rrs),
        };
        let addresses = Addresses::from(&records);

        assert!(addresses.v4.is_empty(), "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 1, "{:?}", addresses.v6);
        assert!(
            addresses.v6.contains(&Ipv6Addr::from_str(ip_addr).unwrap()),
            "{:?}",
            addresses.v6
        );
    }

    #[test]
    fn test_from_multiple_v6_record_set() {
        let ips = ["::1", "::2", "::3", "::4", "::5"];
        let rrs = create_rrs_multiple(&ips, RrType::Aaaa);

        let records = Route53AddressRecords {
            v4: None,
            v6: Some(rrs),
        };
        let addresses = Addresses::from(&records);

        assert!(addresses.v4.is_empty());
        assert_eq!(addresses.v6.len(), 5, "{:?}", addresses.v6);
        for ip in ips {
            assert!(
                addresses.v6.contains(&Ipv6Addr::from_str(ip).unwrap()),
                "{:?}",
                addresses.v6
            );
        }
    }

    #[test]
    fn test_from_some_of_each_record_set() {
        let v4_ips = ["192.168.0.1", "192.168.0.2"];
        let v6_ips = ["::3"];

        let v4_rrs = create_rrs_multiple(&v4_ips, RrType::A);
        let v6_rrs = create_rrs_multiple(&v6_ips, RrType::Aaaa);

        let records = Route53AddressRecords {
            v4: Some(v4_rrs),
            v6: Some(v6_rrs),
        };
        let addresses = Addresses::from(&records);

        assert_eq!(addresses.v4.len(), v4_ips.len(), "{:?}", addresses.v4);
        for ip in v4_ips {
            assert!(
                addresses.v4.contains(&Ipv4Addr::from_str(ip).unwrap()),
                "{:?}",
                addresses.v4
            );
        }

        assert_eq!(addresses.v6.len(), v6_ips.len(), "{:?}", addresses.v6);
        for ip in v6_ips {
            assert!(
                addresses.v6.contains(&Ipv6Addr::from_str(ip).unwrap()),
                "{:?}",
                addresses.v6
            );
        }
    }
}
