// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::collections::HashSet;
use std::convert::From;
use std::net::{Ipv4Addr, Ipv6Addr};

use aws_sdk_route53::types::ResourceRecordSet;
use crate::aws_route53::get_ip_addresses_from_resource_record_set;


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
        let ipv4addr_set = if let Some(rrs) = item.v4.as_ref() {
            get_ip_addresses_from_resource_record_set::<Ipv4Addr>(rrs)
        }
        else {
            HashSet::<Ipv4Addr>::new()
        };

        let ipv6addr_set = if let Some(rrs) = item.v6.as_ref() {
            get_ip_addresses_from_resource_record_set::<Ipv6Addr>(rrs)
        }
        else {
            HashSet::<Ipv6Addr>::new()
        };

        Addresses {
            v4: ipv4addr_set,
            v6: ipv6addr_set,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use aws_sdk_route53::types::{ResourceRecord, RrType};

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
        assert_eq!(addresses.v4.len(), 0, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 0, "{:?}", addresses.v6);
    }

    #[test]
    fn test_from_single_v4_record_set() {
        let ip_addr = "192.168.0.1";

        let empty = Route53AddressRecords {
            v4: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::A)
                    .resource_records(ResourceRecord::builder().value(ip_addr).build().unwrap())
                    .build()
                    .unwrap(),
            ),
            v6: None,
        };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 1, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 0, "{:?}", addresses.v6);

        assert!(
            addresses.v4.contains(&Ipv4Addr::from_str(ip_addr).unwrap()),
            "{:?}",
            addresses.v4
        );
    }

    #[test]
    fn test_from_multiple_v4_record_set() {
        let ip_addr1 = "192.168.0.1";
        let ip_addr2 = "192.168.0.2";
        let ip_addr3 = "192.168.0.3";
        let ip_addr4 = "192.168.0.4";
        let ip_addr5 = "192.168.0.5";

        let empty = Route53AddressRecords {
            v4: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::A)
                    .resource_records(ResourceRecord::builder().value(ip_addr1).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr2).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr3).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr4).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr5).build().unwrap())
                    .build()
                    .unwrap(),
            ),
            v6: None,
        };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 5, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 0, "{:?}", addresses.v6);

        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr1).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr2).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr3).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr4).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr5).unwrap()),
            "{:?}",
            addresses.v4
        );
    }

    #[test]
    fn test_from_single_v6_record_set() {
        let ip_addr = "::1";

        let empty = Route53AddressRecords {
            v4: None,
            v6: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::Aaaa)
                    .resource_records(ResourceRecord::builder().value(ip_addr).build().unwrap())
                    .build()
                    .unwrap(),
            ),
        };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 0, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 1, "{:?}", addresses.v6);

        assert!(
            addresses.v6.contains(&Ipv6Addr::from_str(ip_addr).unwrap()),
            "{:?}",
            addresses.v6
        );
    }

    #[test]
    fn test_from_multiple_v6_record_set() {
        let ip_addr1 = "::1";
        let ip_addr2 = "::2";
        let ip_addr3 = "::3";
        let ip_addr4 = "::4";
        let ip_addr5 = "::5";

        let empty = Route53AddressRecords {
            v4: None,
            v6: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::Aaaa)
                    .resource_records(ResourceRecord::builder().value(ip_addr1).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr2).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr3).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr4).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr5).build().unwrap())
                    .build()
                    .unwrap(),
            ),
        };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 0, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 5, "{:?}", addresses.v6);

        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr1).unwrap()),
            "{:?}",
            addresses.v6
        );
        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr2).unwrap()),
            "{:?}",
            addresses.v6
        );
        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr3).unwrap()),
            "{:?}",
            addresses.v6
        );
        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr4).unwrap()),
            "{:?}",
            addresses.v6
        );
        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr5).unwrap()),
            "{:?}",
            addresses.v6
        );
    }

    #[test]
    fn test_from_some_of_each_record_set() {
        let ip_addr4_1 = "192.168.0.1";
        let ip_addr4_2 = "192.168.0.2";
        let ip_addr6_1 = "::3";

        let empty = Route53AddressRecords {
            v4: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::A)
                    .resource_records(ResourceRecord::builder().value(ip_addr4_1).build().unwrap())
                    .resource_records(ResourceRecord::builder().value(ip_addr4_2).build().unwrap())
                    .build()
                    .unwrap(),
            ),
            v6: Some(
                ResourceRecordSet::builder()
                    .name("example.com")
                    .r#type(RrType::Aaaa)
                    .resource_records(ResourceRecord::builder().value(ip_addr6_1).build().unwrap())
                    .build()
                    .unwrap(),
            ),
        };
        let addresses = Addresses::from(&empty);
        assert_eq!(addresses.v4.len(), 2, "{:?}", addresses.v4);
        assert_eq!(addresses.v6.len(), 1, "{:?}", addresses.v6);

        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr4_1).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v4
                .contains(&Ipv4Addr::from_str(ip_addr4_2).unwrap()),
            "{:?}",
            addresses.v4
        );
        assert!(
            addresses
                .v6
                .contains(&Ipv6Addr::from_str(ip_addr6_1).unwrap()),
            "{:?}",
            addresses.v6
        );
    }
}
