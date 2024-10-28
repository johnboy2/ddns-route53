use std::net::{Ipv4Addr, Ipv6Addr};
use std::vec::Vec;

use aws_sdk_route53::types::ResourceRecordSet;

#[derive(Debug)]
pub struct Addresses {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

// TODO: Consider writing your own fmt::Debutg impl for this, which doesn't emit any of the 'None' value from the ResourceRecordSet object.
//       That would be helpful, because there are more such 'None' values that non-None ones -- leading to cleaner output.
#[derive(Debug)]
pub struct AddressRecords {
    pub v4: Option<ResourceRecordSet>,
    pub v6: Option<ResourceRecordSet>,
}
