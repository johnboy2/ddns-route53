use std::net::{Ipv4Addr, Ipv6Addr};
use std::vec::Vec;

#[derive(Debug, PartialEq)]
pub struct Addresses {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}
