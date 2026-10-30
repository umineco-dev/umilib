use crate::protocol::ethernet::MACAddress;
use crate::protocol::ip::IPv4Address;

/// An address that ARP carries, of a fixed length: a hardware address or
/// a protocol address (RFC 826 lets both be of any length).
pub trait ARPAddress: Copy + Eq {
    const LENGTH: usize;

    /// The address of `bytes`, which are [`ARPAddress::LENGTH`] long.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    fn as_bytes(&self) -> &[u8];

    /// Whether every byte is zero: the sender protocol address of a probe
    /// (RFC 5227 §2.1.1), which no cache learns.
    fn is_unspecified(&self) -> bool {
        self.as_bytes().iter().all(|&byte| byte == 0)
    }

    /// Whether the address names a group (a multicast or broadcast hardware
    /// address), which no host has as its own: no cache learns it as a
    /// sender's (RFC 1812 §3.3.2). Addresses without groups have none.
    fn is_multicast(&self) -> bool {
        false
    }
}

impl<const N: usize> ARPAddress for [u8; N] {
    const LENGTH: usize = N;

    fn from_bytes(bytes: &[u8]) -> Option<[u8; N]> {
        bytes.try_into().ok()
    }

    fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl ARPAddress for MACAddress {
    const LENGTH: usize = MACAddress::LENGTH;

    fn from_bytes(bytes: &[u8]) -> Option<MACAddress> {
        bytes.try_into().ok().map(MACAddress)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn is_multicast(&self) -> bool {
        MACAddress::is_multicast(self)
    }
}

impl ARPAddress for IPv4Address {
    const LENGTH: usize = IPv4Address::LENGTH;

    fn from_bytes(bytes: &[u8]) -> Option<IPv4Address> {
        bytes.try_into().ok().map(IPv4Address)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
