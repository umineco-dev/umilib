use core::fmt;
use core::str::FromStr;

use super::{IPError, IPv4Address, IPv6Address};

/// An address of either IP version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IPAddress {
    V4(IPv4Address),
    V6(IPv6Address),
}

impl IPAddress {
    /// The version number: 4 or 6.
    pub const fn version(&self) -> u8 {
        match self {
            IPAddress::V4(_) => 4,
            IPAddress::V6(_) => 6,
        }
    }

    /// The bytes of the address, in network byte order.
    pub fn octets(&self) -> &[u8] {
        match self {
            IPAddress::V4(address) => &address.0,
            IPAddress::V6(address) => &address.0,
        }
    }

    /// The address of `octets`: 4 bytes for IPv4, 16 for IPv6.
    pub fn from_octets(octets: &[u8]) -> Result<IPAddress, IPError> {
        if let Ok(octets) = <[u8; 4]>::try_from(octets) {
            return Ok(IPAddress::V4(IPv4Address(octets)));
        }
        <[u8; 16]>::try_from(octets).map(|octets| IPAddress::V6(IPv6Address(octets))).map_err(|_| IPError::Length)
    }

    /// The IPv4 address of an IPv4-mapped IPv6 address, and the address
    /// itself otherwise.
    pub const fn to_canonical(&self) -> IPAddress {
        match self {
            IPAddress::V6(address) => match address.to_ipv4_mapped() {
                Some(address) => IPAddress::V4(address),
                None => *self,
            },
            IPAddress::V4(_) => *self,
        }
    }

    pub const fn is_unspecified(&self) -> bool {
        match self {
            IPAddress::V4(address) => address.is_unspecified(),
            IPAddress::V6(address) => address.is_unspecified(),
        }
    }

    pub const fn is_loopback(&self) -> bool {
        match self {
            IPAddress::V4(address) => address.is_loopback(),
            IPAddress::V6(address) => address.is_loopback(),
        }
    }

    pub const fn is_multicast(&self) -> bool {
        match self {
            IPAddress::V4(address) => address.is_multicast(),
            IPAddress::V6(address) => address.is_multicast(),
        }
    }

    pub const fn is_link_local(&self) -> bool {
        match self {
            IPAddress::V4(address) => address.is_link_local(),
            IPAddress::V6(address) => address.is_link_local(),
        }
    }

    pub const fn is_documentation(&self) -> bool {
        match self {
            IPAddress::V4(address) => address.is_documentation(),
            IPAddress::V6(address) => address.is_documentation(),
        }
    }

    /// The address with every bit after the first `length` cleared.
    pub const fn prefix(&self, length: u8) -> IPAddress {
        match self {
            IPAddress::V4(address) => IPAddress::V4(address.prefix(length)),
            IPAddress::V6(address) => IPAddress::V6(address.prefix(length)),
        }
    }

    /// Whether the first `length` bits are those of `prefix`; never for a
    /// prefix of the other version.
    pub const fn has_prefix(&self, prefix: &IPAddress, length: u8) -> bool {
        match (self, prefix) {
            (IPAddress::V4(address), IPAddress::V4(prefix)) => address.has_prefix(prefix, length),
            (IPAddress::V6(address), IPAddress::V6(prefix)) => address.has_prefix(prefix, length),
            _ => false,
        }
    }

    /// The prefix of `length` bits of this address as [`IPAddress::to_canonical`]
    /// makes it: a prefix of at least 96 bits of an IPv4-mapped IPv6
    /// address is the IPv4 prefix of `length - 96` bits (RFC 4291
    /// §2.5.5.2); any other is itself. The bits after the length are cleared,
    /// and a length beyond the address's bits is all of them.
    pub const fn to_canonical_prefix(&self, length: u8) -> (IPAddress, u8) {
        let (address, length) = match self {
            IPAddress::V6(address) => match address.to_ipv4_mapped() {
                Some(mapped) if length >= 96 => (IPAddress::V4(mapped), length - 96),
                _ => (*self, length),
            },
            IPAddress::V4(_) => (*self, length),
        };
        let bits = match address {
            IPAddress::V4(_) => 32,
            IPAddress::V6(_) => 128,
        };
        let length = if length > bits { bits } else { length };
        (address.prefix(length), length)
    }

    /// Reads an IPv6 address if the text has a colon, and an IPv4 address otherwise.
    pub fn from_ascii(text: &[u8]) -> Result<IPAddress, IPError> {
        if text.contains(&b':') {
            IPv6Address::from_ascii(text).map(IPAddress::V6)
        } else {
            IPv4Address::from_ascii(text).map(IPAddress::V4)
        }
    }
}

impl From<IPv4Address> for IPAddress {
    fn from(address: IPv4Address) -> IPAddress {
        IPAddress::V4(address)
    }
}

impl From<IPv6Address> for IPAddress {
    fn from(address: IPv6Address) -> IPAddress {
        IPAddress::V6(address)
    }
}

impl FromStr for IPAddress {
    type Err = IPError;

    fn from_str(text: &str) -> Result<IPAddress, IPError> {
        IPAddress::from_ascii(text.as_bytes())
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IPAddress::V4(address) => address.fmt(formatter),
            IPAddress::V6(address) => address.fmt(formatter),
        }
    }
}
