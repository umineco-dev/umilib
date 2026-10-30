use core::fmt;
use core::str::FromStr;

use super::{IPError, IPv6Address};

/// An IPv4 address (RFC 791), in network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(C)]
pub struct IPv4Address(pub [u8; 4]);

impl IPv4Address {
    pub const LENGTH: usize = 4;
    pub const BITS: u8 = 32;
    /// 0.0.0.0, "this host on this network" (RFC 1122 §3.2.1.3).
    pub const UNSPECIFIED: IPv4Address = IPv4Address([0, 0, 0, 0]);
    /// 127.0.0.1.
    pub const LOOPBACK: IPv4Address = IPv4Address([127, 0, 0, 1]);
    /// 255.255.255.255, the limited broadcast address (RFC 919, RFC 1122 §3.2.1.3).
    pub const BROADCAST: IPv4Address = IPv4Address([255, 255, 255, 255]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> IPv4Address {
        IPv4Address([a, b, c, d])
    }

    /// The address whose bits, most significant first, are those of `bits`.
    pub const fn from_bits(bits: u32) -> IPv4Address {
        IPv4Address(bits.to_be_bytes())
    }

    pub const fn to_bits(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// The address with every bit after the first `length` cleared (all of
    /// them are kept from a length of 32 on).
    pub const fn prefix(&self, length: u8) -> IPv4Address {
        IPv4Address::from_bits(self.to_bits() & IPv4Address::mask(length))
    }

    /// Whether the first `length` bits are those of `prefix`.
    pub const fn has_prefix(&self, prefix: &IPv4Address, length: u8) -> bool {
        (self.to_bits() ^ prefix.to_bits()) & IPv4Address::mask(length) == 0
    }

    /// The netmask of a prefix of `length` bits (all of them from 32 on).
    pub const fn mask(length: u8) -> u32 {
        if length >= IPv4Address::BITS { u32::MAX } else { !(u32::MAX >> length) }
    }

    pub const fn is_unspecified(&self) -> bool {
        self.to_bits() == 0
    }

    /// 127.0.0.0/8 (RFC 1122 §3.2.1.3).
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (RFC 1918).
    pub const fn is_private(&self) -> bool {
        matches!(self.0, [10, ..] | [172, 16..=31, ..] | [192, 168, ..])
    }

    /// 169.254.0.0/16 (RFC 3927).
    pub const fn is_link_local(&self) -> bool {
        matches!(self.0, [169, 254, ..])
    }

    /// 224.0.0.0/4 (RFC 5771).
    pub const fn is_multicast(&self) -> bool {
        self.0[0] >> 4 == 0b1110
    }

    pub const fn is_broadcast(&self) -> bool {
        self.to_bits() == u32::MAX
    }

    /// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (RFC 5737).
    pub const fn is_documentation(&self) -> bool {
        matches!(self.0, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
    }

    /// The IPv4-mapped IPv6 address `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2).
    pub const fn to_ipv6_mapped(&self) -> IPv6Address {
        let [a, b, c, d] = self.0;
        IPv6Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d])
    }

    /// Reads a dotted decimal address: four decimal numbers from 0 to 255
    /// without leading zeros (which some readers take as octal; RFC 6943
    /// §3.1.1), separated by dots.
    pub fn from_ascii(text: &[u8]) -> Result<IPv4Address, IPError> {
        let mut octets = [0u8; 4];
        let mut parts = text.split(|&byte| byte == b'.');
        for octet in &mut octets {
            let part = parts.next().ok_or(IPError::Syntax)?;
            *octet = IPv4Address::decimal(part).ok_or(IPError::Syntax)?;
        }
        if parts.next().is_some() {
            return Err(IPError::Syntax);
        }
        Ok(IPv4Address(octets))
    }

    /// The value of a decimal number from 0 to 255 without leading zeros.
    pub fn decimal(digits: &[u8]) -> Option<u8> {
        if digits.is_empty() || digits.len() > 3 || (digits.len() > 1 && digits[0] == b'0') {
            return None;
        }
        let mut value = 0u16;
        for &digit in digits {
            if !digit.is_ascii_digit() {
                return None;
            }
            value = value * 10 + (digit - b'0') as u16;
        }
        u8::try_from(value).ok()
    }
}

impl From<[u8; 4]> for IPv4Address {
    fn from(octets: [u8; 4]) -> IPv4Address {
        IPv4Address(octets)
    }
}

impl From<IPv4Address> for [u8; 4] {
    fn from(address: IPv4Address) -> [u8; 4] {
        address.0
    }
}

impl FromStr for IPv4Address {
    type Err = IPError;

    fn from_str(text: &str) -> Result<IPv4Address, IPError> {
        IPv4Address::from_ascii(text.as_bytes())
    }
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(formatter, "{a}.{b}.{c}.{d}")
    }
}
