use core::fmt;
use core::str::FromStr;

use super::EthernetError;

/// A 48-bit MAC address (an EUI-48, IEEE 802), in transmission byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(C)]
pub struct MACAddress(pub [u8; 6]);

impl MACAddress {
    pub const LENGTH: usize = 6;
    pub const ZERO: MACAddress = MACAddress([0; 6]);
    pub const BROADCAST: MACAddress = MACAddress([0xFF; 6]);

    /// Whether the Individual/Group bit is set: a group (multicast or broadcast) address.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    pub const fn is_broadcast(&self) -> bool {
        matches!(self.0, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    /// Whether the Universal/Local bit is set: an address not assigned by its organization's identifier.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// The modified EUI-64 interface identifier of the address (RFC 4291
    /// appendix A, RFC 2464 §4): `FF-FE` in the middle and the
    /// Universal/Local bit inverted.
    pub const fn modified_eui64(&self) -> [u8; 8] {
        let [a, b, c, d, e, f] = self.0;
        [a ^ 0x02, b, c, 0xFF, 0xFE, d, e, f]
    }

    /// The address that the IPv4 multicast address `address` maps to:
    /// `01-00-5E` and its last 23 bits (RFC 1112 §6.4, RFC 7042 §2.1.1).
    pub const fn from_ipv4_multicast(address: [u8; 4]) -> MACAddress {
        MACAddress([0x01, 0x00, 0x5E, address[1] & 0x7F, address[2], address[3]])
    }

    /// The address that the IPv6 multicast address `address` maps to:
    /// `33-33` and its last 32 bits (RFC 2464 §7, RFC 7042 §2.3.1).
    pub const fn from_ipv6_multicast(address: [u8; 16]) -> MACAddress {
        MACAddress([0x33, 0x33, address[12], address[13], address[14], address[15]])
    }

    /// Reads six pairs of hexadecimal digits separated by colons or, as
    /// IEEE writes them, by hyphens (one separator throughout).
    pub fn from_ascii(text: &[u8]) -> Result<MACAddress, EthernetError> {
        if text.len() != 17 || !(text[2] == b':' || text[2] == b'-') {
            return Err(EthernetError::Syntax);
        }
        let separator = text[2];
        let mut octets = [0u8; 6];
        for (index, octet) in octets.iter_mut().enumerate() {
            let start = index * 3;
            if index > 0 && text[start - 1] != separator {
                return Err(EthernetError::Syntax);
            }
            let digit = |byte: u8| (byte as char).to_digit(16).ok_or(EthernetError::Syntax);
            *octet = (digit(text[start])? << 4 | digit(text[start + 1])?) as u8;
        }
        Ok(MACAddress(octets))
    }
}

impl From<[u8; 6]> for MACAddress {
    fn from(octets: [u8; 6]) -> MACAddress {
        MACAddress(octets)
    }
}

impl From<MACAddress> for [u8; 6] {
    fn from(address: MACAddress) -> [u8; 6] {
        address.0
    }
}

impl FromStr for MACAddress {
    type Err = EthernetError;

    fn from_str(text: &str) -> Result<MACAddress, EthernetError> {
        MACAddress::from_ascii(text.as_bytes())
    }
}

impl fmt::Display for MACAddress {
    /// Lowercase hexadecimal pairs separated by colons.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}
