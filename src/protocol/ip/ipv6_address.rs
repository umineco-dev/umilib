use core::fmt;
use core::str::FromStr;

use super::{IPError, IPv4Address};

/// An IPv6 address (RFC 4291), in network byte order. Its text form is that
/// of RFC 5952.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(C)]
pub struct IPv6Address(pub [u8; 16]);

impl IPv6Address {
    pub const LENGTH: usize = 16;
    pub const BITS: u8 = 128;
    /// `::` (RFC 4291 §2.5.2).
    pub const UNSPECIFIED: IPv6Address = IPv6Address([0; 16]);
    /// `::1` (RFC 4291 §2.5.3).
    pub const LOOPBACK: IPv6Address = IPv6Address::from_words([0, 0, 0, 0, 0, 0, 0, 1]);
    /// `ff02::1`, every node on the link (RFC 4291 §2.7.1).
    pub const ALL_NODES: IPv6Address = IPv6Address::from_words([0xFF02, 0, 0, 0, 0, 0, 0, 1]);
    /// `ff02::2`, every router on the link (RFC 4291 §2.7.1).
    pub const ALL_ROUTERS: IPv6Address = IPv6Address::from_words([0xFF02, 0, 0, 0, 0, 0, 0, 2]);

    /// The address of the eight 16-bit words `words`, first word first.
    pub const fn from_words(words: [u16; 8]) -> IPv6Address {
        let mut octets = [0u8; 16];
        let mut index = 0;
        while index < 8 {
            let [high, low] = words[index].to_be_bytes();
            octets[2 * index] = high;
            octets[2 * index + 1] = low;
            index += 1;
        }
        IPv6Address(octets)
    }

    pub const fn to_words(&self) -> [u16; 8] {
        let mut words = [0u16; 8];
        let mut index = 0;
        while index < 8 {
            words[index] = u16::from_be_bytes([self.0[2 * index], self.0[2 * index + 1]]);
            index += 1;
        }
        words
    }

    /// The address whose bits, most significant first, are those of `bits`.
    pub const fn from_bits(bits: u128) -> IPv6Address {
        IPv6Address(bits.to_be_bytes())
    }

    pub const fn to_bits(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// The address with every bit after the first `length` cleared (all of
    /// them are kept from a length of 128 on).
    pub const fn prefix(&self, length: u8) -> IPv6Address {
        IPv6Address::from_bits(self.to_bits() & IPv6Address::mask(length))
    }

    /// Whether the first `length` bits are those of `prefix`.
    pub const fn has_prefix(&self, prefix: &IPv6Address, length: u8) -> bool {
        (self.to_bits() ^ prefix.to_bits()) & IPv6Address::mask(length) == 0
    }

    /// The mask of a prefix of `length` bits (all of them from 128 on).
    pub const fn mask(length: u8) -> u128 {
        if length >= IPv6Address::BITS { u128::MAX } else { !(u128::MAX >> length) }
    }

    /// The address of the 64-bit prefix `prefix` and the interface identifier
    /// `interface_identifier` (RFC 4291 §2.5.1).
    pub const fn from_interface_identifier(prefix: [u8; 8], interface_identifier: [u8; 8]) -> IPv6Address {
        let mut octets = [0u8; 16];
        let mut index = 0;
        while index < 8 {
            octets[index] = prefix[index];
            octets[8 + index] = interface_identifier[index];
            index += 1;
        }
        IPv6Address(octets)
    }

    /// The link-local address `fe80::/64` of `interface_identifier` (RFC 4291 §2.5.6).
    pub const fn link_local(interface_identifier: [u8; 8]) -> IPv6Address {
        IPv6Address::from_interface_identifier([0xFE, 0x80, 0, 0, 0, 0, 0, 0], interface_identifier)
    }

    /// The last 64 bits, the interface identifier of a unicast address (RFC 4291 §2.5.1).
    pub const fn interface_identifier(&self) -> [u8; 8] {
        let mut identifier = [0u8; 8];
        let mut index = 0;
        while index < 8 {
            identifier[index] = self.0[8 + index];
            index += 1;
        }
        identifier
    }

    /// The solicited-node multicast address `ff02::1:ffXX:XXXX` of this
    /// address, of its last 24 bits (RFC 4291 §2.7.1).
    pub const fn solicited_node(&self) -> IPv6Address {
        let [.., a, b, c] = self.0;
        IPv6Address([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, a, b, c])
    }

    pub const fn is_unspecified(&self) -> bool {
        self.to_bits() == 0
    }

    pub const fn is_loopback(&self) -> bool {
        self.to_bits() == 1
    }

    /// `ff00::/8` (RFC 4291 §2.7).
    pub const fn is_multicast(&self) -> bool {
        self.0[0] == 0xFF
    }

    /// The scope of a multicast address (RFC 4291 §2.7, RFC 7346): 1 for
    /// the interface, 2 for the link, 5 for the site, 14 for the world...
    pub const fn multicast_scope(&self) -> Option<u8> {
        if self.is_multicast() { Some(self.0[1] & 0x0F) } else { None }
    }

    /// The link-local unicast addresses `fe80::/10` (RFC 4291 §2.5.6).
    pub const fn is_link_local(&self) -> bool {
        self.0[0] == 0xFE && self.0[1] & 0xC0 == 0x80
    }

    /// The unique local addresses `fc00::/7` (RFC 4193).
    pub const fn is_unique_local(&self) -> bool {
        self.0[0] & 0xFE == 0xFC
    }

    /// `2001:db8::/32` (RFC 3849) and `3fff::/20` (RFC 9637).
    pub const fn is_documentation(&self) -> bool {
        matches!(self.0, [0x20, 0x01, 0x0D, 0xB8, ..])
            || (self.0[0] == 0x3F && self.0[1] == 0xFF && self.0[2] & 0xF0 == 0)
    }

    /// The IPv4 address of an IPv4-mapped address `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2).
    pub const fn to_ipv4_mapped(&self) -> Option<IPv4Address> {
        match self.0 {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d] => Some(IPv4Address([a, b, c, d])),
            _ => None,
        }
    }

    /// Reads an address in any of the forms of RFC 4291 §2.2: eight groups
    /// of one to four hexadecimal digits separated by colons, one `::` for
    /// one or more groups of zeros, and the last 32 bits in dotted decimal.
    pub fn from_ascii(text: &[u8]) -> Result<IPv6Address, IPError> {
        let gap = text.windows(2).position(|pair| pair == b"::");
        let (head, tail) = match gap {
            Some(index) => (&text[..index], Some(&text[index + 2..])),
            None => (text, None),
        };
        let mut words = [0u16; 8];
        let head_count = IPv6Address::groups(head, tail.is_none(), &mut words)?;
        let Some(tail) = tail else {
            return if head_count == 8 { Ok(IPv6Address::from_words(words)) } else { Err(IPError::Syntax) };
        };
        let mut tail_words = [0u16; 8];
        let tail_count = IPv6Address::groups(tail, true, &mut tail_words)?;
        if head_count + tail_count > 7 {
            return Err(IPError::Syntax);
        }
        words[8 - tail_count..].copy_from_slice(&tail_words[..tail_count]);
        Ok(IPv6Address::from_words(words))
    }

    /// Reads the groups of `text` (empty for none) into the start of `words`
    /// and returns their count; the last group may be a dotted decimal IPv4
    /// address, two words, if `last` (the groups end the address).
    pub fn groups(text: &[u8], last: bool, words: &mut [u16; 8]) -> Result<usize, IPError> {
        let mut count = 0;
        if text.is_empty() {
            return Ok(0);
        }
        let mut groups = text.split(|&byte| byte == b':').peekable();
        while let Some(group) = groups.next() {
            if group.contains(&b'.') {
                if !last || groups.peek().is_some() || count > 6 {
                    return Err(IPError::Syntax);
                }
                let [a, b, c, d] = IPv4Address::from_ascii(group)?.0;
                words[count] = u16::from_be_bytes([a, b]);
                words[count + 1] = u16::from_be_bytes([c, d]);
                count += 2;
                continue;
            }
            if count == 8 || group.is_empty() || group.len() > 4 {
                return Err(IPError::Syntax);
            }
            let mut word = 0u16;
            for &digit in group {
                word = word << 4 | (digit as char).to_digit(16).ok_or(IPError::Syntax)? as u16;
            }
            words[count] = word;
            count += 1;
        }
        Ok(count)
    }
}

impl From<[u8; 16]> for IPv6Address {
    fn from(octets: [u8; 16]) -> IPv6Address {
        IPv6Address(octets)
    }
}

impl From<IPv6Address> for [u8; 16] {
    fn from(address: IPv6Address) -> [u8; 16] {
        address.0
    }
}

impl FromStr for IPv6Address {
    type Err = IPError;

    fn from_str(text: &str) -> Result<IPv6Address, IPError> {
        IPv6Address::from_ascii(text.as_bytes())
    }
}

impl fmt::Display for IPv6Address {
    /// The text form of RFC 5952 §4: lowercase, without leading zeros, the
    /// first longest run of two or more zero groups written `::`; and of §5:
    /// an IPv4-mapped address, the only form of RFC 4291 with a well-known
    /// prefix for embedded IPv4, as `::ffff:a.b.c.d`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = self.to_ipv4_mapped() {
            return write!(formatter, "::ffff:{address}");
        }
        let words = self.to_words();
        let (mut start, mut length) = (8, 0);
        let mut index = 0;
        while index < 8 {
            let run = words[index..].iter().take_while(|&&word| word == 0).count();
            if run > length {
                (start, length) = (index, run);
            }
            index += run.max(1);
        }
        if length < 2 {
            start = 8;
        }
        for (index, word) in words.iter().enumerate() {
            if index == start {
                formatter.write_str("::")?;
            } else if index > start && index < start + length {
                continue;
            } else {
                if index > 0 && index != start + length {
                    formatter.write_str(":")?;
                }
                write!(formatter, "{word:x}")?;
            }
        }
        Ok(())
    }
}
