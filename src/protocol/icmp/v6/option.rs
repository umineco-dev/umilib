use crate::bytes::Writer;
use crate::protocol::icmp::ICMPError;
use crate::protocol::ip::IPv6Address;

/// The type of a Neighbor Discovery option, from the IANA registry "IPv6
/// Neighbor Discovery Option Formats". Types without a constant here are
/// kept as they are, and ignored by the messages (RFC 4861 §4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NDPOptionKind(pub u8);

impl NDPOptionKind {
    pub const SOURCE_LINK_ADDRESS: NDPOptionKind = NDPOptionKind(1);
    pub const TARGET_LINK_ADDRESS: NDPOptionKind = NDPOptionKind(2);
    pub const PREFIX_INFORMATION: NDPOptionKind = NDPOptionKind(3);
    pub const REDIRECTED_HEADER: NDPOptionKind = NDPOptionKind(4);
    pub const MTU: NDPOptionKind = NDPOptionKind(5);
    /// RFC 3971, used by duplicate address detection (RFC 7527).
    pub const NONCE: NDPOptionKind = NDPOptionKind(14);
    /// RFC 4191.
    pub const ROUTE_INFORMATION: NDPOptionKind = NDPOptionKind(24);
    /// RFC 8106.
    pub const RECURSIVE_DNS_SERVERS: NDPOptionKind = NDPOptionKind(25);
    /// RFC 8106.
    pub const DNS_SEARCH_LIST: NDPOptionKind = NDPOptionKind(31);
}

/// One option of a Neighbor Discovery message (RFC 4861 §4.6): its type and
/// the bytes after its type and length octets, padding included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPOption<'a> {
    pub kind: NDPOptionKind,
    pub data: &'a [u8],
}

impl NDPOption<'_> {
    /// The unit of option lengths.
    pub const UNIT: usize = 8;

    /// Writes an option of `kind` with `data`, padded with zeros to a
    /// multiple of 8 bytes, at most 2,040.
    pub fn encode(kind: NDPOptionKind, data: &[u8], out: &mut impl Writer) -> Result<(), ICMPError> {
        let length = (data.len() + 2).div_ceil(NDPOption::UNIT);
        let units = u8::try_from(length).map_err(|_| ICMPError::Length)?;
        out.write(&[kind.0, units])?;
        out.write(data)?;
        let zeros = [0u8; NDPOption::UNIT];
        Ok(out.write(&zeros[..length * NDPOption::UNIT - 2 - data.len()])?)
    }

    /// The MTU of an MTU option (RFC 4861 §4.6.4).
    pub fn mtu(&self) -> Option<u32> {
        let data = self.data.get(2..6).filter(|_| self.kind == NDPOptionKind::MTU)?;
        Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// The packet of a Redirected Header option (RFC 4861 §4.6.3): as much of
    /// the redirected packet as fits.
    pub fn redirected_packet(&self) -> Option<&[u8]> {
        self.data.get(6..).filter(|_| self.kind == NDPOptionKind::REDIRECTED_HEADER)
    }
}

/// The options of a Neighbor Discovery message, in order; an option of
/// length zero ends it with an error (RFC 4861 §4.6: the message is invalid).
#[derive(Clone, Debug)]
pub struct NDPOptions<'a> {
    pub bytes: &'a [u8],
}

impl<'a> NDPOptions<'a> {
    pub fn new(bytes: &'a [u8]) -> NDPOptions<'a> {
        NDPOptions { bytes }
    }

    /// Whether every option of `bytes` has a length greater than zero and fits.
    pub fn check(bytes: &[u8]) -> Result<(), ICMPError> {
        for option in NDPOptions::new(bytes) {
            option?;
        }
        Ok(())
    }

    /// The data of the first option of `kind`.
    pub fn find(bytes: &'a [u8], kind: NDPOptionKind) -> Option<&'a [u8]> {
        NDPOptions::new(bytes).flatten().find(|option| option.kind == kind).map(|option| option.data)
    }
}

impl<'a> Iterator for NDPOptions<'a> {
    type Item = Result<NDPOption<'a>, ICMPError>;

    fn next(&mut self) -> Option<Result<NDPOption<'a>, ICMPError>> {
        if self.bytes.is_empty() {
            return None;
        }
        let length = self.bytes.get(1).map(|&units| units as usize * NDPOption::UNIT);
        let Some(length) = length.filter(|&length| length > 0 && length <= self.bytes.len()) else {
            self.bytes = &[];
            return Some(Err(ICMPError::Invalid));
        };
        let option = NDPOption { kind: NDPOptionKind(self.bytes[0]), data: &self.bytes[2..length] };
        self.bytes = &self.bytes[length..];
        Some(Ok(option))
    }
}

/// A Prefix Information option (RFC 4861 §4.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NDPPrefixInformation {
    /// 0 to 128.
    pub prefix_length: u8,
    /// The prefix is on-link (the L flag).
    pub on_link: bool,
    /// The prefix may be used for stateless address autoconfiguration (the A flag).
    pub autonomous: bool,
    /// The other six bits of the flags field, as received: those defined
    /// after RFC 4861 (the R flag of RFC 6275, the P flag of RFC 9762) and
    /// the reserved ones.
    pub flags: u8,
    /// Seconds; all ones is infinity.
    pub valid_lifetime: u32,
    /// Seconds; all ones is infinity; at most the valid lifetime.
    pub preferred_lifetime: u32,
    /// The prefix, the bits after its length zero.
    pub prefix: IPv6Address,
}

impl NDPPrefixInformation {
    /// The length of the option's data.
    pub const LENGTH: usize = 30;
    pub const INFINITY: u32 = u32::MAX;

    /// The bits of the flags field that [`NDPPrefixInformation::flags`] holds.
    pub const FLAGS: u8 = 0x3F;

    /// The prefix of the data of a Prefix Information option, which must be
    /// 30 bytes with a prefix length of at most 128, and a preferred lifetime
    /// of at most the valid lifetime (RFC 4861 §4.6.2; RFC 4862 §5.5.3 ignores
    /// the option otherwise). The bits after the prefix length are ignored.
    pub fn decode(data: &[u8]) -> Result<NDPPrefixInformation, ICMPError> {
        let data: &[u8; NDPPrefixInformation::LENGTH] = data.try_into().map_err(|_| ICMPError::Invalid)?;
        let word = |index: usize| u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&data[14..30]);
        let information = NDPPrefixInformation {
            prefix_length: data[0],
            on_link: data[1] & 0x80 != 0,
            autonomous: data[1] & 0x40 != 0,
            flags: data[1] & NDPPrefixInformation::FLAGS,
            valid_lifetime: word(2),
            preferred_lifetime: word(6),
            prefix: IPv6Address(prefix).prefix(data[0].min(128)),
        };
        information.check()?;
        Ok(information)
    }

    /// Checks the prefix length and the lifetimes, as [`NDPPrefixInformation::decode`] does, and
    /// that `flags` holds only its bits.
    pub fn check(&self) -> Result<(), ICMPError> {
        if self.prefix_length > 128
            || self.preferred_lifetime > self.valid_lifetime
            || self.flags & !NDPPrefixInformation::FLAGS != 0
        {
            return Err(ICMPError::Invalid);
        }
        Ok(())
    }

    /// Writes the option; the bits of the prefix after its length are written as zero.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        self.check()?;
        let mut data = [0u8; NDPPrefixInformation::LENGTH];
        data[0] = self.prefix_length;
        data[1] = (self.on_link as u8) << 7 | (self.autonomous as u8) << 6 | self.flags;
        data[2..6].copy_from_slice(&self.valid_lifetime.to_be_bytes());
        data[6..10].copy_from_slice(&self.preferred_lifetime.to_be_bytes());
        data[14..30].copy_from_slice(&self.prefix.prefix(self.prefix_length).0);
        NDPOption::encode(NDPOptionKind::PREFIX_INFORMATION, &data, out)
    }
}

/// The two-bit preferences of default routers and routes (RFC 4191 §2.1).
#[derive(Clone, Copy, Debug)]
pub struct NDPPreference;

impl NDPPreference {
    pub const HIGH: u8 = 0b01;
    pub const MEDIUM: u8 = 0b00;
    pub const LOW: u8 = 0b11;
    /// Never sent: a router preference of it is read as medium (§2.2), and a
    /// Route Information option of it is ignored (§2.3).
    pub const RESERVED: u8 = 0b10;

    /// Whether `preference` is one of the three that are sent.
    pub const fn is_valid(preference: u8) -> bool {
        preference <= 0b11 && preference != NDPPreference::RESERVED
    }
}

/// A Route Information option (RFC 4191 §2.3): a prefix reachable through
/// the router, with its preference and lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NDPRouteInformation {
    pub prefix_length: u8,
    /// The two bits of the preference (RFC 4191 §2.1): 1 high, 0 medium, 3 low.
    pub preference: u8,
    /// Seconds; all ones is infinity.
    pub lifetime: u32,
    /// The prefix, the bits after its length zero.
    pub prefix: IPv6Address,
}

impl NDPRouteInformation {
    /// The prefix of the data of a Route Information option: the length of
    /// the option, in units of 8 bytes, must hold the prefix length, and the
    /// preference must not be the reserved one (RFC 4191 §2.3).
    pub fn decode(data: &[u8]) -> Result<NDPRouteInformation, ICMPError> {
        let fixed = data.get(..6).ok_or(ICMPError::Invalid)?;
        let prefix_length = fixed[0];
        let preference = (fixed[1] >> 3) & 0b11;
        if !(data.len() + 2).is_multiple_of(NDPOption::UNIT) || preference == NDPPreference::RESERVED {
            return Err(ICMPError::Invalid);
        }
        let units = (data.len() + 2) / NDPOption::UNIT;
        let needed = match prefix_length {
            0 => 1,
            1..=64 => 2,
            65..=128 => 3,
            _ => return Err(ICMPError::Invalid),
        };
        if units < needed || units > 3 {
            return Err(ICMPError::Invalid);
        }
        let mut prefix = [0u8; 16];
        let bytes = &data[6..];
        prefix[..bytes.len()].copy_from_slice(bytes);
        Ok(NDPRouteInformation {
            prefix_length,
            preference,
            lifetime: u32::from_be_bytes([fixed[2], fixed[3], fixed[4], fixed[5]]),
            prefix: IPv6Address(prefix).prefix(prefix_length),
        })
    }

    /// Writes the option, of the fewest units that hold the prefix; the
    /// preference must be one of the three that are sent.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        if !NDPPreference::is_valid(self.preference) {
            return Err(ICMPError::Invalid);
        }
        let bytes = match self.prefix_length {
            0 => 0,
            1..=64 => 8,
            65..=128 => 16,
            _ => return Err(ICMPError::Invalid),
        };
        let mut data = [0u8; 22];
        data[0] = self.prefix_length;
        data[1] = self.preference << 3;
        data[2..6].copy_from_slice(&self.lifetime.to_be_bytes());
        data[6..6 + bytes].copy_from_slice(&self.prefix.prefix(self.prefix_length).0[..bytes]);
        NDPOption::encode(NDPOptionKind::ROUTE_INFORMATION, &data[..6 + bytes], out)
    }
}

/// A Recursive DNS Server option (RFC 8106 §5.1): the lifetime and the
/// addresses of the servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NDPRecursiveDNSServers<'a> {
    /// Seconds; all ones is infinity, zero withdraws the servers.
    pub lifetime: u32,
    /// The addresses, 16 bytes each.
    pub addresses: &'a [u8],
}

impl<'a> NDPRecursiveDNSServers<'a> {
    /// The servers of the data of a Recursive DNS Server option, which must
    /// hold at least one address (RFC 8106 §5.1: a length of 3 or more).
    pub fn decode(data: &'a [u8]) -> Result<NDPRecursiveDNSServers<'a>, ICMPError> {
        let fixed = data.get(..6).ok_or(ICMPError::Invalid)?;
        let addresses = &data[6..];
        if addresses.is_empty() || !addresses.len().is_multiple_of(IPv6Address::LENGTH) {
            return Err(ICMPError::Invalid);
        }
        Ok(NDPRecursiveDNSServers { lifetime: u32::from_be_bytes([fixed[2], fixed[3], fixed[4], fixed[5]]), addresses })
    }

    /// The addresses in order.
    pub fn iter(&self) -> impl Iterator<Item = IPv6Address> + 'a {
        self.addresses.as_chunks::<{ IPv6Address::LENGTH }>().0.iter().map(|bytes| IPv6Address(*bytes))
    }

    /// Writes the option.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), ICMPError> {
        if self.addresses.is_empty() || !self.addresses.len().is_multiple_of(IPv6Address::LENGTH) {
            return Err(ICMPError::Invalid);
        }
        let units = u8::try_from(1 + self.addresses.len() / NDPOption::UNIT).map_err(|_| ICMPError::Length)?;
        out.write(&[NDPOptionKind::RECURSIVE_DNS_SERVERS.0, units, 0, 0])?;
        out.write(&self.lifetime.to_be_bytes())?;
        Ok(out.write(self.addresses)?)
    }
}
