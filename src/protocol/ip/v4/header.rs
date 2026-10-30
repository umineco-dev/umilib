use crate::bytes::Writer;

use super::super::{IPProtocol, IPv4Address, InternetChecksum};
use super::{IPv4Error, IPv4Options};

/// The header of an IPv4 packet (RFC 791 §3.1). The header checksum is not
/// kept: [`IPv4Header::decode`] checks it and [`IPv4Header::encode`] computes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IPv4Header {
    /// The Differentiated Services codepoint, the first 6 bits of the old
    /// Type of Service (RFC 2474).
    pub dscp: u8,
    /// The Explicit Congestion Notification bits (RFC 3168).
    pub ecn: u8,
    /// The length of the header and the data.
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// The offset of the fragment's data, in units of 8 bytes.
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: IPProtocol,
    pub source: IPv4Address,
    pub destination: IPv4Address,
    pub options: IPv4Options,
}

impl IPv4Header {
    pub const VERSION: u8 = 4;
    pub const MINIMUM_LENGTH: usize = 20;
    pub const MAXIMUM_LENGTH: usize = 60;
    pub const MAXIMUM_TOTAL_LENGTH: usize = 65535;
    /// The MTU every IPv4 module accepts without further fragmentation (RFC 791 §3.2).
    pub const MINIMUM_MTU: usize = 68;
    /// The time to live that IANA recommends ("IP Parameters").
    pub const DEFAULT_TIME_TO_LIVE: u8 = 64;
    /// The unit of fragment offsets.
    pub const FRAGMENT_UNIT: usize = 8;

    /// The header of a datagram of `payload_length` bytes of `protocol`
    /// without options, with the default time to live, which may be fragmented.
    pub fn new(
        source: IPv4Address,
        destination: IPv4Address,
        protocol: IPProtocol,
        payload_length: usize,
    ) -> Result<IPv4Header, IPv4Error> {
        let mut header = IPv4Header {
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification: 0,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            time_to_live: IPv4Header::DEFAULT_TIME_TO_LIVE,
            protocol,
            source,
            destination,
            options: IPv4Options::new(),
        };
        header.set_payload_length(payload_length)?;
        Ok(header)
    }

    /// The length of the header with its padded options.
    pub fn header_length(&self) -> usize {
        IPv4Header::MINIMUM_LENGTH + self.options.padded_length()
    }

    /// The length of the data: the total length less the header.
    pub fn payload_length(&self) -> usize {
        (self.total_length as usize).saturating_sub(self.header_length())
    }

    /// Sets the total length for `length` bytes of data after the header.
    pub fn set_payload_length(&mut self, length: usize) -> Result<(), IPv4Error> {
        let total = self.header_length().checked_add(length).filter(|&total| total <= IPv4Header::MAXIMUM_TOTAL_LENGTH);
        self.total_length = total.ok_or(IPv4Error::Length)? as u16;
        Ok(())
    }

    /// Whether the packet is a fragment of a larger datagram.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }

    /// The header at the start of `bytes` and the data it covers (up to the
    /// total length; any bytes after it, such as the padding of a link
    /// layer, are not data). The version must be 4, the lengths consistent,
    /// the checksum right and the options well formed. The reserved flag,
    /// which senders set to zero, is ignored.
    pub fn decode(bytes: &[u8]) -> Result<(IPv4Header, &[u8]), IPv4Error> {
        // The version and the lengths are checked before the checksum, which covers them.
        if bytes.first().is_some_and(|first| first >> 4 != IPv4Header::VERSION) {
            return Err(IPv4Error::Version);
        }
        let total_length = bytes.get(2..4).map(|field| u16::from_be_bytes([field[0], field[1]]) as usize);
        if total_length.is_some_and(|total_length| total_length > bytes.len()) {
            return Err(IPv4Error::Length);
        }
        IPv4Header::decode_truncated(bytes)
    }

    /// The header at the start of `bytes` and as much of its data as
    /// `bytes` holds: the start of a datagram, as an ICMP error message
    /// quotes it (RFC 792). The header itself must be whole and right, as
    /// for [`IPv4Header::decode`].
    pub fn decode_truncated(bytes: &[u8]) -> Result<(IPv4Header, &[u8]), IPv4Error> {
        let fixed = bytes.get(..IPv4Header::MINIMUM_LENGTH).ok_or(IPv4Error::Length)?;
        if fixed[0] >> 4 != IPv4Header::VERSION {
            return Err(IPv4Error::Version);
        }
        let header_length = (fixed[0] & 0x0F) as usize * 4;
        let total_length = u16::from_be_bytes([fixed[2], fixed[3]]);
        if header_length < IPv4Header::MINIMUM_LENGTH
            || (total_length as usize) < header_length
            || header_length > bytes.len()
        {
            return Err(IPv4Error::Length);
        }
        if !InternetChecksum::verify(&bytes[..header_length]) {
            return Err(IPv4Error::Checksum);
        }
        let flags = u16::from_be_bytes([fixed[6], fixed[7]]);
        let header = IPv4Header {
            dscp: fixed[1] >> 2,
            ecn: fixed[1] & 0b11,
            total_length,
            identification: u16::from_be_bytes([fixed[4], fixed[5]]),
            dont_fragment: flags & 0x4000 != 0,
            more_fragments: flags & 0x2000 != 0,
            fragment_offset: flags & 0x1FFF,
            time_to_live: fixed[8],
            protocol: IPProtocol(fixed[9]),
            source: IPv4Address([fixed[12], fixed[13], fixed[14], fixed[15]]),
            destination: IPv4Address([fixed[16], fixed[17], fixed[18], fixed[19]]),
            options: IPv4Options::decode(&bytes[IPv4Header::MINIMUM_LENGTH..header_length])?,
        };
        Ok((header, &bytes[header_length..(total_length as usize).min(bytes.len())]))
    }

    /// The bytes of the header, with its checksum, in the first
    /// [`IPv4Header::header_length`] bytes of the array.
    pub fn to_bytes(&self) -> [u8; IPv4Header::MAXIMUM_LENGTH] {
        let mut bytes = [0u8; IPv4Header::MAXIMUM_LENGTH];
        let length = self.header_length();
        bytes[0] = IPv4Header::VERSION << 4 | (length / 4) as u8;
        bytes[1] = (self.dscp & 0x3F) << 2 | (self.ecn & 0b11);
        bytes[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags =
            (self.dont_fragment as u16) << 14 | (self.more_fragments as u16) << 13 | (self.fragment_offset & 0x1FFF);
        bytes[6..8].copy_from_slice(&flags.to_be_bytes());
        bytes[8] = self.time_to_live;
        bytes[9] = self.protocol.0;
        bytes[12..16].copy_from_slice(&self.source.0);
        bytes[16..20].copy_from_slice(&self.destination.0);
        let options = self.options.as_bytes();
        bytes[20..20 + options.len()].copy_from_slice(options);
        let checksum = InternetChecksum::checksum(&bytes[..length]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    /// Writes the header with its checksum.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv4Error> {
        Ok(out.write(&self.to_bytes()[..self.header_length()])?)
    }
}
