use crate::bytes::Writer;

use super::super::{IPProtocol, IPv6Address};
use super::IPv6Error;

/// The fixed header of an IPv6 packet (RFC 8200 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IPv6Header {
    /// The Differentiated Services codepoint, the first 6 bits of the
    /// Traffic Class (RFC 2474).
    pub dscp: u8,
    /// The Explicit Congestion Notification bits, the last 2 bits of the
    /// Traffic Class (RFC 3168).
    pub ecn: u8,
    /// The 20-bit flow label (RFC 6437).
    pub flow_label: u32,
    /// The length of everything after this header: extension headers and upper-layer data.
    pub payload_length: u16,
    pub next_header: IPProtocol,
    pub hop_limit: u8,
    pub source: IPv6Address,
    pub destination: IPv6Address,
}

impl IPv6Header {
    pub const VERSION: u8 = 6;
    pub const LENGTH: usize = 40;
    pub const MAXIMUM_PAYLOAD_LENGTH: usize = 65535;
    /// The MTU every link carries (RFC 8200 §5).
    pub const MINIMUM_MTU: usize = 1280;
    /// The hop limit that IANA recommends ("IP Parameters").
    pub const DEFAULT_HOP_LIMIT: u8 = 64;
    pub const MAXIMUM_FLOW_LABEL: u32 = 0xF_FFFF;

    /// The header of a packet of `payload_length` bytes starting with
    /// `next_header`, with the default hop limit and no flow label.
    pub fn new(
        source: IPv6Address,
        destination: IPv6Address,
        next_header: IPProtocol,
        payload_length: usize,
    ) -> Result<IPv6Header, IPv6Error> {
        Ok(IPv6Header {
            dscp: 0,
            ecn: 0,
            flow_label: 0,
            payload_length: u16::try_from(payload_length).map_err(|_| IPv6Error::Length)?,
            next_header,
            hop_limit: IPv6Header::DEFAULT_HOP_LIMIT,
            source,
            destination,
        })
    }

    /// The header at the start of `bytes` and the payload it covers (up to
    /// the payload length; any bytes after it are not payload). The version
    /// must be 6. Jumbograms (RFC 2675) are not read: a payload length of
    /// zero is an empty payload.
    pub fn decode(bytes: &[u8]) -> Result<(IPv6Header, &[u8]), IPv6Error> {
        let (header, payload) = IPv6Header::decode_truncated(bytes)?;
        if payload.len() < header.payload_length as usize {
            return Err(IPv6Error::Length);
        }
        Ok((header, payload))
    }

    /// The header at the start of `bytes` and as much of its payload as
    /// `bytes` holds: the start of a packet, as an ICMPv6 error message
    /// quotes it (RFC 4443 §2.4 (c)).
    pub fn decode_truncated(bytes: &[u8]) -> Result<(IPv6Header, &[u8]), IPv6Error> {
        let fixed = bytes.get(..IPv6Header::LENGTH).ok_or(IPv6Error::Length)?;
        if fixed[0] >> 4 != IPv6Header::VERSION {
            return Err(IPv6Error::Version);
        }
        let first = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let payload_length = u16::from_be_bytes([fixed[4], fixed[5]]);
        let rest = &bytes[IPv6Header::LENGTH..];
        let payload = &rest[..(payload_length as usize).min(rest.len())];
        let traffic_class = (first >> 20) as u8;
        let header = IPv6Header {
            dscp: traffic_class >> 2,
            ecn: traffic_class & 0b11,
            flow_label: first & IPv6Header::MAXIMUM_FLOW_LABEL,
            payload_length,
            next_header: IPProtocol(fixed[6]),
            hop_limit: fixed[7],
            source: IPv6Address(fixed[8..24].try_into().map_err(|_| IPv6Error::Length)?),
            destination: IPv6Address(fixed[24..40].try_into().map_err(|_| IPv6Error::Length)?),
        };
        Ok((header, payload))
    }

    pub fn to_bytes(&self) -> [u8; IPv6Header::LENGTH] {
        let mut bytes = [0u8; IPv6Header::LENGTH];
        let traffic_class = (self.dscp & 0x3F) << 2 | (self.ecn & 0b11);
        let first = (IPv6Header::VERSION as u32) << 28
            | (traffic_class as u32) << 20
            | (self.flow_label & IPv6Header::MAXIMUM_FLOW_LABEL);
        bytes[..4].copy_from_slice(&first.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes[6] = self.next_header.0;
        bytes[7] = self.hop_limit;
        bytes[8..24].copy_from_slice(&self.source.0);
        bytes[24..40].copy_from_slice(&self.destination.0);
        bytes
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv6Error> {
        Ok(out.write(&self.to_bytes())?)
    }
}
