use crate::bytes::Writer;
use crate::protocol::ip::{IPAddress, IPProtocol, IPPseudoHeader};

use super::{TCPError, TCPFlags, TCPOptionSet, TCPOptions, TCPSequence};

/// The fixed 20 bytes of a TCP header (RFC 9293 §3.1), its fields as they
/// are: nothing is checked but its length. [`TCPSegment`] reads and writes
/// a segment with its rules; this type reads the header that an ICMP error
/// quotes, whose segment is cut short.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TCPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: TCPSequence,
    pub acknowledgment: TCPSequence,
    /// The length of the header in 32-bit words, options included.
    pub data_offset: u8,
    /// The four reserved bits (RFC 9293 §3.1), zero when sent.
    pub reserved: u8,
    pub flags: TCPFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TCPHeader {
    pub const LENGTH: usize = 20;

    /// The header at the start of `bytes`; fails with [`TCPError::Length`] if they are fewer than 20.
    pub fn decode(bytes: &[u8]) -> Result<TCPHeader, TCPError> {
        let header = bytes.first_chunk::<{ TCPHeader::LENGTH }>().ok_or(TCPError::Length)?;
        let half = |index: usize| u16::from_be_bytes([header[index], header[index + 1]]);
        let word =
            |index: usize| u32::from_be_bytes([header[index], header[index + 1], header[index + 2], header[index + 3]]);
        Ok(TCPHeader {
            source_port: half(0),
            destination_port: half(2),
            sequence: TCPSequence(word(4)),
            acknowledgment: TCPSequence(word(8)),
            data_offset: header[12] >> 4,
            reserved: header[12] & 0x0F,
            flags: TCPFlags(header[13]),
            window: half(14),
            checksum: half(16),
            urgent_pointer: half(18),
        })
    }

    pub fn to_bytes(&self) -> [u8; TCPHeader::LENGTH] {
        let mut bytes = [0u8; TCPHeader::LENGTH];
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.sequence.0.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.acknowledgment.0.to_be_bytes());
        bytes[12] = (self.data_offset << 4) | (self.reserved & 0x0F);
        bytes[13] = self.flags.0;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        bytes
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TCPError> {
        Ok(out.write(&self.to_bytes())?)
    }
}

/// A TCP segment (RFC 9293 §3.1): its fields, its options as bytes, and its
/// data. The data offset and the checksum are not kept:
/// [`TCPSegment::decode`] checks them and [`TCPSegment::encode`] computes
/// them over the pseudo-header of the addresses that carry the segment
/// (RFC 9293 §3.1, RFC 8200 §8.1). The reserved bits are ignored when read
/// and sent as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TCPSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: TCPSequence,
    pub acknowledgment: TCPSequence,
    pub flags: TCPFlags,
    pub window: u16,
    pub urgent_pointer: u16,
    /// The options, padding included, as received; padded with zeros to a
    /// multiple of 4 bytes when written (RFC 9293 MUST-69).
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TCPSegment<'a> {
    /// The segment of `bytes`, the payload of an IP packet from `source` to
    /// `destination`. Its checksum must be right (RFC 9293 MUST-3), its data
    /// offset at least 5 words and within the bytes, and its options of legal
    /// lengths (MUST-7). Fails with [`TCPError::Length`], [`TCPError::Checksum`],
    /// [`TCPError::Option`] or [`TCPError::Family`].
    pub fn decode(bytes: &'a [u8], source: IPAddress, destination: IPAddress) -> Result<TCPSegment<'a>, TCPError> {
        let header = TCPHeader::decode(bytes)?;
        let offset = header.data_offset as usize * 4;
        if offset < TCPHeader::LENGTH || offset > bytes.len() {
            return Err(TCPError::Length);
        }
        let mut checksum = IPPseudoHeader::new(source, destination, IPProtocol::TCP, bytes.len())?.checksum();
        checksum.update(bytes);
        if checksum.sum16() != 0xFFFF {
            return Err(TCPError::Checksum);
        }
        let options = &bytes[TCPHeader::LENGTH..offset];
        TCPOptions::check(options)?;
        Ok(TCPSegment {
            source_port: header.source_port,
            destination_port: header.destination_port,
            sequence: header.sequence,
            acknowledgment: header.acknowledgment,
            flags: header.flags,
            window: header.window,
            urgent_pointer: header.urgent_pointer,
            options,
            payload: &bytes[offset..],
        })
    }

    /// The options this crate understands ([`TCPOptionSet::decode`]).
    pub fn option_set(&self) -> Result<TCPOptionSet, TCPError> {
        TCPOptionSet::decode(self.options)
    }

    /// The length of the options padded to a multiple of 4, the header and the data.
    pub fn length(&self) -> usize {
        TCPHeader::LENGTH + self.options.len().next_multiple_of(4) + self.payload.len()
    }

    /// The sequence space the segment takes (SEG.LEN, RFC 9293 §3.4): its
    /// data, and one for each of SYN and FIN.
    pub fn sequence_length(&self) -> u32 {
        let controls = self.flags.contains(TCPFlags::SYN) as u32 + self.flags.contains(TCPFlags::FIN) as u32;
        (self.payload.len() as u32).wrapping_add(controls)
    }

    /// The header of the segment from `source` to `destination`, with its
    /// data offset and its checksum. Fails with [`TCPError::Option`] for more
    /// than 40 bytes of options, [`TCPError::Length`] for a segment too long
    /// for the IP version, or [`TCPError::Family`].
    pub fn header(&self, source: IPAddress, destination: IPAddress) -> Result<TCPHeader, TCPError> {
        let padded = self.options.len().next_multiple_of(4);
        if padded > TCPOptionSet::MAXIMUM_LENGTH {
            return Err(TCPError::Option);
        }
        let mut header = TCPHeader {
            source_port: self.source_port,
            destination_port: self.destination_port,
            sequence: self.sequence,
            acknowledgment: self.acknowledgment,
            data_offset: ((TCPHeader::LENGTH + padded) / 4) as u8,
            reserved: 0,
            flags: self.flags,
            window: self.window,
            checksum: 0,
            urgent_pointer: self.urgent_pointer,
        };
        let mut checksum = IPPseudoHeader::new(source, destination, IPProtocol::TCP, self.length())?.checksum();
        checksum.update(&header.to_bytes());
        checksum.update(self.options);
        checksum.update(&[0; 3][..padded - self.options.len()]);
        checksum.update(self.payload);
        header.checksum = checksum.finish();
        Ok(header)
    }

    /// Writes the segment, as [`TCPSegment::header`] makes its header.
    pub fn encode(&self, source: IPAddress, destination: IPAddress, out: &mut impl Writer) -> Result<(), TCPError> {
        let header = self.header(source, destination)?;
        header.encode(out)?;
        out.write(self.options)?;
        out.write(&[0; 3][..self.options.len().next_multiple_of(4) - self.options.len()])?;
        Ok(out.write(self.payload)?)
    }
}
