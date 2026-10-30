use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};

use super::{QUICConnectionID, QUICError, QUICVarint, QUICVersion};

/// The types of packets of QUIC versions 1 and 2 (RFC 9000 §17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QUICPacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
    /// The short header packet (RFC 9000 §17.3.1).
    OneRTT,
}

impl QUICPacketType {
    /// The packet number space of packets of this type (RFC 9000 §12.3);
    /// `None` for Retry, which has no packet number.
    pub const fn space(self) -> Option<QUICPacketNumberSpace> {
        match self {
            QUICPacketType::Initial => Some(QUICPacketNumberSpace::Initial),
            QUICPacketType::Handshake => Some(QUICPacketNumberSpace::Handshake),
            QUICPacketType::ZeroRTT | QUICPacketType::OneRTT => Some(QUICPacketNumberSpace::ApplicationData),
            QUICPacketType::Retry => None,
        }
    }
}

/// The packet number spaces (RFC 9000 §12.3): each has its own packet
/// numbers, acknowledgments and loss recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QUICPacketNumberSpace {
    Initial = 0,
    Handshake = 1,
    /// 0-RTT and 1-RTT packets.
    ApplicationData = 2,
}

impl QUICPacketNumberSpace {
    pub const ALL: [QUICPacketNumberSpace; 3] =
        [QUICPacketNumberSpace::Initial, QUICPacketNumberSpace::Handshake, QUICPacketNumberSpace::ApplicationData];

    /// The position of this space in [`QUICPacketNumberSpace::ALL`], for tables of spaces.
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// The encoding of packet numbers in headers (RFC 9000 §17.1, Appendix A):
/// the least significant 1 to 4 bytes, from which the receiver recovers the
/// number closest to the one it expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICPacketNumber;

impl QUICPacketNumber {
    /// The largest packet number: 2^62 - 1 (RFC 9000 §12.3).
    pub const MAXIMUM: u64 = (1 << 62) - 1;

    /// The bytes that encode `number` when `largest_acknowledged` is the
    /// largest number the peer acknowledged in its space: enough for more
    /// than twice the unacknowledged range (RFC 9000 §17.1, Appendix A.2),
    /// all of the number before any acknowledgment. `None` if 4 bytes are not
    /// enough: more than 2^31 packets are unacknowledged.
    pub fn length(number: u64, largest_acknowledged: Option<u64>) -> Option<usize> {
        let unacknowledged = match largest_acknowledged {
            Some(largest) => number.checked_sub(largest)?,
            None => number.checked_add(1)?,
        };
        // log2(unacknowledged) + 1 bits, rounded up: the bit length of the
        // count, one more unless it is a power of two.
        let length = u64::BITS - unacknowledged.leading_zeros();
        let bits = if unacknowledged.is_power_of_two() { length } else { length + 1 };
        let bytes = bits.div_ceil(8).max(1) as usize;
        (bytes <= 4).then_some(bytes)
    }

    /// The packet number nearest the next expected one, `largest + 1`,
    /// whose least significant `length` bytes are `truncated` (RFC 9000
    /// Appendix A.3); `largest` is the largest number received in the
    /// space, `None` before any.
    pub fn decode(truncated: u64, length: usize, largest: Option<u64>) -> u64 {
        let expected = largest.map_or(0, |largest| largest + 1);
        let window = 1u64 << (8 * length.clamp(1, 4));
        let half = window / 2;
        let candidate = (expected & !(window - 1)) | (truncated & (window - 1));
        if candidate + half <= expected && candidate < (1 << 62) - window {
            candidate + window
        } else if candidate > expected + half && candidate >= window {
            candidate - window
        } else {
            candidate
        }
    }
}

/// The header of a long header packet that has a packet number: Initial,
/// 0-RTT or Handshake (RFC 9000 §17.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICLongHeader<'a> {
    pub packet_type: QUICPacketType,
    pub version: QUICVersion,
    pub destination: QUICConnectionID,
    pub source: QUICConnectionID,
    /// The token of an Initial packet (RFC 9000 §17.2.2); empty for the other types.
    pub token: &'a [u8],
}

/// The header of a 1-RTT packet (RFC 9000 §17.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICShortHeader {
    pub destination: QUICConnectionID,
    /// The latency spin bit (RFC 9000 §17.4).
    pub spin: bool,
    /// The key phase (RFC 9001 §6), under header protection: known once it is removed.
    pub key_phase: bool,
}

/// The header of a packet with a packet number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QUICHeader<'a> {
    Long(QUICLongHeader<'a>),
    Short(QUICShortHeader),
}

impl QUICHeader<'_> {
    pub fn packet_type(&self) -> QUICPacketType {
        match self {
            QUICHeader::Long(header) => header.packet_type,
            QUICHeader::Short(_) => QUICPacketType::OneRTT,
        }
    }

    pub fn destination(&self) -> QUICConnectionID {
        match self {
            QUICHeader::Long(header) => header.destination,
            QUICHeader::Short(header) => header.destination,
        }
    }

    /// Writes the header, unprotected, with the least significant `length`
    /// bytes of `number` (1 to 4), the Reserved Bits zero, and the QUIC bit
    /// `fixed` (RFC 9287 lets it be zero). A long header's Length counts the
    /// packet number and `payload_length` bytes, the payload with its AEAD
    /// tag. Returns where the packet number starts in `out`. Fails with
    /// [`QUICError::Config`] for a version this crate does not implement, a
    /// type without such a header, or a length out of range.
    pub fn encode(
        &self,
        fixed: bool,
        number: u64,
        length: usize,
        payload_length: usize,
        out: &mut Vec<u8>,
    ) -> Result<usize, QUICError> {
        if !(1..=4).contains(&length) {
            return Err(QUICError::Config);
        }
        let fixed = if fixed { 0x40 } else { 0 };
        let number_bits = (length - 1) as u8;
        match self {
            QUICHeader::Long(header) => {
                let profile = header.version.profile().ok_or(QUICError::Config)?;
                let bits = profile.long_type_bits(header.packet_type).ok_or(QUICError::Config)?;
                if header.packet_type == QUICPacketType::Retry {
                    return Err(QUICError::Config);
                }
                out.push(0x80 | fixed | (bits << 4) | number_bits);
                out.write_be(header.version.0)?;
                QUICLongHeader::write_id(out, header.destination.as_slice())?;
                QUICLongHeader::write_id(out, header.source.as_slice())?;
                if header.packet_type == QUICPacketType::Initial {
                    QUICVarint::write(out, header.token.len() as u64)?;
                    out.extend_from_slice(header.token);
                } else if !header.token.is_empty() {
                    return Err(QUICError::Config);
                }
                QUICVarint::write(out, (length + payload_length) as u64)?;
            }
            QUICHeader::Short(header) => {
                let spin = if header.spin { 0x20 } else { 0 };
                let phase = if header.key_phase { 0x04 } else { 0 };
                out.push(fixed | spin | phase | number_bits);
                out.extend_from_slice(header.destination.as_slice());
            }
        }
        let offset = out.len();
        out.extend_from_slice(&number.to_be_bytes()[8 - length..]);
        Ok(offset)
    }
}

impl QUICLongHeader<'_> {
    /// Writes a connection ID with its length byte.
    pub fn write_id(out: &mut impl Writer, id: &[u8]) -> Result<(), QUICError> {
        out.write_u8(u8::try_from(id.len()).map_err(|_| QUICError::Config)?)?;
        out.write(id)?;
        Ok(())
    }

    /// Reads a connection ID with its length byte, of at most `maximum` bytes.
    pub fn read_id<'a>(reader: &mut Reader<'a>, maximum: usize) -> Result<&'a [u8], QUICError> {
        let length = reader.read_u8().map_err(|_| QUICError::InvalidPacket)? as usize;
        if length > maximum {
            return Err(QUICError::InvalidPacket);
        }
        reader.read_slice(length).map_err(|_| QUICError::InvalidPacket)
    }
}

/// A packet with a packet number, before header protection is removed
/// (RFC 9001 §5.4): its header, and where its fields are in the datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICProtectedPacket<'a> {
    pub header: QUICHeader<'a>,
    /// The QUIC bit (RFC 9000 §17.2, RFC 9287): packets without it are
    /// discarded unless the end advertised `grease_quic_bit`.
    pub fixed: bool,
    /// Where the Packet Number field starts, from the packet's first byte.
    pub number_offset: usize,
    /// The bytes of the datagram that are this packet: a long header's
    /// Length says where it ends; a short header packet takes the rest.
    pub length: usize,
}

/// A Version Negotiation packet (RFC 8999 §6, RFC 9000 §17.2.1). Its
/// connection IDs may be up to 255 bytes: they echo a packet of any version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICVersionNegotiation<'a> {
    pub destination: &'a [u8],
    pub source: &'a [u8],
    /// The Supported Version fields, 4 bytes each.
    pub versions: &'a [u8],
}

impl<'a> QUICVersionNegotiation<'a> {
    /// The versions the server lists.
    pub fn versions(&self) -> impl Iterator<Item = QUICVersion> + 'a {
        self.versions.as_chunks::<4>().0.iter().map(|bytes| QUICVersion(u32::from_be_bytes(*bytes)))
    }

    /// Writes a Version Negotiation packet answering a packet whose
    /// connection IDs were `destination` and `source`: they are swapped
    /// (RFC 9000 §17.2.1). `unused` gives the seven arbitrary bits; the bit
    /// 0x40 is set so that the packet looks like QUIC to demultiplexers
    /// (RFC 9000 §17.2.1, RFC 7983).
    pub fn encode(
        destination: &[u8],
        source: &[u8],
        versions: &[QUICVersion],
        unused: u8,
        out: &mut impl Writer,
    ) -> Result<(), QUICError> {
        out.write_u8(0x80 | 0x40 | (unused & 0x3F))?;
        out.write_be(QUICVersion::NEGOTIATION.0)?;
        QUICLongHeader::write_id(out, source)?;
        QUICLongHeader::write_id(out, destination)?;
        for version in versions {
            out.write_be(version.0)?;
        }
        Ok(())
    }
}

/// A Retry packet (RFC 9000 §17.2.5). It is not protected; its Retry
/// Integrity Tag (RFC 9001 §5.8) authenticates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICRetry<'a> {
    pub version: QUICVersion,
    pub destination: QUICConnectionID,
    pub source: QUICConnectionID,
    pub token: &'a [u8],
    pub tag: [u8; 16],
}

impl QUICRetry<'_> {
    /// Writes the packet without its tag: the bytes the tag covers, after
    /// the original destination connection ID (RFC 9001 §5.8). `unused`
    /// gives the four arbitrary bits.
    pub fn encode_without_tag(&self, unused: u8, out: &mut impl Writer) -> Result<(), QUICError> {
        let profile = self.version.profile().ok_or(QUICError::Config)?;
        let bits = profile.long_type_bits(QUICPacketType::Retry).ok_or(QUICError::Config)?;
        out.write_u8(0x80 | 0x40 | (bits << 4) | (unused & 0x0F))?;
        out.write_be(self.version.0)?;
        QUICLongHeader::write_id(out, self.destination.as_slice())?;
        QUICLongHeader::write_id(out, self.source.as_slice())?;
        out.write(self.token)?;
        Ok(())
    }

    /// Writes the packet with its tag.
    pub fn encode(&self, unused: u8, out: &mut impl Writer) -> Result<(), QUICError> {
        self.encode_without_tag(unused, out)?;
        out.write(&self.tag)?;
        Ok(())
    }
}

/// What every version of QUIC shares (RFC 8999 §5): the header form, a long
/// header's version and connection IDs of up to 255 bytes, a short header's
/// destination connection ID of a length the receiver knows. A server reads
/// this much of a packet of any version, to route it or to answer with
/// Version Negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QUICInvariantHeader<'a> {
    Long { version: QUICVersion, destination: &'a [u8], source: &'a [u8] },
    Short { destination: &'a [u8] },
}

impl<'a> QUICInvariantHeader<'a> {
    /// The invariant header of the first packet of `datagram`; a short
    /// header's connection ID is `short_length` bytes.
    pub fn decode(datagram: &'a [u8], short_length: usize) -> Result<QUICInvariantHeader<'a>, QUICError> {
        let mut reader = Reader::new(datagram);
        let first = reader.read_u8().map_err(|_| QUICError::InvalidPacket)?;
        if first & 0x80 == 0 {
            let destination = reader.read_slice(short_length).map_err(|_| QUICError::InvalidPacket)?;
            return Ok(QUICInvariantHeader::Short { destination });
        }
        let version = QUICVersion(reader.read_be().map_err(|_| QUICError::InvalidPacket)?);
        let destination = QUICLongHeader::read_id(&mut reader, 255)?;
        let source = QUICLongHeader::read_id(&mut reader, 255)?;
        Ok(QUICInvariantHeader::Long { version, destination, source })
    }

    pub fn destination(&self) -> &'a [u8] {
        match self {
            QUICInvariantHeader::Long { destination, .. } | QUICInvariantHeader::Short { destination } => destination,
        }
    }
}

/// A packet read from a datagram, before any protection is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QUICPacket<'a> {
    VersionNegotiation(QUICVersionNegotiation<'a>),
    Retry(QUICRetry<'a>),
    Protected(QUICProtectedPacket<'a>),
    /// A long header packet of a version this crate does not implement
    /// (RFC 8999 §5.1): a server answers with Version Negotiation.
    Unsupported(QUICInvariantHeader<'a>),
}

impl<'a> QUICPacket<'a> {
    /// The first packet of `datagram`; a short header's destination
    /// connection ID is `short_length` bytes, the length of this end's IDs.
    /// Fails with [`QUICError::InvalidPacket`] for what must be discarded:
    /// a packet cut short, a connection ID of versions 1 and 2 above 20
    /// bytes, a Length past the datagram (RFC 9000 §12.2, §17.2).
    pub fn decode(datagram: &'a [u8], short_length: usize) -> Result<QUICPacket<'a>, QUICError> {
        let invalid = |_| QUICError::InvalidPacket;
        let invariant = QUICInvariantHeader::decode(datagram, short_length)?;
        let first = datagram[0];
        let fixed = first & 0x40 != 0;
        let QUICInvariantHeader::Long { version, .. } = invariant else {
            let destination = QUICConnectionID::new(invariant.destination()).ok_or(QUICError::InvalidPacket)?;
            let header = QUICShortHeader { destination, spin: first & 0x20 != 0, key_phase: false };
            return Ok(QUICPacket::Protected(QUICProtectedPacket {
                header: QUICHeader::Short(header),
                fixed,
                number_offset: 1 + short_length,
                length: datagram.len(),
            }));
        };
        if version == QUICVersion::NEGOTIATION {
            let QUICInvariantHeader::Long { destination, source, .. } = invariant else { unreachable!() };
            let versions = &datagram[7 + destination.len() + source.len()..];
            if !versions.len().is_multiple_of(4) {
                return Err(QUICError::InvalidPacket);
            }
            return Ok(QUICPacket::VersionNegotiation(QUICVersionNegotiation { destination, source, versions }));
        }
        let Some(profile) = version.profile() else {
            return Ok(QUICPacket::Unsupported(invariant));
        };
        let mut reader = Reader::new(&datagram[5..]);
        let destination = QUICLongHeader::read_id(&mut reader, QUICConnectionID::MAXIMUM_LENGTH)?;
        let source = QUICLongHeader::read_id(&mut reader, QUICConnectionID::MAXIMUM_LENGTH)?;
        let destination = QUICConnectionID::new(destination).ok_or(QUICError::InvalidPacket)?;
        let source = QUICConnectionID::new(source).ok_or(QUICError::InvalidPacket)?;
        let packet_type = profile.long_type(first);
        if packet_type == QUICPacketType::Retry {
            let rest = reader.read_rest();
            let split = rest.len().checked_sub(16).ok_or(QUICError::InvalidPacket)?;
            let (token, tag) = rest.split_at(split);
            let tag = tag.try_into().map_err(|_| QUICError::InvalidPacket)?;
            return Ok(QUICPacket::Retry(QUICRetry { version, destination, source, token, tag }));
        }
        let token = if packet_type == QUICPacketType::Initial {
            let length = QUICVarint::read(&mut reader).map_err(invalid)?;
            let length = usize::try_from(length).map_err(|_| QUICError::InvalidPacket)?;
            reader.read_slice(length).map_err(invalid)?
        } else {
            &[]
        };
        let length = QUICVarint::read(&mut reader).map_err(invalid)?;
        let number_offset = 5 + reader.position();
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| number_offset.checked_add(length))
            .filter(|end| *end <= datagram.len())
            .ok_or(QUICError::InvalidPacket)?;
        let header = QUICLongHeader { packet_type, version, destination, source, token };
        Ok(QUICPacket::Protected(QUICProtectedPacket {
            header: QUICHeader::Long(header),
            fixed,
            number_offset,
            length: end,
        }))
    }

    /// The bytes of the datagram this packet takes: Version Negotiation,
    /// Retry and packets of unknown versions take the whole datagram.
    pub fn length(&self, datagram: &[u8]) -> usize {
        match self {
            QUICPacket::Protected(packet) => packet.length,
            _ => datagram.len(),
        }
    }
}
