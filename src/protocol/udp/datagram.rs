use crate::bytes::Writer;
use crate::protocol::ip::{IPAddress, IPProtocol, IPPseudoHeader};

use super::{UDPConfig, UDPError, UDPHeader};

/// A UDP datagram (RFC 768): its ports, whether it carries a checksum, and
/// its data. The length and the checksum are not kept: [`UDPDatagram::decode`]
/// checks them and [`UDPDatagram::encode`] computes them, over the
/// pseudo-header of the IP addresses that carry the datagram (RFC 768,
/// RFC 8200 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UDPDatagram<'a> {
    /// Zero if not used (RFC 768).
    pub source_port: u16,
    pub destination_port: u16,
    /// Whether the datagram carries a checksum. One without is allowed over
    /// IPv4 (RFC 768), and over IPv6 only on the ports of [`UDPConfig`].
    pub checksummed: bool,
    pub payload: &'a [u8],
}

impl<'a> UDPDatagram<'a> {
    /// The datagram of `bytes`, the payload of an IP packet from `source` to
    /// `destination`. Bytes after the length of the header are not part of
    /// it; a length of 0 over IPv6 is that of a jumbogram, which takes all
    /// the bytes (RFC 2675 §4). A zero checksum over IPv6 needs the
    /// destination port in `config.zero_checksum_receive_ports`. A source
    /// that names no single host is refused (RFC 1122 §4.1.3.6). Fails with
    /// [`UDPError::Length`], [`UDPError::Checksum`], [`UDPError::ZeroChecksum`],
    /// [`UDPError::Family`] or [`UDPError::Source`].
    pub fn decode(
        bytes: &'a [u8],
        source: IPAddress,
        destination: IPAddress,
        config: &UDPConfig,
    ) -> Result<UDPDatagram<'a>, UDPError> {
        let header = UDPHeader::decode(bytes)?;
        let ipv6 = UDPDatagram::is_ipv6(source, destination)?;
        UDPDatagram::check_source(source)?;
        let length = if header.length == 0 && ipv6 { bytes.len() } else { header.length as usize };
        if length < UDPHeader::LENGTH || length > bytes.len() {
            return Err(UDPError::Length);
        }
        let datagram = &bytes[..length];
        let checksummed = header.checksum != 0;
        if checksummed {
            let mut checksum = IPPseudoHeader::new(source, destination, IPProtocol::UDP, length)?.checksum();
            checksum.update(datagram);
            if checksum.sum16() != 0xFFFF {
                return Err(UDPError::Checksum);
            }
        } else if ipv6 && !config.zero_checksum_receive_ports.contains(&header.destination_port) {
            return Err(UDPError::ZeroChecksum);
        }
        Ok(UDPDatagram {
            source_port: header.source_port,
            destination_port: header.destination_port,
            checksummed,
            payload: &datagram[UDPHeader::LENGTH..],
        })
    }

    /// The header of the datagram from `source` to `destination`, with its
    /// length (zero for an IPv6 jumbogram, RFC 2675 §4) and its checksum
    /// (all ones for a sum of zero, RFC 768). Without a checksum over IPv6,
    /// the source port must be in `config.zero_checksum_send_ports`. The
    /// length is checked against the 16 bits of the field over IPv4; that the
    /// datagram fits an IPv4 packet with its header is for the IP layer.
    pub fn header(&self, source: IPAddress, destination: IPAddress, config: &UDPConfig) -> Result<UDPHeader, UDPError> {
        let ipv6 = UDPDatagram::is_ipv6(source, destination)?;
        UDPDatagram::check_source(source)?;
        let length = self.length();
        let field = match u16::try_from(length) {
            Ok(field) => field,
            Err(_) if ipv6 => 0,
            Err(_) => return Err(UDPError::Length),
        };
        let mut header = UDPHeader {
            source_port: self.source_port,
            destination_port: self.destination_port,
            length: field,
            checksum: 0,
        };
        if self.checksummed {
            let mut checksum = IPPseudoHeader::new(source, destination, IPProtocol::UDP, length)?.checksum();
            checksum.update(&header.to_bytes());
            checksum.update(self.payload);
            header.checksum = match checksum.finish() {
                0 => 0xFFFF,
                sum => sum,
            };
        } else if ipv6 && !config.zero_checksum_send_ports.contains(&self.source_port) {
            return Err(UDPError::ZeroChecksum);
        }
        Ok(header)
    }

    /// Writes the datagram, as [`UDPDatagram::header`] makes its header.
    pub fn encode(
        &self,
        source: IPAddress,
        destination: IPAddress,
        config: &UDPConfig,
        out: &mut impl Writer,
    ) -> Result<(), UDPError> {
        self.header(source, destination, config)?.encode(out)?;
        Ok(out.write(self.payload)?)
    }

    /// The length of the header and the data.
    pub fn length(&self) -> usize {
        UDPHeader::LENGTH + self.payload.len()
    }

    /// The reply to this datagram: from its destination port to its source
    /// port, with `payload`.
    pub fn reply<'b>(&self, payload: &'b [u8]) -> UDPDatagram<'b> {
        UDPDatagram {
            source_port: self.destination_port,
            destination_port: self.source_port,
            checksummed: true,
            payload,
        }
    }

    /// Checks that `source` names a single host: not multicast, nor the IPv4
    /// limited broadcast (RFC 1122 §4.1.3.6, RFC 4291 §2.7); fails with
    /// [`UDPError::Source`]. Whether it is a broadcast address of a subnet,
    /// or one of the host's own addresses, is for the caller to know.
    pub fn check_source(source: IPAddress) -> Result<(), UDPError> {
        let broadcast = matches!(source, IPAddress::V4(address) if address.is_broadcast());
        if source.is_multicast() || broadcast { Err(UDPError::Source) } else { Ok(()) }
    }

    /// Whether `source` and `destination` are IPv6 addresses; fails with
    /// [`UDPError::Family`] if they are of different versions.
    pub fn is_ipv6(source: IPAddress, destination: IPAddress) -> Result<bool, UDPError> {
        match (source, destination) {
            (IPAddress::V4(_), IPAddress::V4(_)) => Ok(false),
            (IPAddress::V6(_), IPAddress::V6(_)) => Ok(true),
            _ => Err(UDPError::Family),
        }
    }
}
