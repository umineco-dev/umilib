//! Tests of `umilib::protocol::tcp`: segments and options against the Linux
//! kernel's (RFC 9293 §3.1, RFC 7323, RFC 2018), sequence numbers (RFC 9293
//! §3.4).

mod connection;
mod control;
mod receiving;
mod recovery;
mod segment;

use umilib::protocol::ip::v4::IPv4Header;
use umilib::protocol::ip::v6::IPv6Header;
use umilib::protocol::ip::{IPAddress, IPProtocol};

use super::Capture;

/// A TCP segment of the capture: its description, its addresses and its bytes.
pub struct Packet {
    pub description: String,
    pub source: IPAddress,
    pub destination: IPAddress,
    pub segment: Vec<u8>,
}

/// The TCP segments of the capture (no VLAN tags, no fragments).
pub fn packets() -> Vec<Packet> {
    let mut packets = Vec::new();
    for (description, frame) in Capture::frames("protocol/tcp/linux.txt") {
        let packet = &frame[14..];
        let (source, destination, protocol, segment): (IPAddress, IPAddress, IPProtocol, &[u8]) =
            match u16::from_be_bytes([frame[12], frame[13]]) {
                0x0800 => {
                    let (header, payload) = IPv4Header::decode(packet).unwrap();
                    (header.source.into(), header.destination.into(), header.protocol, payload)
                }
                0x86DD => {
                    let (header, payload) = IPv6Header::decode(packet).unwrap();
                    (header.source.into(), header.destination.into(), header.next_header, payload)
                }
                _ => continue,
            };
        if protocol == IPProtocol::TCP {
            packets.push(Packet { description, source, destination, segment: segment.to_vec() });
        }
    }
    packets
}
