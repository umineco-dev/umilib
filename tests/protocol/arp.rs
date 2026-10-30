//! Tests of `umilib::protocol::arp`: the packet (RFC 826), the reception
//! algorithm and the cache (RFC 826, RFC 1122 §2.3.2), and probes (RFC
//! 5227), against packets of the Linux kernel.

use std::collections::VecDeque;
use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::arp::{
    ARPCache, ARPConfig, ARPError, ARPEvent, ARPHardwareType, ARPOperation, ARPPacket, ARPResolution,
};
use umilib::protocol::ethernet::{EtherType, EthernetHeader, MACAddress};
use umilib::protocol::ip::IPv4Address;
use umilib::runtime::Instant;

use super::Capture;

/// The ARP packets of the Linux capture: the description and the bytes.
fn packets() -> Vec<(String, Vec<u8>)> {
    let mut packets = Vec::new();
    for (description, frame) in Capture::frames("protocol/ethernet/linux.txt") {
        let (header, data) = EthernetHeader::decode(&frame).unwrap();
        if header.ether_type == EtherType::ARP {
            packets.push((description, data.to_vec()));
        }
    }
    packets
}

fn encode(packet: &ARPPacket) -> Vec<u8> {
    let mut buffer = Buffer::new();
    packet.encode(&mut buffer).unwrap();
    buffer.into_vec()
}

fn ip(text: &str) -> IPv4Address {
    text.parse().unwrap()
}

fn mac(text: &str) -> MACAddress {
    text.parse().unwrap()
}

#[test]
fn decodes_linux_packets() {
    let packets = packets();
    assert!(packets.len() >= 6);
    for (description, bytes) in &packets {
        let packet: ARPPacket = ARPPacket::decode(bytes).unwrap();
        assert_eq!(packet.hardware_type, ARPHardwareType::ETHERNET);
        assert_eq!(packet.protocol_type, EtherType::IPV4);
        // tcpdump: "Request who-has TARGET tell SENDER" or "Reply SENDER is-at HARDWARE".
        if let Some(rest) = description.split("Request who-has ").nth(1) {
            let words: Vec<&str> = rest.split([' ', ',']).collect();
            assert_eq!(packet.operation, ARPOperation::REQUEST);
            assert_eq!(packet.target_protocol, ip(words[0]));
            assert_eq!(packet.sender_protocol, ip(words[2]));
        } else {
            let rest = description.split("Reply ").nth(1).unwrap();
            let words: Vec<&str> = rest.split([' ', ',']).collect();
            assert_eq!(packet.operation, ARPOperation::REPLY);
            assert_eq!(packet.sender_protocol, ip(words[0]));
            assert_eq!(packet.sender_hardware, mac(words[2]));
        }
        assert_eq!(encode(&packet), bytes[..28], "{description}");
    }
}

#[test]
fn answers_linux_requests_as_linux_does() {
    // RFC 826: the reply swaps the fields and puts the local addresses as the sender.
    let packets: Vec<(ARPPacket, Vec<u8>)> =
        packets().into_iter().map(|(_, bytes)| (ARPPacket::decode(&bytes).unwrap(), bytes)).collect();
    let mut answered = 0;
    for (index, (request, _)) in
        packets.iter().enumerate().filter(|(_, (packet, _))| packet.operation == ARPOperation::REQUEST)
    {
        let answer = |(reply, _): &&(ARPPacket, Vec<u8>)| {
            reply.operation == ARPOperation::REPLY
                && reply.sender_protocol == request.target_protocol
                && reply.target_protocol == request.sender_protocol
        };
        let (reply, reply_bytes) = packets[index..].iter().find(answer).unwrap();
        let (request, reply) = (*request, *reply);
        let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
        let reception = cache.receive(&request, reply.sender_hardware, &[reply.sender_protocol], Instant::ZERO);
        assert_eq!(reception.reply, Some(reply));
        assert_eq!(encode(&reception.reply.unwrap()), reply_bytes[..28]);
        answered += 1;
        // The requester is learned (the packet is for a local address).
        assert_eq!(cache.lookup(&request.sender_protocol, Instant::ZERO), Some(request.sender_hardware));
        assert!(!reception.conflict);
    }
    assert!(answered >= 5);
}

#[test]
fn packet_layout() {
    // RFC 826: hardware type, protocol type, lengths, operation, then the addresses.
    let packet = ARPPacket::ethernet_request(mac("02:00:00:00:00:01"), ip("192.0.2.1"), ip("192.0.2.9"));
    let bytes = encode(&packet);
    assert_eq!(bytes, [0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 9]);
    assert_eq!(ARPPacket::<MACAddress, IPv4Address>::length(), 28);
    // Padding after the packet is ignored; a short packet or other lengths are refused.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0; 18]);
    assert_eq!(ARPPacket::decode(&padded), Ok(packet));
    assert_eq!(ARPPacket::<MACAddress, IPv4Address>::decode(&bytes[..27]), Err(ARPError::Length));
    let mut other = bytes.clone();
    other[5] = 16;
    assert_eq!(ARPPacket::<MACAddress, IPv4Address>::decode(&other), Err(ARPError::Length));
}

#[test]
fn other_address_lengths() {
    // RFC 826 lets both addresses be of any length.
    let packet: ARPPacket<[u8; 8], [u8; 16]> = ARPPacket {
        hardware_type: ARPHardwareType(27),
        protocol_type: EtherType::IPV6,
        operation: ARPOperation::REPLY,
        sender_hardware: [1; 8],
        sender_protocol: [2; 16],
        target_hardware: [3; 8],
        target_protocol: [4; 16],
    };
    let mut buffer = Buffer::new();
    packet.encode(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 8 + 2 * (8 + 16));
    assert_eq!(&buffer.as_slice()[4..6], &[8, 16]);
    assert_eq!(ARPPacket::decode(buffer.as_slice()), Ok(packet));
}

#[test]
fn probes_and_announcements() {
    // RFC 5227 §2.1.1 and §2.3.
    let probe = ARPPacket::ethernet_request(mac("02:00:00:00:00:01"), IPv4Address::UNSPECIFIED, ip("192.0.2.7"));
    assert!(probe.is_probe() && !probe.is_announcement());
    let announcement = ARPPacket::ethernet_request(mac("02:00:00:00:00:01"), ip("192.0.2.7"), ip("192.0.2.7"));
    assert!(announcement.is_announcement() && !announcement.is_probe());
    // A probe is answered, but its sender is not learned (RFC 5227 §2.5).
    let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
    let reception = cache.receive(&probe, mac("02:00:00:00:00:07"), &[ip("192.0.2.7")], Instant::ZERO);
    let reply = reception.reply.unwrap();
    assert_eq!(reply.target_protocol, IPv4Address::UNSPECIFIED);
    assert_eq!(reply.target_hardware, mac("02:00:00:00:00:01"));
    assert!(cache.entries.is_empty());
}

#[test]
fn reception_merges_as_rfc826_says() {
    let local = [ip("192.0.2.1")];
    let hardware = mac("02:00:00:00:00:01");
    let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
    // Not for us and not known: not learned, not answered.
    let other = ARPPacket::ethernet_request(mac("02:00:00:00:00:05"), ip("192.0.2.5"), ip("192.0.2.6"));
    let reception = cache.receive(&other, hardware, &local, Instant::ZERO);
    assert_eq!(reception.reply, None);
    assert!(cache.entries.is_empty());
    // For us: learned and answered.
    let request = ARPPacket::ethernet_request(mac("02:00:00:00:00:05"), ip("192.0.2.5"), ip("192.0.2.1"));
    assert!(cache.receive(&request, hardware, &local, Instant::ZERO).reply.is_some());
    assert_eq!(cache.lookup(&ip("192.0.2.5"), Instant::ZERO), Some(mac("02:00:00:00:00:05")));
    // Known: updated even if not for us, and a reply is not answered.
    let moved = ARPPacket::ethernet_request(mac("02:00:00:00:00:55"), ip("192.0.2.5"), ip("192.0.2.6"));
    assert_eq!(cache.receive(&moved, hardware, &local, Instant::ZERO).reply, None);
    assert_eq!(cache.lookup(&ip("192.0.2.5"), Instant::ZERO), Some(mac("02:00:00:00:00:55")));
    let reply = ARPPacket { operation: ARPOperation::REPLY, ..request };
    assert_eq!(cache.receive(&reply, hardware, &local, Instant::ZERO).reply, None);
    // Another hardware type or protocol is ignored.
    let foreign = ARPPacket { hardware_type: ARPHardwareType::IEEE_802, ..request };
    assert_eq!(cache.receive(&foreign, hardware, &local, Instant::ZERO).reply, None);
    let foreign = ARPPacket { protocol_type: EtherType::IPV6, ..request };
    assert_eq!(cache.receive(&foreign, hardware, &local, Instant::ZERO).reply, None);
    // A packet that claims a local address from another interface is a conflict (RFC 5227 §2.4).
    let claim = ARPPacket::ethernet_request(mac("02:00:00:00:00:66"), ip("192.0.2.1"), ip("192.0.2.1"));
    let reception = cache.receive(&claim, hardware, &local, Instant::ZERO);
    assert!(reception.conflict);
    assert_eq!(cache.lookup(&ip("192.0.2.1"), Instant::ZERO), None);
}

#[test]
fn resolution_requests_at_most_once_per_interval() {
    // RFC 1122 §2.3.2.1: at most one request per second per destination.
    let config = ARPConfig::default();
    assert_eq!(config.retransmission_interval, Duration::from_secs(1));
    let mut cache: ARPCache = ARPCache::new(config);
    let target = ip("192.0.2.9");
    let start = Instant::from_nanos(1);
    assert_eq!(cache.resolve(target, Some(vec![1]), start), Ok(ARPResolution::Request));
    assert_eq!(cache.resolve(target, Some(vec![2]), start), Ok(ARPResolution::Pending));
    assert_eq!(cache.poll(start.saturating_add(Duration::from_millis(999))), None);
    assert_eq!(cache.poll_timeout(), Some(start.saturating_add(Duration::from_secs(1))));
    assert_eq!(cache.poll(start.saturating_add(Duration::from_secs(1))), Some(ARPEvent::Request(target)));
    assert_eq!(cache.poll(start.saturating_add(Duration::from_secs(1))), None);
    assert_eq!(cache.poll(start.saturating_add(Duration::from_secs(2))), Some(ARPEvent::Request(target)));
    // After the last request, the address is unreachable; the latest packet was kept (RFC 1122 §2.3.2.2).
    let event = cache.poll(start.saturating_add(Duration::from_secs(3)));
    assert_eq!(event, Some(ARPEvent::Unreachable(target, VecDeque::from([vec![2]]))));
    assert!(cache.entries.is_empty());
}

#[test]
fn resolution_completes_with_the_reply() {
    let mut cache: ARPCache = ARPCache::new(ARPConfig { maximum_queued: 2, ..ARPConfig::default() });
    let target = ip("192.0.2.9");
    for packet in 1..=3u8 {
        cache.resolve(target, Some(vec![packet]), Instant::ZERO).unwrap();
    }
    let reply = ARPPacket {
        operation: ARPOperation::REPLY,
        ..ARPPacket::ethernet_request(mac("02:00:00:00:00:09"), target, ip("192.0.2.1"))
    };
    let reception = cache.receive(&reply, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO);
    assert_eq!(reception.resolved, [vec![2], vec![3]]);
    assert_eq!(cache.resolve(target, None, Instant::ZERO), Ok(ARPResolution::Resolved(mac("02:00:00:00:00:09"))));
}

#[test]
fn entries_expire_and_static_entries_stay() {
    let config = ARPConfig::default();
    let mut cache: ARPCache = ARPCache::new(config);
    let request = ARPPacket::ethernet_request(mac("02:00:00:00:00:05"), ip("192.0.2.5"), ip("192.0.2.1"));
    cache.receive(&request, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO);
    cache.insert_static(ip("192.0.2.200"), mac("02:00:00:00:00:c8"));
    let later = Instant::ZERO.saturating_add(config.timeout);
    assert_eq!(cache.poll_timeout(), Some(later));
    assert_eq!(cache.lookup(&ip("192.0.2.5"), later), None);
    assert_eq!(cache.resolve(ip("192.0.2.5"), None, later), Ok(ARPResolution::Request));
    assert_eq!(cache.poll(later.saturating_add(Duration::from_secs(3600))), Some(ARPEvent::Request(ip("192.0.2.5"))));
    assert_eq!(cache.lookup(&ip("192.0.2.200"), Instant::MAX), Some(mac("02:00:00:00:00:c8")));
    // A static entry is not replaced by what packets say.
    let claim = ARPPacket::ethernet_request(mac("02:00:00:00:00:99"), ip("192.0.2.200"), ip("192.0.2.1"));
    cache.receive(&claim, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO);
    assert_eq!(cache.lookup(&ip("192.0.2.200"), Instant::ZERO), Some(mac("02:00:00:00:00:c8")));
    assert!(cache.remove(&ip("192.0.2.200")).is_some());
}

#[test]
fn cache_limits() {
    let mut cache: ARPCache = ARPCache::new(ARPConfig { maximum_entries: 2, ..ARPConfig::default() });
    // Resolving a new address in a full table forgets the entry due soonest.
    assert_eq!(cache.resolve(ip("192.0.2.1"), None, Instant::from_nanos(2)), Ok(ARPResolution::Request));
    assert_eq!(cache.resolve(ip("192.0.2.2"), None, Instant::from_nanos(1)), Ok(ARPResolution::Request));
    assert_eq!(cache.resolve(ip("192.0.2.3"), None, Instant::from_nanos(3)), Ok(ARPResolution::Request));
    assert_eq!(cache.entries.keys().copied().collect::<Vec<_>>(), [ip("192.0.2.1"), ip("192.0.2.3")]);
    // What packets say never pushes an entry out: a request is answered, its sender not learned.
    let request = ARPPacket::ethernet_request(mac("02:00:00:00:00:05"), ip("192.0.2.5"), ip("192.0.2.9"));
    let reception = cache.receive(&request, mac("02:00:00:00:00:09"), &[ip("192.0.2.9")], Instant::ZERO);
    assert!(reception.reply.is_some());
    assert_eq!(cache.entries.len(), 2);
    assert_eq!(cache.lookup(&ip("192.0.2.5"), Instant::ZERO), None);
    // A table already beyond its limit is brought back within it.
    let mut cache: ARPCache = ARPCache::new(ARPConfig { maximum_entries: 5, ..ARPConfig::default() });
    for last in 1..=5u8 {
        cache.resolve(IPv4Address::new(192, 0, 2, last), None, Instant::from_nanos(last as u64)).unwrap();
    }
    cache.config.maximum_entries = 2;
    assert_eq!(cache.resolve(ip("192.0.2.9"), None, Instant::ZERO), Ok(ARPResolution::Request));
    assert_eq!(cache.entries.len(), 2);
    let mut empty: ARPCache = ARPCache::new(ARPConfig { maximum_entries: 0, ..ARPConfig::default() });
    assert_eq!(empty.resolve(ip("192.0.2.9"), None, Instant::ZERO), Err(ARPError::Limit));
    // Static entries are never forgotten, and count against the limit.
    let mut cache: ARPCache = ARPCache::new(ARPConfig { maximum_entries: 1, ..ARPConfig::default() });
    cache.insert_static(ip("192.0.2.200"), mac("02:00:00:00:00:c8"));
    assert_eq!(cache.resolve(ip("192.0.2.2"), None, Instant::ZERO), Err(ARPError::Limit));
}

#[test]
fn conflicts_are_neither_learned_nor_answered() {
    // RFC 5227 §2.5: a request is answered unless it conflicts (§2.4), that
    // is, claims a local address from another hardware address.
    let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
    let claim = ARPPacket::ethernet_request(mac("02:00:00:00:00:66"), ip("192.0.2.1"), ip("192.0.2.1"));
    let reception = cache.receive(&claim, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO);
    assert!(reception.conflict);
    assert_eq!(reception.reply, None);
    let asking = ARPPacket::ethernet_request(mac("02:00:00:00:00:66"), ip("192.0.2.1"), ip("192.0.2.7"));
    let reception =
        cache.receive(&asking, mac("02:00:00:00:00:01"), &[ip("192.0.2.1"), ip("192.0.2.7")], Instant::ZERO);
    assert!(reception.conflict && reception.reply.is_none());
    // Our own packet coming back is no conflict.
    let own = ARPPacket::ethernet_request(mac("02:00:00:00:00:01"), ip("192.0.2.1"), ip("192.0.2.1"));
    assert!(!cache.receive(&own, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO).conflict);
}

#[test]
fn group_hardware_addresses_are_not_learned() {
    // No host has a multicast or broadcast hardware address as its own (RFC 1812 §3.3.2).
    let mut cache: ARPCache = ARPCache::new(ARPConfig::default());
    for sender in [MACAddress::BROADCAST, mac("01:00:5e:00:00:01"), mac("33:33:00:00:00:01")] {
        let request = ARPPacket::ethernet_request(sender, ip("192.0.2.5"), ip("192.0.2.1"));
        cache.receive(&request, mac("02:00:00:00:00:01"), &[ip("192.0.2.1")], Instant::ZERO);
        assert_eq!(cache.lookup(&ip("192.0.2.5"), Instant::ZERO), None, "{sender}");
    }
}
