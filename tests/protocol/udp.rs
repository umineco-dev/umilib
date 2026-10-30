//! Tests of `umilib::protocol::udp` and the endpoints of `umilib::protocol::ip`:
//! the datagrams of the Linux kernel (echoes, no checksum over IPv4, the zero
//! checksum of IPv6 tunnels, fragmented datagrams, the quote of a Port
//! Unreachable), the checksum against an independent computation, and the
//! rules of RFC 768, RFC 2675 §4 and RFC 6936 §4.

use umilib::bytes::Buffer;
use umilib::protocol::ip::v4::{IPv4Header, IPv4Reassembler, IPv4ReassemblyConfig};
use umilib::protocol::ip::v6::{IPv6ExtensionHeaders, IPv6Header, IPv6Reassembler, IPv6ReassemblyConfig};
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPEndpointPattern, IPError, IPProtocol, IPv4Address, IPv6Address};
use umilib::protocol::udp::{UDPConfig, UDPDatagram, UDPError, UDPHeader, UDPRequest, UDPRule};
use umilib::runtime::Instant;
use umilib::service::Rule;

use super::Capture;

/// A packet of the capture, after the Ethernet header (the capture has no
/// VLAN tags): its description, addresses, upper-layer protocol and payload.
struct Packet {
    description: String,
    source: IPAddress,
    destination: IPAddress,
    protocol: IPProtocol,
    payload: Vec<u8>,
    /// Whether the packet was reassembled: the description is then that of the last fragment.
    reassembled: bool,
}

/// The packets of the capture, with fragments reassembled.
fn packets() -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut v4 = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    let mut v6 = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
    for (description, frame) in Capture::frames("protocol/udp/linux.txt") {
        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        let packet = &frame[14..];
        let packet = match ether_type {
            0x0800 => {
                let (header, payload) = IPv4Header::decode(packet).unwrap();
                let reassembled = header.fragment_offset != 0;
                let Some((header, payload)) = v4.receive(&header, payload, Instant::ZERO).unwrap() else { continue };
                Packet {
                    description,
                    source: header.source.into(),
                    destination: header.destination.into(),
                    protocol: header.protocol,
                    payload,
                    reassembled,
                }
            }
            0x86DD => {
                let (header, payload) = IPv6Header::decode(packet).unwrap();
                let reassembled = header.next_header == IPProtocol::IPV6_FRAGMENT;
                let Some((header, payload)) = v6.receive(&header, payload, Instant::ZERO).unwrap() else { continue };
                let Ok((protocol, offset)) = IPv6ExtensionHeaders::upper_layer(header.next_header, &payload) else {
                    continue;
                };
                Packet {
                    description,
                    source: header.source.into(),
                    destination: header.destination.into(),
                    protocol,
                    payload: payload[offset..].to_vec(),
                    reassembled,
                }
            }
            _ => continue,
        };
        packets.push(packet);
    }
    packets
}

fn datagrams() -> Vec<Packet> {
    packets().into_iter().filter(|packet| packet.protocol == IPProtocol::UDP).collect()
}

fn encoded(datagram: &UDPDatagram, source: IPAddress, destination: IPAddress, config: &UDPConfig) -> Vec<u8> {
    let mut buffer = Buffer::new();
    datagram.encode(source, destination, config, &mut buffer).unwrap();
    buffer.into_vec()
}

/// The checksum of RFC 768 computed independently: the one's complement of
/// the one's complement sum of the pseudo-header and the datagram, with the
/// checksum field as zero, all ones for zero.
fn reference_checksum(source: IPAddress, destination: IPAddress, datagram: &[u8]) -> u16 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(source.octets());
    bytes.extend_from_slice(destination.octets());
    match source {
        IPAddress::V4(_) => bytes.extend_from_slice(&[0, 17, (datagram.len() >> 8) as u8, datagram.len() as u8]),
        IPAddress::V6(_) => {
            bytes.extend_from_slice(&(datagram.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 17]);
        }
    }
    bytes.extend_from_slice(&datagram[..6]);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&datagram[8..]);
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum: u32 = bytes.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    match !(sum as u16) {
        0 => 0xFFFF,
        checksum => checksum,
    }
}

fn endpoints(text: &str) -> (u16, u16) {
    // tcpdump: "address.port > address.port:", the ports after the last dot.
    let line = text.lines().find(|line| line.contains(" > ") && !line.contains("ethertype")).unwrap_or_else(|| {
        let line = text.lines().next().unwrap();
        &line[line.rfind(") ").unwrap() + 2..]
    });
    // IPv4 has its flow on a line of its own; IPv6 on the first, after the header.
    let (before, after) = line.split_once(" > ").unwrap();
    let source = before.split_whitespace().last().unwrap();
    let destination = after.split_whitespace().next().unwrap().trim_end_matches(':');
    let port = |endpoint: &str| endpoint.rsplit('.').next().unwrap().parse::<u16>().unwrap();
    (port(source), port(destination))
}

#[test]
fn linux_datagrams() {
    let config = UDPConfig { zero_checksum_receive_ports: vec![7003], ..UDPConfig::default() };
    let datagrams = datagrams();
    // Ten requests, their ten echoes and two datagrams to a closed port.
    assert_eq!(datagrams.len(), 22);
    for packet in &datagrams {
        let datagram = UDPDatagram::decode(&packet.payload, packet.source, packet.destination, &config)
            .unwrap_or_else(|error| panic!("{error}: {}", packet.description));
        if !packet.reassembled {
            assert_eq!((datagram.source_port, datagram.destination_port), endpoints(&packet.description));
        }
        let header = UDPHeader::decode(&packet.payload).unwrap();
        assert_eq!(header.length as usize, packet.payload.len());
        if datagram.checksummed {
            assert_eq!(header.checksum, reference_checksum(packet.source, packet.destination, &packet.payload));
            assert_eq!(encoded(&datagram, packet.source, packet.destination, &config), packet.payload);
        }
    }
    // The echo servers answer with the request's data: what `reply` writes.
    let mut answered = 0;
    for request in &datagrams {
        let datagram = UDPDatagram::decode(&request.payload, request.source, request.destination, &config).unwrap();
        if !(7001..=7003).contains(&datagram.destination_port) {
            continue;
        }
        let Some(answer) = datagrams.iter().find(|answer| {
            answer.source == request.destination
                && UDPHeader::decode(&answer.payload).is_ok_and(|header| {
                    (header.source_port, header.destination_port) == (datagram.destination_port, datagram.source_port)
                })
        }) else {
            continue;
        };
        let reply = datagram.reply(datagram.payload);
        assert_eq!(
            encoded(&reply, answer.source, answer.destination, &config),
            answer.payload,
            "{}",
            request.description
        );
        answered += 1;
    }
    assert_eq!(answered, 10);
    // Datagrams longer than the link, fragmented by Linux, read whole.
    let long: Vec<u8> = (0..12).flat_map(|_| 0..=255u8).collect();
    let whole = datagrams
        .iter()
        .filter(|packet| {
            UDPDatagram::decode(&packet.payload, packet.source, packet.destination, &config).unwrap().payload == long
        })
        .count();
    assert_eq!(whole, 4);
}

#[test]
fn datagrams_without_a_checksum() {
    // RFC 768: a zero checksum over IPv4 means none was computed.
    let datagrams = datagrams();
    let ipv4 = datagrams.iter().find(|packet| packet.description.contains(".40007 >")).unwrap();
    let datagram = UDPDatagram::decode(&ipv4.payload, ipv4.source, ipv4.destination, &UDPConfig::default()).unwrap();
    assert!(!datagram.checksummed);
    assert_eq!(datagram.payload, b"no checksum");
    assert_eq!(encoded(&datagram, ipv4.source, ipv4.destination, &UDPConfig::default()), ipv4.payload);
    // RFC 6936 §4 (5, 6): over IPv6, discarded unless the port allows it.
    let ipv6 = datagrams.iter().find(|packet| packet.description.contains("bad udp cksum 0x0000")).unwrap();
    assert_eq!(
        UDPDatagram::decode(&ipv6.payload, ipv6.source, ipv6.destination, &UDPConfig::default()),
        Err(UDPError::ZeroChecksum)
    );
    let other = UDPConfig { zero_checksum_receive_ports: vec![7002], ..UDPConfig::default() };
    assert_eq!(UDPDatagram::decode(&ipv6.payload, ipv6.source, ipv6.destination, &other), Err(UDPError::ZeroChecksum));
    let receive = UDPConfig { zero_checksum_receive_ports: vec![7003], ..UDPConfig::default() };
    let datagram = UDPDatagram::decode(&ipv6.payload, ipv6.source, ipv6.destination, &receive).unwrap();
    assert!(!datagram.checksummed);
    // RFC 6936 §4 (2, 3): sent so only from a port that allows it.
    let mut buffer = Buffer::new();
    assert_eq!(datagram.encode(ipv6.source, ipv6.destination, &receive, &mut buffer), Err(UDPError::ZeroChecksum));
    let send = UDPConfig { zero_checksum_send_ports: vec![40008], ..UDPConfig::default() };
    assert_eq!(encoded(&datagram, ipv6.source, ipv6.destination, &send), ipv6.payload);
    // RFC 6936 §4 (4, 7): a checksum may always be sent, and is checked when not zero.
    let checked = UDPDatagram { checksummed: true, ..datagram };
    let bytes = encoded(&checked, ipv6.source, ipv6.destination, &UDPConfig::default());
    assert_eq!(UDPDatagram::decode(&bytes, ipv6.source, ipv6.destination, &receive), Ok(checked));
    let mut wrong = bytes.clone();
    wrong[9] ^= 1;
    assert_eq!(UDPDatagram::decode(&wrong, ipv6.source, ipv6.destination, &receive), Err(UDPError::Checksum));
}

#[test]
fn port_unreachable_quotes_the_header() {
    // RFC 792 and RFC 4443 §3.1: the error quotes the datagram, whose ports
    // identify the flow (RFC 6936 §4 (10)).
    let packets = packets();
    let errors: Vec<_> = packets
        .iter()
        .filter(|packet| match packet.protocol {
            IPProtocol::ICMP => packet.payload[0] == 3,
            IPProtocol::ICMPV6 => packet.payload[0] == 1,
            _ => false,
        })
        .collect();
    assert_eq!(errors.len(), 2);
    for error in errors {
        let quote = match error.protocol {
            IPProtocol::ICMP => &error.payload[8 + 20..],
            _ => &error.payload[8 + 40..],
        };
        let header = UDPHeader::decode(quote).unwrap();
        assert_eq!((header.destination_port, header.length), (9, 8 + 6));
        assert!(header.source_port == 40011 || header.source_port == 40012);
    }
}

fn v4(text: &str) -> IPAddress {
    IPAddress::V4(text.parse::<IPv4Address>().unwrap())
}

fn v6(text: &str) -> IPAddress {
    IPAddress::V6(text.parse::<IPv6Address>().unwrap())
}

#[test]
fn lengths() {
    // RFC 768: the length covers the header and the data, at least 8.
    let (source, destination) = (v4("192.0.2.1"), v4("192.0.2.2"));
    let config = UDPConfig::default();
    let datagram = UDPDatagram { source_port: 1, destination_port: 2, checksummed: true, payload: b"data" };
    let bytes = encoded(&datagram, source, destination, &config);
    assert_eq!(&bytes[4..6], &[0, 12]);
    assert_eq!(UDPDatagram::decode(&bytes[..7], source, destination, &config), Err(UDPError::Length));
    for length in [0u16, 7, 13] {
        let mut changed = bytes.clone();
        changed[4..6].copy_from_slice(&length.to_be_bytes());
        changed[6..8].copy_from_slice(&[0, 0]);
        assert_eq!(UDPDatagram::decode(&changed, source, destination, &config), Err(UDPError::Length), "{length}");
    }
    // Bytes after the length (padding of the link or of IP) are not data.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0xEE; 6]);
    assert_eq!(UDPDatagram::decode(&padded, source, destination, &config), Ok(datagram));
    // The source port is optional: zero if not used.
    let anonymous = UDPDatagram { source_port: 0, ..datagram };
    let bytes = encoded(&anonymous, source, destination, &config);
    assert_eq!(UDPDatagram::decode(&bytes, source, destination, &config), Ok(anonymous));
    // The addresses are of one version.
    let mut buffer = Buffer::new();
    assert_eq!(datagram.encode(source, v6("2001:db8::2"), &config, &mut buffer), Err(UDPError::Family));
    assert_eq!(UDPDatagram::decode(&bytes, source, v6("2001:db8::2"), &config), Err(UDPError::Family));
}

#[test]
fn a_checksum_of_zero_is_sent_as_all_ones() {
    // RFC 768: "If the computed checksum is zero, it is transmitted as all ones."
    for (source, destination) in [(v4("192.0.2.1"), v4("192.0.2.2")), (v6("2001:db8::1"), v6("2001:db8::2"))] {
        let config = UDPConfig::default();
        let found = (0..=u16::MAX).find_map(|word| {
            let payload = word.to_be_bytes();
            let datagram =
                UDPDatagram { source_port: 1000, destination_port: 2000, checksummed: true, payload: &payload };
            let header = datagram.header(source, destination, &config).unwrap();
            (header.checksum == 0xFFFF).then_some((header, payload))
        });
        let (header, payload) = found.unwrap();
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        assert_eq!(reference_checksum(source, destination, &bytes), 0xFFFF);
        let datagram = UDPDatagram::decode(&bytes, source, destination, &config).unwrap();
        assert!(datagram.checksummed);
    }
}

#[test]
fn jumbograms() {
    // RFC 2675 §4: over IPv6 a length of more than 65,535 is sent as zero,
    // with the actual length in the pseudo-header, and read from the packet.
    let (source, destination) = (v6("2001:db8::1"), v6("2001:db8::2"));
    let config = UDPConfig::default();
    let payload = vec![0x42; 70_000];
    let datagram = UDPDatagram { source_port: 1, destination_port: 2, checksummed: true, payload: &payload };
    let bytes = encoded(&datagram, source, destination, &config);
    assert_eq!(&bytes[4..6], &[0, 0]);
    assert_eq!(UDPHeader::decode(&bytes).unwrap().checksum, reference_checksum(source, destination, &bytes));
    assert_eq!(UDPDatagram::decode(&bytes, source, destination, &config), Ok(datagram));
    // A zero length without a jumbogram takes the payload length.
    let small = UDPDatagram { payload: b"small", ..datagram };
    let mut bytes = encoded(&small, source, destination, &config);
    bytes[4..6].copy_from_slice(&[0, 0]);
    let mut checksum = umilib::protocol::ip::IPPseudoHeader::new(source, destination, IPProtocol::UDP, bytes.len())
        .unwrap()
        .checksum();
    bytes[6..8].copy_from_slice(&[0, 0]);
    checksum.update(&bytes);
    bytes[6..8].copy_from_slice(&checksum.finish().to_be_bytes());
    assert_eq!(UDPDatagram::decode(&bytes, source, destination, &config), Ok(small));
    // IPv4 has no jumbograms.
    let (source, destination) = (v4("192.0.2.1"), v4("192.0.2.2"));
    let mut buffer = Buffer::new();
    assert_eq!(datagram.encode(source, destination, &config, &mut buffer), Err(UDPError::Length));
}

#[test]
fn headers_read_as_they_are() {
    let header = UDPHeader { source_port: 0x1234, destination_port: 53, length: 9, checksum: 0xBEEF };
    let bytes = header.to_bytes();
    assert_eq!(bytes, [0x12, 0x34, 0, 53, 0, 9, 0xBE, 0xEF]);
    assert_eq!(UDPHeader::decode(&bytes), Ok(header));
    assert_eq!(UDPHeader::decode(&bytes[..7]), Err(UDPError::Length));
}

#[test]
fn endpoints_and_rules() {
    // RFC 3986 §3.2.2: IPv6 addresses in brackets.
    let endpoint: IPEndpoint = "192.0.2.1:53".parse().unwrap();
    assert_eq!(endpoint, IPEndpoint::new(v4("192.0.2.1"), 53));
    assert_eq!(endpoint.to_string(), "192.0.2.1:53");
    let endpoint: IPEndpoint = "[2001:db8::1]:443".parse().unwrap();
    assert_eq!(endpoint.to_string(), "[2001:db8::1]:443");
    for text in ["2001:db8::1:443", "192.0.2.1", "192.0.2.1:65536", "192.0.2.1:+53", "[192.0.2.1]:53", "192.0.2.1:"] {
        assert_eq!(text.parse::<IPEndpoint>(), Err(IPError::Syntax), "{text}");
    }
    // Patterns: prefixes and port ranges; IPv4-mapped addresses match as IPv4.
    let pattern = IPEndpointPattern::ports(5000, 5999).with_prefix(v4("198.51.100.0"), 24);
    assert!(pattern.matches(&"198.51.100.7:5000".parse().unwrap()));
    assert!(pattern.matches(&"[::ffff:198.51.100.7]:5999".parse().unwrap()));
    assert!(!pattern.matches(&"198.51.101.7:5000".parse().unwrap()));
    assert!(!pattern.matches(&"198.51.100.7:6000".parse().unwrap()));
    assert!(!pattern.matches(&"[2001:db8::7]:5000".parse().unwrap()));
    assert!(IPEndpointPattern::ANY.matches(&"[2001:db8::7]:0".parse().unwrap()));
    assert!(
        IPEndpointPattern::port(53).with_address(v6("2001:db8::53")).matches(&"[2001:db8::53]:53".parse().unwrap())
    );
    // A rule routes by the local endpoint and, if given, the remote one.
    let request = UDPRequest {
        local: "[2001:db8::53]:53".parse().unwrap(),
        remote: "[2001:db8:1::9]:40000".parse().unwrap(),
        payload: Vec::new(),
    };
    assert!(UDPRule::new(IPEndpointPattern::port(53)).matches(&request));
    assert!(!UDPRule::new(IPEndpointPattern::port(853)).matches(&request));
    let inside = IPEndpointPattern::ANY.with_prefix(v6("2001:db8:1::"), 48);
    assert!(UDPRule::new(IPEndpointPattern::port(53)).with_remote(inside).matches(&request));
    let outside = IPEndpointPattern::ANY.with_prefix(v6("2001:db8:2::"), 48);
    assert!(!UDPRule::new(IPEndpointPattern::port(53)).with_remote(outside).matches(&request));
}

#[test]
fn ipv4_mapped_prefixes() {
    // RFC 4291 §2.5.5.2: 80 zero bits, 16 one bits, then the 32 bits of the
    // IPv4 address; a prefix of at least 96 bits of them is an IPv4 prefix.
    let mapped = |text: &str| v6(&format!("::ffff:{text}"));
    let net = IPEndpointPattern::ANY.with_prefix(mapped("198.51.100.0"), 120);
    assert_eq!(net, IPEndpointPattern::ANY.with_prefix(v4("198.51.100.0"), 24));
    assert!(net.matches(&"198.51.100.7:1".parse().unwrap()));
    assert!(net.matches(&"[::ffff:198.51.100.7]:1".parse().unwrap()));
    assert!(!net.matches(&"198.51.101.7:1".parse().unwrap()));
    let all = IPEndpointPattern::ANY.with_prefix(mapped("0.0.0.0"), 96);
    assert!(all.matches(&"203.0.113.1:1".parse().unwrap()) && !all.matches(&"[2001:db8::1]:1".parse().unwrap()));
    // A shorter prefix is an IPv6 prefix, which matches no IPv4 address.
    let wide = IPEndpointPattern::ANY.with_prefix(v6("::"), 0);
    assert!(wide.matches(&"[2001:db8::1]:1".parse().unwrap()) && !wide.matches(&"198.51.100.7:1".parse().unwrap()));
    // Equal sets are equal patterns: the bits after the length are cleared,
    // and a length beyond the address's bits is all of them.
    assert_eq!(
        IPEndpointPattern::ANY.with_prefix(v4("198.51.100.7"), 24),
        IPEndpointPattern::ANY.with_prefix(v4("198.51.100.0"), 24)
    );
    assert_eq!(
        IPEndpointPattern::ANY.with_prefix(v4("192.0.2.1"), 200),
        IPEndpointPattern::ANY.with_address(v4("192.0.2.1"))
    );
    assert_eq!(v6("::ffff:192.0.2.1").to_canonical_prefix(120), (v4("192.0.2.0"), 24));
    assert_eq!(v6("::ffff:192.0.2.1").to_canonical_prefix(104), (v4("192.0.0.0"), 8));
    assert_eq!(v6("2001:db8::1").to_canonical_prefix(32), (v6("2001:db8::"), 32));
    // A pattern built by hand is compared as one built with `with_prefix`.
    let raw = IPEndpointPattern { prefix: Some((mapped("198.51.100.0"), 120)), ..IPEndpointPattern::ANY };
    assert!(raw.matches(&"198.51.100.7:1".parse().unwrap()));
}

#[test]
fn sources_that_name_no_single_host() {
    // RFC 1122 §4.1.3.6: a datagram from a broadcast or multicast address is
    // discarded, and none is sent from one (RFC 4291 §2.7 for IPv6).
    let config = UDPConfig::default();
    let datagram = UDPDatagram { source_port: 1, destination_port: 2, checksummed: true, payload: b"x" };
    for (good, bad, destination) in [
        (v4("192.0.2.1"), v4("224.0.0.1"), v4("192.0.2.2")),
        (v4("192.0.2.1"), v4("255.255.255.255"), v4("192.0.2.2")),
        (v6("2001:db8::1"), v6("ff02::1"), v6("2001:db8::2")),
    ] {
        let bytes = encoded(&datagram, good, destination, &config);
        assert!(UDPDatagram::decode(&bytes, good, destination, &config).is_ok());
        let mut buffer = Buffer::new();
        assert_eq!(datagram.encode(bad, destination, &config, &mut buffer), Err(UDPError::Source), "{bad}");
        let mut checksum = umilib::protocol::ip::IPPseudoHeader::new(bad, destination, IPProtocol::UDP, bytes.len())
            .unwrap()
            .checksum();
        let mut forged = bytes.clone();
        forged[6..8].copy_from_slice(&[0, 0]);
        checksum.update(&forged);
        forged[6..8].copy_from_slice(&checksum.finish().to_be_bytes());
        assert_eq!(UDPDatagram::decode(&forged, bad, destination, &config), Err(UDPError::Source), "{bad}");
    }
    // The unspecified address is a source while a host learns its address (RFC 2131).
    let unspecified = encoded(&datagram, v4("0.0.0.0"), v4("255.255.255.255"), &config);
    assert!(UDPDatagram::decode(&unspecified, v4("0.0.0.0"), v4("255.255.255.255"), &config).is_ok());
}
