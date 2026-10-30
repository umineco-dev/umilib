//! Tests of `umilib::protocol::icmp::v4`: the messages of RFC 792, RFC 1191
//! and RFC 4884, against the messages of the Linux kernel, and the rules of
//! error messages of RFC 1122 §3.2.2.

use umilib::bytes::{Buffer, Writer};
use umilib::protocol::ethernet::EtherType;
use umilib::protocol::icmp::v4::{ICMPv4Code, ICMPv4Message, ICMPv4Type};
use umilib::protocol::icmp::{ICMPError, ICMPExtensionObject};
use umilib::protocol::ip::v4::IPv4Header;
use umilib::protocol::ip::{IPProtocol, IPv4Address};

use super::packets;

/// The ICMP messages of the capture: the description, the IP header and the message bytes.
fn messages() -> Vec<(String, IPv4Header, Vec<u8>)> {
    let mut messages = Vec::new();
    for (description, packet) in packets(EtherType::IPV4) {
        let (header, payload) = IPv4Header::decode(&packet).unwrap();
        if header.protocol == IPProtocol::ICMP && !header.is_fragment() {
            messages.push((description, header, payload.to_vec()));
        }
    }
    messages
}

fn encode(message: &ICMPv4Message) -> Vec<u8> {
    let mut buffer = Buffer::new();
    message.encode(&mut buffer).unwrap();
    buffer.into_vec()
}

#[test]
fn decodes_linux_messages() {
    let messages = messages();
    assert!(messages.len() >= 12);
    for (description, _, bytes) in &messages {
        let message = ICMPv4Message::decode(bytes).unwrap_or_else(|error| panic!("{error}: {description}"));
        assert_eq!(encode(&message), *bytes, "{description}");
        let first = description.lines().nth(1).unwrap_or_default();
        let expected = [
            ("echo request", ICMPv4Type::ECHO_REQUEST, 0),
            ("echo reply", ICMPv4Type::ECHO_REPLY, 0),
            ("time exceeded in-transit", ICMPv4Type::TIME_EXCEEDED, ICMPv4Code::TIME_TO_LIVE_EXCEEDED),
            ("reassembly time exceeded", ICMPv4Type::TIME_EXCEEDED, ICMPv4Code::REASSEMBLY_TIME_EXCEEDED),
            ("need to frag", ICMPv4Type::DESTINATION_UNREACHABLE, ICMPv4Code::FRAGMENTATION_NEEDED),
            ("port 9 unreachable", ICMPv4Type::DESTINATION_UNREACHABLE, ICMPv4Code::PORT_UNREACHABLE),
            ("protocol 253 unreachable", ICMPv4Type::DESTINATION_UNREACHABLE, ICMPv4Code::PROTOCOL_UNREACHABLE),
            ("redirect", ICMPv4Type::REDIRECT, ICMPv4Code::REDIRECT_HOST),
        ];
        let (_, kind, code) =
            expected.iter().find(|(text, ..)| first.contains(text)).unwrap_or_else(|| panic!("{description}"));
        assert_eq!((message.kind, message.code), (*kind, *code), "{description}");
        if let Some(rest) = first.split(", id ").nth(1) {
            let mut numbers = rest.split(", seq ");
            let identifier: u16 = numbers.next().unwrap().parse().unwrap();
            let sequence: u16 = numbers.next().unwrap().split(',').next().unwrap().parse().unwrap();
            assert_eq!((message.identifier(), message.sequence()), (Some(identifier), Some(sequence)));
        }
    }
}

#[test]
fn linux_errors_quote_their_datagram() {
    // RFC 792 and RFC 1122 §3.2.2: the header and at least 8 bytes of the
    // datagram, unchanged; RFC 4884: a length attribute and extensions.
    let mut checked = 0;
    for (description, _, bytes) in messages() {
        let message = ICMPv4Message::decode(&bytes).unwrap();
        if !message.kind.is_error() {
            continue;
        }
        let (invoking, data) = message.invoking().unwrap_or_else(|| panic!("{description}"));
        assert!(data.len() >= ICMPv4Message::MINIMUM_QUOTE, "{description}");
        let quoted = description.lines().nth(2).unwrap();
        assert!(quoted.contains(&format!("id {}", invoking.identification)), "{description}");
        assert!(quoted.contains(&format!("ttl {}", invoking.time_to_live)), "{description}");
        let (original, extensions) = message.original().unwrap();
        if description.contains("Multi-Part extension v2") {
            assert!(message.kind.is_extensible());
            assert_eq!(original.len(), message.rest[1] as usize * 4);
            assert!(original.len() >= 128);
            let extensions = extensions.unwrap();
            let objects: Vec<_> = extensions.iter().map(Result::unwrap).collect();
            assert_eq!(objects[0].class, ICMPExtensionObject::INTERFACE_INFORMATION);
            assert!(description.contains(&format!("Class-Type: {}", objects[0].kind)), "{description}");
        } else {
            assert!(extensions.is_none());
        }
        checked += 1;
    }
    assert!(checked >= 6);
}

#[test]
fn field_meanings() {
    let messages = messages();
    let find = |text: &str| {
        let (_, _, bytes) = messages.iter().find(|(description, ..)| description.contains(text)).unwrap();
        bytes.clone()
    };
    // RFC 1191 §4: the MTU of the next hop.
    let bytes = find("need to frag (mtu 576)");
    assert_eq!(ICMPv4Message::decode(&bytes).unwrap().next_hop_mtu(), Some(576));
    // RFC 792: the gateway of a Redirect.
    let bytes = find("redirect 203.0.113.3 to host 192.0.2.3");
    assert_eq!(ICMPv4Message::decode(&bytes).unwrap().gateway(), Some(IPv4Address::new(192, 0, 2, 3)));
    let echo = ICMPv4Message::echo_request(1, 2, &[]);
    assert_eq!((echo.next_hop_mtu(), echo.gateway(), echo.pointer()), (None, None, None));
    let problem = ICMPv4Message { kind: ICMPv4Type::PARAMETER_PROBLEM, code: 0, rest: [12, 0, 0, 0], body: &[] };
    assert_eq!(problem.pointer(), Some(12));
    // RFC 792: the timestamps of a Timestamp Reply.
    let body = [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
    let reply = ICMPv4Message { kind: ICMPv4Type::TIMESTAMP_REPLY, code: 0, rest: [0, 7, 0, 9], body: &body };
    assert_eq!(reply.timestamps(), Some([1, 2, 3]));
    assert_eq!((reply.identifier(), reply.sequence()), (Some(7), Some(9)));
}

#[test]
fn echo_replies_as_linux_sends_them() {
    // RFC 792: the reply returns the identifier, sequence number and data.
    let messages = messages();
    let mut checked = 0;
    for (description, header, bytes) in &messages {
        let request = ICMPv4Message::decode(bytes).unwrap();
        let Some(reply) = request.echo_reply() else { continue };
        let answer = messages.iter().find(|(_, other, answer)| {
            other.source == header.destination
                && ICMPv4Message::decode(answer).is_ok_and(|answer| {
                    answer.kind == ICMPv4Type::ECHO_REPLY
                        && answer.identifier() == request.identifier()
                        && answer.sequence() == request.sequence()
                })
        });
        if let Some((_, _, answer)) = answer {
            assert_eq!(encode(&reply), *answer, "{description}");
            checked += 1;
        }
    }
    assert!(checked >= 3);
    assert_eq!(ICMPv4Message::echo_request(1, 1, &[]).echo_reply().unwrap().echo_reply(), None);
}

#[test]
fn checksum_and_length_are_checked() {
    let mut bytes = encode(&ICMPv4Message::echo_request(0x1234, 1, b"data"));
    assert_eq!(&bytes[..2], &[8, 0]);
    assert!(umilib::protocol::ip::InternetChecksum::verify(&bytes));
    assert!(ICMPv4Message::decode(&bytes).is_ok());
    assert_eq!(ICMPv4Message::decode(&bytes[..7]), Err(ICMPError::Length));
    bytes[9] ^= 1;
    assert_eq!(ICMPv4Message::decode(&bytes), Err(ICMPError::Checksum));
}

#[test]
fn types() {
    // RFC 1122 §3.2.2: the error messages.
    for kind in [3, 4, 5, 11, 12] {
        assert!(ICMPv4Type(kind).is_error(), "{kind}");
    }
    for kind in [0, 8, 9, 10, 13, 14, 42, 43] {
        assert!(!ICMPv4Type(kind).is_error(), "{kind}");
    }
    // RFC 4884 §4: the extensible errors.
    assert!(ICMPv4Type::TIME_EXCEEDED.is_extensible() && !ICMPv4Type::REDIRECT.is_extensible());
    // RFC 6633 and RFC 6918: deprecated types.
    for kind in [4, 6, 15, 16, 17, 18, 30, 39] {
        assert!(ICMPv4Type(kind).is_deprecated(), "{kind}");
    }
    assert!(!ICMPv4Type::ECHO_REQUEST.is_deprecated() && !ICMPv4Type::TIMESTAMP.is_deprecated());
}

fn datagram(source: [u8; 4], destination: [u8; 4], protocol: IPProtocol, payload: &[u8]) -> IPv4Header {
    IPv4Header::new(IPv4Address(source), IPv4Address(destination), protocol, payload.len()).unwrap()
}

#[test]
fn errors_are_not_sent_about_everything() {
    // RFC 1122 §3.2.2: no error about an error, a broadcast or multicast,
    // a non-initial fragment, or a source that is not a single host.
    let udp = [0u8; 8];
    let unicast = datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol::UDP, &udp);
    assert!(ICMPv4Message::may_report(&unicast, &udp, false));
    assert!(!ICMPv4Message::may_report(&unicast, &udp, true));
    let error = [3u8, 3, 0, 0, 0, 0, 0, 0];
    assert!(!ICMPv4Message::may_report(
        &datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol::ICMP, &error),
        &error,
        false
    ));
    let echo = [8u8, 0, 0, 0, 0, 0, 0, 0];
    assert!(ICMPv4Message::may_report(
        &datagram([192, 0, 2, 1], [192, 0, 2, 2], IPProtocol::ICMP, &echo),
        &echo,
        false
    ));
    for destination in [[255, 255, 255, 255], [224, 0, 0, 1], [239, 1, 2, 3]] {
        assert!(!ICMPv4Message::may_report(&datagram([192, 0, 2, 1], destination, IPProtocol::UDP, &udp), &udp, false));
    }
    for source in [[0, 0, 0, 0], [0, 1, 2, 3], [127, 0, 0, 1], [224, 0, 0, 1], [240, 0, 0, 1], [255, 255, 255, 255]] {
        assert!(
            !ICMPv4Message::may_report(&datagram(source, [192, 0, 2, 2], IPProtocol::UDP, &udp), &udp, false),
            "{source:?}"
        );
    }
    let mut fragment = unicast;
    fragment.fragment_offset = 1;
    assert!(!ICMPv4Message::may_report(&fragment, &udp, false));
    fragment.fragment_offset = 0;
    fragment.more_fragments = true;
    assert!(ICMPv4Message::may_report(&fragment, &udp, false));
}

#[test]
fn quotes_fit_576_bytes() {
    // RFC 1812 §4.3.2.3: as much of the datagram as keeps the error within 576 bytes.
    let datagram = vec![7u8; 1500];
    assert_eq!(ICMPv4Message::quote(&datagram, 20).len(), 576 - 20 - 8);
    assert_eq!(ICMPv4Message::quote(&datagram[..100], 20).len(), 100);
    assert_eq!(ICMPv4Message::quote(&datagram, 60).len(), 576 - 60 - 8);
}

#[test]
fn malformed_extensions_keep_the_quote() {
    // RFC 4884 §9: the extensions are checked; the quoted datagram before
    // them still identifies the flow when they are malformed.
    let datagram = datagram([192, 0, 2, 1], [198, 51, 100, 1], IPProtocol::UDP, &[0; 8]);
    let mut body = Buffer::new();
    datagram.encode(&mut body).unwrap();
    body.write(&[0; 8]).unwrap();
    let mut body = body.into_vec();
    body.resize(128, 0);
    body.extend_from_slice(&[0x20, 0, 0xFF, 0xFF, 0, 8, 2, 1, 9, 9, 9, 9]);
    let message = ICMPv4Message {
        kind: ICMPv4Type::TIME_EXCEEDED,
        code: ICMPv4Code::TIME_TO_LIVE_EXCEEDED,
        rest: [0, 32, 0, 0],
        body: &body,
    };
    assert_eq!(message.original(), Err(ICMPError::Checksum));
    let (invoking, _) = message.invoking().unwrap();
    assert_eq!((invoking.source, invoking.destination), (datagram.source, datagram.destination));
    // RFC 1812 §4.3.2.3: whatever the header length, the quote fits 576 bytes.
    assert_eq!(ICMPv4Message::quote_length(1500, usize::MAX), 0);
}
