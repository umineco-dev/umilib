//! Tests of `umilib::protocol::icmp::v6`: the messages of RFC 4443 and the
//! Neighbor Discovery of RFC 4861 (with RFC 4191 and RFC 8106), against the
//! messages of the Linux kernel and radvd, the rules of error messages of
//! RFC 4443 §2.4, and the Neighbor Cache of RFC 4861 §7.3 and Appendix C.

use std::collections::VecDeque;
use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::ethernet::EtherType;
use umilib::protocol::icmp::ICMPError;
use umilib::protocol::icmp::v6::{
    ICMPv6Code, ICMPv6Message, ICMPv6Type, NDPMessage, NDPNeighborAdvertisement, NDPNeighborSolicitation, NDPOption,
    NDPOptionKind, NDPOptions, NDPPreference, NDPPrefixInformation, NDPRecursiveDNSServers, NDPRedirect,
    NDPRouteInformation, NDPRouterAdvertisement, NDPRouterSolicitation, NeighborCache, NeighborConfig, NeighborEvent,
    NeighborReception, NeighborResolution, NeighborState,
};
use umilib::protocol::ip::v6::{IPv6ExtensionHeaders, IPv6Header};
use umilib::protocol::ip::{IPProtocol, IPv6Address};
use umilib::runtime::Instant;

use super::packets;

/// The ICMPv6 messages of the capture, after their extension headers: the
/// description, the IPv6 header and the message bytes.
fn messages() -> Vec<(String, IPv6Header, Vec<u8>)> {
    let mut messages = Vec::new();
    for (description, packet) in packets(EtherType::IPV6) {
        let (header, payload) = IPv6Header::decode(&packet).unwrap();
        // A fragment holds a part of a message, whose checksum cannot be checked alone.
        let fragmented = IPv6ExtensionHeaders::new(header.next_header, payload)
            .flatten()
            .any(|extension| extension.kind == IPProtocol::IPV6_FRAGMENT);
        if fragmented {
            continue;
        }
        if let Ok((IPProtocol::ICMPV6, offset)) = IPv6ExtensionHeaders::upper_layer(header.next_header, payload) {
            messages.push((description, header, payload[offset..].to_vec()));
        }
    }
    messages
}

fn address(text: &str) -> IPv6Address {
    text.parse().unwrap()
}

fn encoded(write: impl FnOnce(&mut Buffer) -> Result<(), ICMPError>) -> Vec<u8> {
    let mut buffer = Buffer::new();
    write(&mut buffer).unwrap();
    buffer.into_vec()
}

#[test]
fn decodes_linux_messages() {
    let messages = messages();
    assert!(messages.len() >= 30);
    for (description, header, bytes) in &messages {
        let message = ICMPv6Message::decode(bytes, header.source, header.destination)
            .unwrap_or_else(|error| panic!("{error}: {description}"));
        assert_eq!(encoded(|out| message.encode(header.source, header.destination, out)), *bytes, "{description}");
        // The checksum covers the addresses (RFC 8200 §8.1).
        assert_eq!(ICMPv6Message::decode(bytes, header.source, IPv6Address::LOOPBACK), Err(ICMPError::Checksum));
    }
}

fn find(text: &str) -> (IPv6Header, Vec<u8>) {
    let (_, header, bytes) =
        messages().into_iter().find(|(description, ..)| description.contains(text)).unwrap_or_else(|| panic!("{text}"));
    (header, bytes)
}

#[test]
fn error_messages_of_linux() {
    let cases = [
        ("time exceeded in-transit for", ICMPv6Type::TIME_EXCEEDED, ICMPv6Code::HOP_LIMIT_EXCEEDED),
        ("time exceeded in-transit (reassembly)", ICMPv6Type::TIME_EXCEEDED, ICMPv6Code::REASSEMBLY_TIME_EXCEEDED),
        ("packet too big, mtu 1280", ICMPv6Type::PACKET_TOO_BIG, 0),
        ("unreachable port", ICMPv6Type::DESTINATION_UNREACHABLE, ICMPv6Code::PORT_UNREACHABLE),
        (
            "parameter problem, next header - octet 6",
            ICMPv6Type::PARAMETER_PROBLEM,
            ICMPv6Code::UNRECOGNIZED_NEXT_HEADER,
        ),
        ("parameter problem, option - octet 42", ICMPv6Type::PARAMETER_PROBLEM, ICMPv6Code::UNRECOGNIZED_OPTION),
    ];
    for (text, kind, code) in cases {
        let (header, bytes) = find(text);
        let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
        assert_eq!((message.kind, message.code), (kind, code), "{text}");
        assert!(message.kind.is_error());
        // RFC 4443 §2.4 (c): as much of the invoking packet as fits 1,280 bytes.
        assert!(IPv6Header::LENGTH + bytes.len() <= ICMPv6Message::MAXIMUM_ERROR_LENGTH, "{text}");
        // The invoking packet came from the host the error goes to.
        let (invoking, _) = message.invoking().unwrap();
        assert_eq!(invoking.source, header.destination, "{text}");
    }
    let (header, bytes) = find("packet too big, mtu 1280");
    assert_eq!(ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap().mtu(), Some(1280));
    let (header, bytes) = find("next header - octet 6");
    assert_eq!(ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap().pointer(), Some(6));
    let (header, bytes) = find("option - octet 42");
    assert_eq!(ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap().pointer(), Some(42));
}

#[test]
fn echo_replies_as_linux_sends_them() {
    // RFC 4443 §4.2: the identifier, sequence number and data of the request.
    let messages = messages();
    let mut checked = 0;
    for (_, header, bytes) in &messages {
        let request = ICMPv6Message::decode(bytes, header.source, header.destination).unwrap();
        let Some(reply) = request.echo_reply() else { continue };
        for (_, other, answer) in &messages {
            if other.source != header.destination || other.destination != header.source {
                continue;
            }
            let Ok(answer_message) = ICMPv6Message::decode(answer, other.source, other.destination) else { continue };
            if answer_message.kind == ICMPv6Type::ECHO_REPLY
                && answer_message.identifier() == request.identifier()
                && answer_message.sequence() == request.sequence()
            {
                assert_eq!(encoded(|out| reply.encode(other.source, other.destination, out)), *answer);
                checked += 1;
            }
        }
    }
    assert!(checked >= 2);
}

#[test]
fn router_advertisement_of_radvd() {
    let (header, bytes) = find("router advertisement");
    let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
    let advertisement = NDPRouterAdvertisement::decode(&message, &header).unwrap();
    // "hop limit 64, Flags [none], pref medium, router lifetime 12s, reachable time 30000ms, retrans timer 1000ms"
    assert_eq!(advertisement.current_hop_limit, 64);
    assert!(!advertisement.managed_flag && !advertisement.other_flag);
    assert_eq!(advertisement.preference, 0);
    assert_eq!(advertisement.router_lifetime, 12);
    assert_eq!((advertisement.reachable_time, advertisement.retransmission_timer), (30000, 1000));
    let options: Vec<NDPOption> = NDPOptions::new(advertisement.options).map(Result::unwrap).collect();
    let data = |kind| options.iter().find(|option| option.kind == kind).unwrap().data;
    let prefix = NDPPrefixInformation::decode(data(NDPOptionKind::PREFIX_INFORMATION)).unwrap();
    assert_eq!((prefix.prefix, prefix.prefix_length), (address("2001:db8:1::"), 64));
    assert!(prefix.on_link && prefix.autonomous);
    assert_eq!((prefix.valid_lifetime, prefix.preferred_lifetime), (86400, 14400));
    let route = NDPRouteInformation::decode(data(NDPOptionKind::ROUTE_INFORMATION)).unwrap();
    assert_eq!(
        (route.prefix, route.prefix_length, route.preference, route.lifetime),
        (address("2001:db8:2::"), 64, 0, 12)
    );
    let servers = NDPRecursiveDNSServers::decode(data(NDPOptionKind::RECURSIVE_DNS_SERVERS)).unwrap();
    assert_eq!(servers.lifetime, 12);
    assert_eq!(servers.iter().collect::<Vec<_>>(), [address("2001:db8:1::53")]);
    let mtu = options.iter().find(|option| option.kind == NDPOptionKind::MTU).unwrap();
    assert_eq!(mtu.mtu(), Some(1500));
    assert_eq!(advertisement.source_link_address(), Some(&[2u8, 0, 0, 0, 1, 1][..]));
    // Writing each part back gives radvd's bytes.
    assert_eq!(encoded(|out| advertisement.encode(header.source, header.destination, out)), bytes);
    assert_eq!(encoded(|out| prefix.encode(out))[2..], *data(NDPOptionKind::PREFIX_INFORMATION));
    assert_eq!(encoded(|out| route.encode(out))[2..], *data(NDPOptionKind::ROUTE_INFORMATION));
    assert_eq!(encoded(|out| servers.encode(out))[2..], *data(NDPOptionKind::RECURSIVE_DNS_SERVERS));
}

#[test]
fn neighbor_discovery_messages_of_linux() {
    let mut counts = [0usize; 4];
    for (description, header, bytes) in messages() {
        let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
        let rewrite = match message.kind {
            ICMPv6Type::ROUTER_SOLICITATION => {
                counts[0] += 1;
                let solicitation = NDPRouterSolicitation::decode(&message, &header).unwrap();
                encoded(|out| solicitation.encode(header.source, header.destination, out))
            }
            ICMPv6Type::NEIGHBOR_SOLICITATION => {
                counts[1] += 1;
                let solicitation = NDPNeighborSolicitation::decode(&message, &header).unwrap();
                let target = description.split("who has ").nth(1).unwrap().split_whitespace().next().unwrap();
                assert_eq!(solicitation.target, address(target), "{description}");
                if header.source.is_unspecified() {
                    // Duplicate address detection: to the solicited-node address, with a nonce.
                    assert!(NDPNeighborSolicitation::is_duplicate_address_detection(&header));
                    assert_eq!(header.destination, solicitation.target.solicited_node());
                    assert!(NDPOptions::find(solicitation.options, NDPOptionKind::NONCE).is_some(), "{description}");
                    assert_eq!(solicitation.source_link_address(), None);
                }
                encoded(|out| solicitation.encode(header.source, header.destination, out))
            }
            ICMPv6Type::NEIGHBOR_ADVERTISEMENT => {
                counts[2] += 1;
                let advertisement = NDPNeighborAdvertisement::decode(&message, &header).unwrap();
                let target = description.split("tgt is ").nth(1).unwrap().split([',', ' ']).next().unwrap();
                assert_eq!(advertisement.target, address(target), "{description}");
                assert_eq!(advertisement.solicited_flag, description.contains("solicited"), "{description}");
                assert_eq!(advertisement.override_flag, description.contains("override"), "{description}");
                assert_eq!(advertisement.router_flag, description.contains("router"), "{description}");
                encoded(|out| advertisement.encode(header.source, header.destination, out))
            }
            ICMPv6Type::ROUTER_ADVERTISEMENT => {
                counts[3] += 1;
                let advertisement = NDPRouterAdvertisement::decode(&message, &header).unwrap();
                encoded(|out| advertisement.encode(header.source, header.destination, out))
            }
            _ => continue,
        };
        assert_eq!(rewrite, bytes, "{description}");
    }
    assert!(counts.iter().all(|&count| count >= 2), "{counts:?}");
}

fn ndp_header(source: &str, destination: &str, length: usize) -> IPv6Header {
    let mut header = IPv6Header::new(address(source), address(destination), IPProtocol::ICMPV6, length).unwrap();
    header.hop_limit = NDPMessage::HOP_LIMIT;
    header
}

fn solicitation_bytes(target: &str, options: &[u8], source: &str, destination: &str) -> Vec<u8> {
    let solicitation = NDPNeighborSolicitation { target: address(target), options };
    encoded(|out| solicitation.encode(address(source), address(destination), out))
}

#[test]
fn neighbor_discovery_validity_checks() {
    // RFC 4861 §7.1.1.
    let slla = encoded(|out| NDPOption::encode(NDPOptionKind::SOURCE_LINK_ADDRESS, &[2, 0, 0, 0, 0, 1], out));
    let decode = |bytes: &[u8], header: &IPv6Header| {
        let message = ICMPv6Message::decode(bytes, header.source, header.destination).unwrap();
        NDPNeighborSolicitation::decode(&message, header).map(|solicitation| solicitation.target)
    };
    let bytes = solicitation_bytes("fe80::2", &slla, "fe80::1", "ff02::1:ff00:2");
    let header = ndp_header("fe80::1", "ff02::1:ff00:2", bytes.len());
    assert_eq!(decode(&bytes, &header), Ok(address("fe80::2")));
    // A hop limit other than 255: forwarded.
    assert_eq!(decode(&bytes, &IPv6Header { hop_limit: 254, ..header }), Err(ICMPError::Invalid));
    // A code other than 0.
    let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
    assert_eq!(
        NDPNeighborSolicitation::decode(&ICMPv6Message { code: 1, ..message }, &header),
        Err(ICMPError::Invalid)
    );
    // Shorter than 24 bytes.
    assert_eq!(
        NDPNeighborSolicitation::decode(&ICMPv6Message { body: &message.body[..15], ..message }, &header),
        Err(ICMPError::Invalid)
    );
    // A multicast target.
    let bytes = solicitation_bytes("ff02::1", &[], "fe80::1", "ff02::1:ff00:1");
    assert_eq!(decode(&bytes, &ndp_header("fe80::1", "ff02::1:ff00:1", bytes.len())), Err(ICMPError::Invalid));
    // An option of length zero.
    let bytes = solicitation_bytes("fe80::2", &[1, 0, 0, 0, 0, 0, 0, 0], "fe80::1", "ff02::1:ff00:2");
    assert_eq!(decode(&bytes, &ndp_header("fe80::1", "ff02::1:ff00:2", bytes.len())), Err(ICMPError::Invalid));
    // From the unspecified address: to a solicited-node address, without a source link-layer address.
    let bytes = solicitation_bytes("fe80::2", &[], "::", "ff02::1:ff00:2");
    assert!(decode(&bytes, &ndp_header("::", "ff02::1:ff00:2", bytes.len())).is_ok());
    let bytes = solicitation_bytes("fe80::2", &[], "::", "fe80::2");
    assert_eq!(decode(&bytes, &ndp_header("::", "fe80::2", bytes.len())), Err(ICMPError::Invalid));
    let bytes = solicitation_bytes("fe80::2", &slla, "::", "ff02::1:ff00:2");
    assert_eq!(decode(&bytes, &ndp_header("::", "ff02::1:ff00:2", bytes.len())), Err(ICMPError::Invalid));
    // Another type.
    let echo = ICMPv6Message::echo_request(1, 1, &[0; 16]);
    assert_eq!(NDPNeighborSolicitation::decode(&echo, &header), Err(ICMPError::Invalid));
}

#[test]
fn advertisement_and_redirect_validity_checks() {
    // RFC 4861 §7.1.2: a solicited advertisement is not multicast.
    let advertisement = NDPNeighborAdvertisement {
        router_flag: false,
        solicited_flag: true,
        override_flag: true,
        target: address("fe80::2"),
        options: &[],
    };
    let check = |advertisement: &NDPNeighborAdvertisement, destination: &str| {
        let bytes = encoded(|out| advertisement.encode(address("fe80::2"), address(destination), out));
        let header = ndp_header("fe80::2", destination, bytes.len());
        let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
        NDPNeighborAdvertisement::decode(&message, &header).map(|_| ())
    };
    assert_eq!(check(&advertisement, "fe80::1"), Ok(()));
    assert_eq!(check(&advertisement, "ff02::1"), Err(ICMPError::Invalid));
    assert_eq!(check(&NDPNeighborAdvertisement { solicited_flag: false, ..advertisement }, "ff02::1"), Ok(()));
    assert_eq!(
        check(&NDPNeighborAdvertisement { target: address("ff02::5"), ..advertisement }, "fe80::1"),
        Err(ICMPError::Invalid)
    );
    // RFC 4861 §6.1.2 and §8.1: Router Advertisements and Redirects come from link-local addresses.
    let router = NDPRouterAdvertisement {
        current_hop_limit: 64,
        managed_flag: true,
        other_flag: false,
        preference: 1,
        flags: 0,
        router_lifetime: 1800,
        reachable_time: 0,
        retransmission_timer: 0,
        options: &[],
    };
    for (source, valid) in [("fe80::1", true), ("2001:db8::1", false)] {
        let bytes = encoded(|out| router.encode(address(source), address("ff02::1"), out));
        let header = ndp_header(source, "ff02::1", bytes.len());
        let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
        assert_eq!(NDPRouterAdvertisement::decode(&message, &header).is_ok(), valid, "{source}");
        if valid {
            assert_eq!(NDPRouterAdvertisement::decode(&message, &header), Ok(router));
            assert_eq!(message.rest[1], 0x80 | 0x08);
        }
    }
    let redirect = |target: &str, destination: &str| {
        let redirect = NDPRedirect { target: address(target), destination: address(destination), options: &[] };
        let bytes = encoded(|out| redirect.encode(address("fe80::1"), address("2001:db8::9"), out));
        let header = ndp_header("fe80::1", "2001:db8::9", bytes.len());
        let message = ICMPv6Message::decode(&bytes, header.source, header.destination).unwrap();
        NDPRedirect::decode(&message, &header).map(|redirect| (redirect.target, redirect.destination))
    };
    // To a router (link-local) or to the destination itself, which is not multicast.
    assert!(redirect("fe80::3", "2001:db8:3::3").is_ok());
    assert!(redirect("2001:db8:3::3", "2001:db8:3::3").is_ok());
    assert_eq!(redirect("2001:db8::7", "2001:db8:3::3"), Err(ICMPError::Invalid));
    assert_eq!(redirect("fe80::3", "ff0e::1"), Err(ICMPError::Invalid));
}

#[test]
fn options() {
    // RFC 4861 §4.6: lengths in units of 8 bytes, the type and length included.
    let option = encoded(|out| NDPOption::encode(NDPOptionKind::SOURCE_LINK_ADDRESS, &[1, 2, 3, 4, 5, 6], out));
    assert_eq!(option, [1, 1, 1, 2, 3, 4, 5, 6]);
    let long = encoded(|out| NDPOption::encode(NDPOptionKind(200), &[9; 7], out));
    assert_eq!(long.len(), 16);
    assert_eq!(long[1], 2);
    assert!(long[9..].iter().all(|&byte| byte == 0));
    let mut both = option.clone();
    both.extend_from_slice(&long);
    let parsed: Vec<_> = NDPOptions::new(&both).map(Result::unwrap).collect();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[1].data.len(), 14);
    assert_eq!(NDPOptions::check(&[1, 2, 0, 0, 0, 0, 0, 0]), Err(ICMPError::Invalid));
    // RFC 4191 §2.3: a Route Information option holds as many bytes of the prefix as its length needs.
    for (length, units) in [(0u8, 1usize), (48, 2), (64, 2), (96, 3)] {
        let route = NDPRouteInformation {
            prefix_length: length,
            preference: 3,
            lifetime: 600,
            prefix: address("2001:db8:aaaa:bbbb:cccc::"),
        };
        let bytes = encoded(|out| route.encode(out));
        assert_eq!(bytes.len(), units * 8, "{length}");
        let decoded = NDPRouteInformation::decode(&bytes[2..]).unwrap();
        assert_eq!(decoded.prefix, route.prefix.prefix(length));
        assert_eq!(decoded.preference, 3);
    }
    assert_eq!(NDPRouteInformation::decode(&[96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(ICMPError::Invalid));
    assert_eq!(NDPRouteInformation::decode(&[129, 0, 0, 0, 0, 0]), Err(ICMPError::Invalid));
    // RFC 8106 §5.1: at least one address.
    assert_eq!(NDPRecursiveDNSServers::decode(&[0, 0, 0, 0, 0, 1]), Err(ICMPError::Invalid));
    assert_eq!(NDPPrefixInformation::decode(&[0; 29]), Err(ICMPError::Invalid));
}

#[test]
fn errors_are_not_sent_about_everything() {
    // RFC 4443 §2.4 (e).
    let header = |source: &str, destination: &str, next_header| {
        IPv6Header::new(address(source), address(destination), next_header, 8).unwrap()
    };
    let error = |kind, code, rest: [u8; 4]| ICMPv6Message { kind, code, rest, body: &[] };
    let udp = [0u8; 8];
    let unreachable = error(ICMPv6Type::DESTINATION_UNREACHABLE, ICMPv6Code::PORT_UNREACHABLE, [0; 4]);
    let report = ICMPv6Message::may_report;
    assert!(report(&header("2001:db8::1", "2001:db8::2", IPProtocol::UDP), &udp, false, &unreachable));
    // (e.1) and (e.2): not about an error or a Redirect; an informational message is fine.
    for kind in [1u8, 2, 3, 4, 100, 137] {
        let message = [kind, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            !report(&header("2001:db8::1", "2001:db8::2", IPProtocol::ICMPV6), &message, false, &unreachable),
            "{kind}"
        );
    }
    let echo = [128u8, 0, 0, 0, 0, 0, 0, 0];
    assert!(report(&header("2001:db8::1", "2001:db8::2", IPProtocol::ICMPV6), &echo, false, &unreachable));
    // A message whose type cannot be read may be an error: cut short, or in
    // a fragment other than the first.
    assert!(!report(&header("2001:db8::1", "2001:db8::2", IPProtocol::ICMPV6), &[], false, &unreachable));
    let fragment = |offset: u16| {
        let field = (offset << 3).to_be_bytes();
        [58, 0, field[0], field[1], 0, 0, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0]
    };
    let fragmented = header("2001:db8::1", "2001:db8::2", IPProtocol::IPV6_FRAGMENT);
    assert!(report(&fragmented, &fragment(0), false, &unreachable));
    assert!(!report(&fragmented, &fragment(1), false, &unreachable));
    // A later fragment's data is not read as headers: one that starts with
    // another extension header may hold ICMPv6, one of UDP does not.
    let mut options = fragment(1);
    options[0] = 60;
    options[8..].copy_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    assert!(!report(&fragmented, &options, false, &unreachable));
    let mut datagram = fragment(1);
    datagram[0] = 17;
    assert!(report(&fragmented, &datagram, false, &unreachable));
    // A header chain that cannot be read is not known to be ICMPv6: a
    // Parameter Problem may be sent about it.
    let cut = header("2001:db8::1", "2001:db8::2", IPProtocol::IPV6_DESTINATION_OPTIONS);
    assert!(report(&cut, &[58, 4, 0, 0], false, &unreachable));
    // (e.3) to (e.5): not about a multicast, except Packet Too Big and an
    // unrecognized option whose type has its highest two bits 10.
    let group = header("2001:db8::1", "ff0e::1", IPProtocol::UDP);
    assert!(!report(&group, &udp, false, &unreachable));
    assert!(!report(&header("2001:db8::1", "2001:db8::2", IPProtocol::UDP), &udp, true, &unreachable));
    assert!(report(&group, &udp, false, &error(ICMPv6Type::PACKET_TOO_BIG, 0, [0, 0, 5, 0])));
    let options = |kind: u8| [17, 0, kind, 0, 0, 0, 0, 0];
    let destination = header("2001:db8::1", "ff0e::1", IPProtocol::IPV6_DESTINATION_OPTIONS);
    let problem = error(ICMPv6Type::PARAMETER_PROBLEM, ICMPv6Code::UNRECOGNIZED_OPTION, 42u32.to_be_bytes());
    assert!(report(&destination, &options(0x80), true, &problem));
    for kind in [0x00, 0x40, 0xC0] {
        assert!(!report(&destination, &options(kind), false, &problem), "{kind}");
    }
    let outside = error(ICMPv6Type::PARAMETER_PROBLEM, ICMPv6Code::UNRECOGNIZED_OPTION, 4000u32.to_be_bytes());
    assert!(!report(&destination, &options(0x80), false, &outside));
    let next_header = error(ICMPv6Type::PARAMETER_PROBLEM, ICMPv6Code::UNRECOGNIZED_NEXT_HEADER, 6u32.to_be_bytes());
    assert!(!report(&group, &udp, false, &next_header));
    // (e.6): not about a source that is not a single node.
    assert!(!report(&header("::", "2001:db8::2", IPProtocol::UDP), &udp, false, &unreachable));
    assert!(!report(&header("ff02::1", "2001:db8::2", IPProtocol::UDP), &udp, false, &unreachable));
    // (c): the quote keeps the error within 1,280 bytes, whatever the headers.
    assert_eq!(ICMPv6Message::quote(&[0; 3000], 0).len(), 1280 - 40 - 8);
    assert_eq!(ICMPv6Message::quote_length(3000, usize::MAX), 0);
}

#[test]
fn types() {
    // RFC 4443 §2.1: errors below 128.
    assert!(ICMPv6Type(127).is_error() && !ICMPv6Type(128).is_error());
    // RFC 4884 §4.6.
    assert!(ICMPv6Type::DESTINATION_UNREACHABLE.is_extensible() && ICMPv6Type::TIME_EXCEEDED.is_extensible());
    assert!(!ICMPv6Type::PACKET_TOO_BIG.is_extensible() && !ICMPv6Type::PARAMETER_PROBLEM.is_extensible());
    assert!(NDPMessage::is_solicited_node(&address("ff02::1:ff00:10a")));
    assert!(!NDPMessage::is_solicited_node(&address("ff02::1:fe00:10a")));
}

const LINK: [u8; 6] = [2, 0, 0, 0, 0, 2];
const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 3];

fn at(milliseconds: u64) -> Instant {
    Instant::from_nanos(1).saturating_add(Duration::from_millis(milliseconds))
}

fn advertisement<'a>(
    target: IPv6Address,
    solicited: bool,
    override_flag: bool,
    options: &'a [u8],
) -> NDPNeighborAdvertisement<'a> {
    NDPNeighborAdvertisement { router_flag: false, solicited_flag: solicited, override_flag, target, options }
}

fn link_option(link: [u8; 6]) -> Vec<u8> {
    encoded(|out| NDPOption::encode(NDPOptionKind::TARGET_LINK_ADDRESS, &link, out))
}

#[test]
fn neighbor_cache_constants() {
    // RFC 4861 §10.
    let config = NeighborConfig::default();
    assert_eq!(config.reachable_time, Duration::from_secs(30));
    assert_eq!(config.retransmission_timer, Duration::from_secs(1));
    assert_eq!(config.delay_first_probe_time, Duration::from_secs(5));
    assert_eq!((config.maximum_multicast_solicitations, config.maximum_unicast_solicitations), (3, 3));
}

#[test]
fn address_resolution() {
    // RFC 4861 Appendix C: INCOMPLETE until an advertisement, three multicast solicitations.
    let target = address("fe80::2");
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    assert_eq!(cache.resolve(target, Some(vec![1]), at(0)), Ok(NeighborResolution::Solicit));
    assert_eq!(cache.resolve(target, Some(vec![2]), at(0)), Ok(NeighborResolution::Pending));
    assert_eq!(cache.poll(at(999)), None);
    assert_eq!(cache.poll(at(1000)), Some(NeighborEvent::Solicit { target, link: None }));
    assert_eq!(cache.poll(at(2000)), Some(NeighborEvent::Solicit { target, link: None }));
    assert_eq!(cache.poll(at(3000)), Some(NeighborEvent::Unreachable { target, packets: VecDeque::from([vec![2]]) }));
    assert!(cache.entries.is_empty());
    // A solicited advertisement makes it REACHABLE and releases the packets.
    cache.resolve(target, Some(vec![3]), at(0)).unwrap();
    let option = link_option(LINK);
    let released = cache.receive_advertisement(&advertisement(target, true, false, &option), at(10)).packets;
    assert_eq!(released, [vec![3]]);
    assert_eq!(cache.resolve(target, None, at(20)), Ok(NeighborResolution::Resolved(LINK)));
    assert!(matches!(cache.lookup(&target), Some((LINK, NeighborState::Reachable { .. }))));
    // An unsolicited one makes it STALE; one without a link-layer address is ignored.
    let other = address("fe80::3");
    cache.resolve(other, None, at(0)).unwrap();
    assert!(cache.receive_advertisement(&advertisement(other, true, true, &[]), at(10)).packets.is_empty());
    assert!(cache.lookup(&other).is_none());
    cache.receive_advertisement(&advertisement(other, false, false, &option), at(10));
    assert!(matches!(cache.lookup(&other), Some((LINK, NeighborState::Stale { .. }))));
    // An advertisement for an unknown target is ignored (RFC 4861 §7.2.5).
    cache.receive_advertisement(&advertisement(address("fe80::99"), true, true, &option), at(10));
    assert!(!cache.entries.contains_key(&address("fe80::99")));
}

#[test]
fn unreachability_detection() {
    // RFC 4861 §7.3.3: REACHABLE, STALE after ReachableTime, DELAY when used,
    // PROBE after DELAY_FIRST_PROBE_TIME, unicast probes, then gone.
    let target = address("fe80::2");
    let option = link_option(LINK);
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    cache.resolve(target, None, at(0)).unwrap();
    cache.receive_advertisement(&advertisement(target, true, false, &option), at(0));
    assert_eq!(cache.poll_timeout(), Some(at(30_000)));
    assert_eq!(cache.poll(at(30_000)), None);
    assert!(matches!(cache.lookup(&target), Some((_, NeighborState::Stale { .. }))));
    assert_eq!(cache.resolve(target, None, at(40_000)), Ok(NeighborResolution::Resolved(LINK)));
    assert!(matches!(cache.lookup(&target), Some((_, NeighborState::Delay { .. }))));
    // A confirmation in DELAY makes it REACHABLE again.
    cache.confirm(&target, at(41_000));
    assert!(matches!(cache.lookup(&target), Some((_, NeighborState::Reachable { .. }))));
    cache.poll(at(71_000));
    cache.resolve(target, None, at(80_000)).unwrap();
    assert_eq!(cache.poll(at(85_000)), Some(NeighborEvent::Solicit { target, link: Some(LINK) }));
    assert!(matches!(cache.lookup(&target), Some((_, NeighborState::Probe { .. }))));
    assert_eq!(cache.poll(at(86_000)), Some(NeighborEvent::Solicit { target, link: Some(LINK) }));
    assert_eq!(cache.poll(at(87_000)), Some(NeighborEvent::Solicit { target, link: Some(LINK) }));
    assert_eq!(cache.poll(at(88_000)), Some(NeighborEvent::Unreachable { target, packets: VecDeque::new() }));
    // A solicited advertisement in PROBE makes it REACHABLE.
    cache.resolve(target, None, at(0)).unwrap();
    cache.receive_advertisement(&advertisement(target, false, false, &option), at(0));
    cache.resolve(target, None, at(1)).unwrap();
    cache.poll(at(5_001));
    cache.receive_advertisement(&advertisement(target, true, false, &[]), at(5_100));
    assert!(matches!(cache.lookup(&target), Some((LINK, NeighborState::Reachable { .. }))));
}

#[test]
fn advertisements_update_as_appendix_c_says() {
    // RFC 4861 §7.2.5 and Appendix C, for an entry not INCOMPLETE.
    let target = address("fe80::2");
    let same = link_option(LINK);
    let different = link_option(OTHER);
    let reachable = |cache: &mut NeighborCache| {
        cache.entries.clear();
        cache.resolve(target, None, at(0)).unwrap();
        cache.receive_advertisement(&advertisement(target, true, false, &same), at(0));
    };
    let state =
        |cache: &NeighborCache| cache.lookup(&target).map(|(link, state)| (link, std::mem::discriminant(&state)));
    let stale = std::mem::discriminant(&NeighborState::<[u8; 6]>::Stale { link: LINK });
    let reach = std::mem::discriminant(&NeighborState::<[u8; 6]>::Reachable { link: LINK, expires: at(0) });
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    // REACHABLE, S=1 O=0, a different address: STALE, the address kept.
    reachable(&mut cache);
    cache.receive_advertisement(&advertisement(target, true, false, &different), at(1));
    assert_eq!(state(&cache), Some((LINK, stale)));
    // STALE, S=1 O=0, a different address: unchanged.
    cache.receive_advertisement(&advertisement(target, true, false, &different), at(2));
    assert_eq!(state(&cache), Some((LINK, stale)));
    // S=1 O=1: the new address, REACHABLE.
    cache.receive_advertisement(&advertisement(target, true, true, &different), at(3));
    assert_eq!(state(&cache), Some((OTHER, reach)));
    // S=0 O=1, a different address: the new address, STALE.
    reachable(&mut cache);
    cache.receive_advertisement(&advertisement(target, false, true, &different), at(1));
    assert_eq!(state(&cache), Some((OTHER, stale)));
    // S=0 O=1, the same address: unchanged.
    reachable(&mut cache);
    cache.receive_advertisement(&advertisement(target, false, true, &same), at(1));
    assert_eq!(state(&cache), Some((LINK, reach)));
    // REACHABLE, S=0 O=0, a different address: STALE, the address kept
    // (§7.2.5 I.a; the table of Appendix C leaves this row out).
    cache.receive_advertisement(&advertisement(target, false, false, &different), at(1));
    assert_eq!(state(&cache), Some((LINK, stale)));
    // The Router flag is taken from the advertisement.
    reachable(&mut cache);
    let router = NDPNeighborAdvertisement { router_flag: true, ..advertisement(target, false, false, &[]) };
    cache.receive_advertisement(&router, at(1));
    assert!(cache.entries[&target].is_router);
}

#[test]
fn learning_from_other_messages() {
    // RFC 4861 Appendix C: Neighbor Solicitations, Router Solicitations and
    // Advertisements and Redirects with a link-layer address.
    let target = address("fe80::2");
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    assert!(cache.learn(target, Some(LINK), None, at(0)).packets.is_empty());
    assert!(matches!(cache.lookup(&target), Some((LINK, NeighborState::Stale { .. }))));
    assert!(!cache.entries[&target].is_router);
    // INCOMPLETE: recorded, STALE, the packets released.
    let other = address("fe80::3");
    cache.resolve(other, Some(vec![7]), at(0)).unwrap();
    assert_eq!(cache.learn(other, Some(OTHER), Some(true), at(1)).packets, [vec![7]]);
    assert!(matches!(cache.lookup(&other), Some((OTHER, NeighborState::Stale { .. }))));
    assert!(cache.entries[&other].is_router);
    // The same address: unchanged; a different one: STALE with it.
    cache.confirm(&target, at(2));
    cache.learn(target, Some(LINK), None, at(3));
    assert!(matches!(cache.lookup(&target), Some((LINK, NeighborState::Reachable { .. }))));
    cache.learn(target, Some(OTHER), None, at(4));
    assert!(matches!(cache.lookup(&target), Some((OTHER, NeighborState::Stale { .. }))));
}

#[test]
fn neighbor_cache_limits() {
    let mut cache: NeighborCache =
        NeighborCache::new(NeighborConfig { maximum_entries: 2, maximum_queued: 2, ..NeighborConfig::default() });
    cache.learn(address("fe80::1"), Some(LINK), None, at(1));
    cache.learn(address("fe80::2"), Some(LINK), None, at(2));
    // Learning never pushes an entry out; resolving forgets the oldest.
    cache.learn(address("fe80::3"), Some(LINK), None, at(3));
    assert_eq!(cache.entries.len(), 2);
    assert_eq!(cache.resolve(address("fe80::4"), None, at(4)), Ok(NeighborResolution::Solicit));
    assert_eq!(cache.entries.keys().copied().collect::<Vec<_>>(), [address("fe80::2"), address("fe80::4")]);
    let target = address("fe80::4");
    for packet in 1..=3u8 {
        cache.resolve(target, Some(vec![packet]), at(5)).unwrap();
    }
    let option = link_option(LINK);
    assert_eq!(
        cache.receive_advertisement(&advertisement(target, true, false, &option), at(6)).packets,
        [vec![2], vec![3]]
    );
    let mut empty: NeighborCache =
        NeighborCache::new(NeighborConfig { maximum_entries: 0, ..NeighborConfig::default() });
    assert_eq!(empty.resolve(target, None, at(0)), Err(ICMPError::Limit));
}

#[test]
fn neighbor_cache_learns_from_linux() {
    // The host's solicitation and the neighbor's solicited advertisement of the capture.
    let messages = messages();
    let advertisement = messages
        .iter()
        .filter_map(|(_, header, bytes)| {
            let message = ICMPv6Message::decode(bytes, header.source, header.destination).ok()?;
            let advertisement = NDPNeighborAdvertisement::decode(&message, header).ok()?;
            (advertisement.solicited_flag && advertisement.target_link_address().is_some()).then_some(advertisement)
        })
        .next()
        .unwrap();
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    cache.resolve(advertisement.target, Some(vec![1]), at(0)).unwrap();
    assert_eq!(cache.receive_advertisement(&advertisement, at(1)).packets, [vec![1]]);
    let link: [u8; 6] = advertisement.target_link_address().unwrap().try_into().unwrap();
    assert_eq!(cache.resolve(advertisement.target, None, at(2)), Ok(NeighborResolution::Resolved(link)));
}

#[test]
fn advertisements_that_must_not_update_the_cache() {
    // RFC 4861 §7.2.5: an advertisement without Override and with a
    // different address changes a REACHABLE entry to STALE "but do not update
    // the entry in any other way", and "MUST NOT update the cache" otherwise.
    let target = address("fe80::2");
    let same = link_option(LINK);
    let different = link_option(OTHER);
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    cache.resolve(target, None, at(0)).unwrap();
    let router = NDPNeighborAdvertisement { router_flag: true, ..advertisement(target, true, false, &same) };
    assert_eq!(cache.receive_advertisement(&router, at(0)), NeighborReception::default());
    assert!(cache.entries[&target].is_router);
    let host = NDPNeighborAdvertisement { router_flag: false, ..advertisement(target, false, false, &different) };
    assert!(!cache.receive_advertisement(&host, at(1)).no_longer_router);
    assert!(cache.entries[&target].is_router);
    assert!(matches!(cache.lookup(&target), Some((LINK, NeighborState::Stale { .. }))));
    let updated = cache.entries[&target].updated;
    assert!(!cache.receive_advertisement(&host, at(2)).no_longer_router);
    assert!(cache.entries[&target].is_router);
    assert_eq!(cache.entries[&target].updated, updated);
    // One that may update it reports a router that became a host (§7.2.5 II).
    let host = NDPNeighborAdvertisement { router_flag: false, ..advertisement(target, false, false, &same) };
    assert!(cache.receive_advertisement(&host, at(3)).no_longer_router);
    assert!(!cache.entries[&target].is_router);
    // While resolving, an advertisement without a link-layer address is discarded.
    let other = address("fe80::3");
    cache.resolve(other, Some(vec![1]), at(0)).unwrap();
    cache.learn(other, None, Some(true), at(0));
    let bare = NDPNeighborAdvertisement { router_flag: false, ..advertisement(other, true, true, &[]) };
    assert_eq!(cache.receive_advertisement(&bare, at(1)), NeighborReception::default());
    assert!(cache.entries[&other].is_router);
    assert!(cache.lookup(&other).is_none());
}

#[test]
fn routers_learned_and_lost() {
    // RFC 4861 §6.3.4: a Router Advertisement makes the sender a router,
    // with or without a link-layer address; §6.2.6: a Router Solicitation
    // makes it a host; §7.2.3: a Neighbor Solicitation leaves the flag alone.
    let target = address("fe80::2");
    let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
    assert_eq!(cache.learn(target, None, Some(true), at(0)), NeighborReception::default());
    assert!(cache.entries.is_empty());
    cache.learn(target, Some(LINK), Some(true), at(0));
    assert!(cache.entries[&target].is_router);
    assert!(!cache.learn(target, Some(OTHER), None, at(1)).no_longer_router);
    assert!(cache.entries[&target].is_router);
    assert!(matches!(cache.lookup(&target), Some((OTHER, NeighborState::Stale { .. }))));
    let reception = cache.learn(target, None, Some(false), at(2));
    assert!(reception.no_longer_router && reception.packets.is_empty());
    assert!(!cache.entries[&target].is_router);
    assert!(!cache.learn(target, None, Some(true), at(3)).no_longer_router);
    assert!(cache.entries[&target].is_router);
}

#[test]
fn neighbor_cache_keeps_neighbors_in_use() {
    // RFC 6583 §7.1: resolutions that nobody answers go before the neighbors
    // in use, and their packets are reported as unreachable (RFC 4861 §7.2.2).
    let config = NeighborConfig { maximum_entries: 3, maximum_queued: 2, ..NeighborConfig::default() };
    let mut cache: NeighborCache = NeighborCache::new(config);
    let router = address("fe80::1");
    cache.learn(router, Some(LINK), Some(true), at(0));
    cache.learn(address("fe80::5"), Some(OTHER), None, at(1));
    cache.resolve(address("2001:db8::1"), Some(vec![1]), at(2)).unwrap();
    // The router is used after the others changed, so it is the last to go.
    assert_eq!(cache.resolve(router, None, at(3)), Ok(NeighborResolution::Resolved(LINK)));
    for (index, time) in [(2u16, 4), (3, 5), (4, 6)] {
        let scanned = IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, index]);
        assert_eq!(cache.resolve(scanned, Some(vec![index as u8]), at(time)), Ok(NeighborResolution::Solicit));
    }
    assert!(cache.entries.contains_key(&router) && cache.entries.contains_key(&address("fe80::5")));
    assert_eq!(cache.entries.len(), 3);
    assert_eq!(cache.poll_timeout(), Some(Instant::ZERO));
    for index in 1..=3u16 {
        let target = IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, index]);
        assert_eq!(
            cache.poll(at(6)),
            Some(NeighborEvent::Unreachable { target, packets: VecDeque::from([vec![index as u8]]) })
        );
    }
    assert!(cache.abandoned.is_empty());
    assert_ne!(cache.poll_timeout(), Some(Instant::ZERO));
    // When nothing is being resolved, the entry used longest ago goes.
    cache.remove(&IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, 4]));
    cache.learn(address("fe80::6"), Some(OTHER), None, at(7));
    cache.resolve(address("fe80::7"), None, at(8)).unwrap();
    assert!(cache.entries.contains_key(&router) && !cache.entries.contains_key(&address("fe80::5")));
    // A timer does not make an entry look used: the neighbor confirmed first
    // and never used again goes before one learned later.
    let mut timed: NeighborCache =
        NeighborCache::new(NeighborConfig { maximum_entries: 2, ..NeighborConfig::default() });
    let idle = address("fe80::8");
    timed.learn(idle, Some(LINK), None, at(0));
    timed.confirm(&idle, at(0));
    timed.learn(address("fe80::9"), Some(OTHER), None, at(20_000));
    assert_eq!(timed.poll(at(30_000)), None);
    assert!(matches!(timed.lookup(&idle), Some((LINK, NeighborState::Stale { .. }))));
    timed.resolve(address("fe80::a"), None, at(31_000)).unwrap();
    assert!(!timed.entries.contains_key(&idle) && timed.entries.contains_key(&address("fe80::9")));
    // The reports of abandoned neighbors are bounded.
    let mut small: NeighborCache =
        NeighborCache::new(NeighborConfig { maximum_entries: 1, ..NeighborConfig::default() });
    for index in 0..10u16 {
        small.resolve(IPv6Address::from_words([0x2001, 0xDB8, 0, 0, 0, 0, 0, index]), None, at(0)).unwrap();
    }
    assert_eq!(small.abandoned.len(), 1);
}

#[test]
fn router_advertisement_preferences_and_flags() {
    // RFC 4191 §2.2: a reserved preference reads as medium, and so does any
    // with a router lifetime of 0; neither is sent.
    let header = |length| ndp_header("fe80::1", "ff02::1", length);
    let decode = |rest: [u8; 4]| {
        let body = [0u8; 8];
        let message = ICMPv6Message { kind: ICMPv6Type::ROUTER_ADVERTISEMENT, code: 0, rest, body: &body };
        NDPRouterAdvertisement::decode(&message, &header(16))
            .map(|advertisement| (advertisement.preference, advertisement.flags))
    };
    assert_eq!(decode([64, 0b01 << 3, 0, 30]), Ok((NDPPreference::HIGH, 0)));
    assert_eq!(decode([64, 0b11 << 3, 0, 30]), Ok((NDPPreference::LOW, 0)));
    assert_eq!(decode([64, 0b10 << 3, 0, 30]), Ok((NDPPreference::MEDIUM, 0)));
    assert_eq!(decode([64, 0b01 << 3, 0, 0]), Ok((NDPPreference::MEDIUM, 0)));
    // The H (RFC 6275) and P (RFC 4389) flags and the reserved bits are kept.
    assert_eq!(decode([64, 0x80 | 0x20 | 0x04 | 0x01, 0, 30]), Ok((NDPPreference::MEDIUM, 0x25)));
    let advertisement = NDPRouterAdvertisement {
        current_hop_limit: 64,
        managed_flag: false,
        other_flag: true,
        preference: NDPPreference::LOW,
        flags: 0x24,
        router_lifetime: 30,
        reachable_time: 0,
        retransmission_timer: 0,
        options: &[],
    };
    let bytes = encoded(|out| advertisement.encode(address("fe80::1"), address("ff02::1"), out));
    assert_eq!(bytes[5], 0x40 | 0x18 | 0x24);
    let message = ICMPv6Message::decode(&bytes, address("fe80::1"), address("ff02::1")).unwrap();
    assert_eq!(NDPRouterAdvertisement::decode(&message, &header(bytes.len())), Ok(advertisement));
    // Bits that have a field of their own are not taken from `flags`.
    for flags in [0x80, 0x40, 0x18] {
        let invalid = NDPRouterAdvertisement { flags, ..advertisement };
        assert_eq!(
            invalid.encode(address("fe80::1"), address("ff02::1"), &mut Buffer::new()),
            Err(ICMPError::Invalid),
            "{flags}"
        );
    }
    for (preference, lifetime) in [(NDPPreference::RESERVED, 30), (4, 30), (NDPPreference::HIGH, 0)] {
        let invalid = NDPRouterAdvertisement { preference, router_lifetime: lifetime, ..advertisement };
        assert_eq!(
            invalid.encode(address("fe80::1"), address("ff02::1"), &mut Buffer::new()),
            Err(ICMPError::Invalid),
            "{preference} {lifetime}"
        );
    }
}

#[test]
fn route_and_prefix_information_limits() {
    // RFC 4191 §2.3: the length is 1, 2 or 3 units; the reserved preference makes the option ignored.
    for length in 0..40usize {
        let mut data = vec![0u8; length];
        if let Some(first) = data.first_mut() {
            *first = 128;
        }
        let valid = length == 22;
        assert_eq!(NDPRouteInformation::decode(&data).is_ok(), valid, "{length}");
    }
    let reserved = [0, NDPPreference::RESERVED << 3, 0, 0, 0, 0];
    assert_eq!(NDPRouteInformation::decode(&reserved), Err(ICMPError::Invalid));
    let route = NDPRouteInformation {
        prefix_length: 0,
        preference: NDPPreference::RESERVED,
        lifetime: 0,
        prefix: IPv6Address::UNSPECIFIED,
    };
    assert_eq!(route.encode(&mut Buffer::new()), Err(ICMPError::Invalid));
    // RFC 4861 §4.6.2: a prefix length of at most 128, the bits after it
    // ignored and sent as zero; RFC 4862 §5.5.3 (c): a preferred lifetime
    // above the valid one makes the option ignored.
    let information = NDPPrefixInformation {
        prefix_length: 48,
        on_link: true,
        autonomous: false,
        flags: 0x20 | 0x10 | 0x01,
        valid_lifetime: 600,
        preferred_lifetime: 300,
        prefix: address("2001:db8:1:2:3::"),
    };
    let bytes = encoded(|out| information.encode(out));
    assert_eq!(bytes[3], 0x80 | 0x31);
    assert_eq!(&bytes[16..32], &address("2001:db8:1::").0);
    let decoded = NDPPrefixInformation::decode(&bytes[2..]).unwrap();
    assert_eq!(decoded, NDPPrefixInformation { prefix: address("2001:db8:1::"), ..information });
    let mut data = bytes[2..].to_vec();
    data[14..30].copy_from_slice(&address("2001:db8:1:ffff::").0);
    assert_eq!(NDPPrefixInformation::decode(&data).unwrap().prefix, address("2001:db8:1::"));
    data[0] = 129;
    assert_eq!(NDPPrefixInformation::decode(&data), Err(ICMPError::Invalid));
    let late = NDPPrefixInformation { preferred_lifetime: 601, ..information };
    assert_eq!(late.encode(&mut Buffer::new()), Err(ICMPError::Invalid));
    for flags in [0x80, 0x40] {
        let invalid = NDPPrefixInformation { flags, ..information };
        assert_eq!(invalid.encode(&mut Buffer::new()), Err(ICMPError::Invalid), "{flags}");
    }
    data[0] = 48;
    data[6..10].copy_from_slice(&601u32.to_be_bytes());
    assert_eq!(NDPPrefixInformation::decode(&data), Err(ICMPError::Invalid));
}
