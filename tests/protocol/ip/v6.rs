//! Tests of `umilib::protocol::ip::v6`: the header (RFC 8200 §3), the
//! extension headers and options (§4), fragmentation and reassembly (§4.5,
//! RFC 5722, RFC 6946, RFC 7112), against packets of the Linux kernel.

use umilib::bytes::Buffer;
use umilib::protocol::ip::v6::{
    IPv6Error, IPv6ExtensionHeader, IPv6ExtensionHeaders, IPv6FragmentHeader, IPv6Fragmenter, IPv6Header, IPv6Option,
    IPv6OptionKind, IPv6OptionsHeader, IPv6Reassembler, IPv6ReassemblyConfig, IPv6RoutingHeader,
};
use umilib::protocol::ip::{IPError, IPProtocol, IPPseudoHeader, IPv6Address};
use umilib::runtime::Instant;

use super::super::Capture;

/// The IPv6 packets of the Linux capture: the description and the bytes
/// after the Ethernet header and its tags.
fn packets() -> Vec<(String, Vec<u8>)> {
    let mut packets = Vec::new();
    for (description, frame) in Capture::frames("protocol/ethernet/linux.txt") {
        let mut offset = 12;
        while matches!(u16::from_be_bytes([frame[offset], frame[offset + 1]]), 0x8100 | 0x88A8) {
            offset += 4;
        }
        if u16::from_be_bytes([frame[offset], frame[offset + 1]]) == 0x86DD {
            packets.push((description, frame[offset + 2..].to_vec()));
        }
    }
    packets
}

/// The value after `name` in tcpdump's description of an IPv6 header.
fn field<'a>(description: &'a str, name: &str) -> Option<&'a str> {
    let start = description.find(&format!("{name} "))? + name.len() + 1;
    description[start..].split([',', ')']).next()
}

fn address(text: &str) -> IPv6Address {
    text.parse().unwrap()
}

fn encode_header(header: &IPv6Header) -> Vec<u8> {
    let mut buffer = Buffer::new();
    header.encode(&mut buffer).unwrap();
    buffer.into_vec()
}

#[test]
fn decodes_linux_packets() {
    let packets = packets();
    assert!(packets.len() >= 20);
    for (description, bytes) in &packets {
        let (header, payload) = IPv6Header::decode(bytes).unwrap_or_else(|error| panic!("{error}: {description}"));
        assert_eq!(Some(header.hop_limit.to_string().as_str()), field(description, "hlim"), "{description}");
        assert_eq!(
            Some(header.payload_length.to_string().as_str()),
            field(description, "payload length:"),
            "{description}"
        );
        let next = field(description, "next-header").unwrap();
        assert!(next.ends_with(&format!("({}", header.next_header.0)), "{description}");
        let flow = field(description, "flowlabel").map_or(0, |value| u32::from_str_radix(&value[2..], 16).unwrap());
        assert_eq!(header.flow_label, flow, "{description}");
        assert_eq!(payload.len(), header.payload_length as usize);
        assert_eq!(encode_header(&header), bytes[..40], "{description}");
        // Every header chain reaches its upper layer.
        let (upper, offset) = IPv6ExtensionHeaders::upper_layer(header.next_header, payload).unwrap();
        assert!(
            !IPv6ExtensionHeader::is_extension(upper) || upper == IPProtocol::IPV6_FRAGMENT || offset <= payload.len()
        );
    }
}

#[test]
fn decodes_hop_by_hop_options_of_linux() {
    // MLDv2 reports carry a Hop-by-Hop Options header with a Router Alert
    // (RFC 2711) and padding (RFC 3810 §5).
    let (description, bytes) =
        packets().into_iter().find(|(description, _)| description.contains("HBH (rtalert")).unwrap();
    let (header, payload) = IPv6Header::decode(&bytes).unwrap();
    assert_eq!(header.next_header, IPProtocol::HOP_BY_HOP_OPTIONS, "{description}");
    let extensions: Vec<_> = IPv6ExtensionHeaders::new(header.next_header, payload).map(Result::unwrap).collect();
    assert_eq!(extensions.len(), 1);
    assert_eq!(extensions[0].kind, IPProtocol::HOP_BY_HOP_OPTIONS);
    assert_eq!(extensions[0].next_header, IPProtocol::ICMPV6);
    let options = IPv6OptionsHeader::decode(extensions[0].bytes).unwrap();
    let options: Vec<_> = options.iter().map(Result::unwrap).collect();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].kind, IPv6OptionKind::ROUTER_ALERT);
    assert_eq!(options[0].data, &[0, 0]);
    assert_eq!(options[0].offset, 2);
    assert_eq!(IPv6ExtensionHeaders::upper_layer(header.next_header, payload), Ok((IPProtocol::ICMPV6, 8)));
    // The ICMPv6 checksum covers the pseudo-header (RFC 8200 §8.1).
    let pseudo =
        IPPseudoHeader::new(header.source.into(), header.destination.into(), IPProtocol::ICMPV6, payload.len() - 8)
            .unwrap();
    let mut checksum = pseudo.checksum();
    checksum.update(&payload[8..]);
    assert_eq!(checksum.sum16(), 0xFFFF);
}

#[test]
fn fields_are_placed_as_rfc8200_says() {
    let mut header = IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::UDP, 0x1234).unwrap();
    header.dscp = 46;
    header.ecn = 2;
    header.flow_label = 0xABCDE;
    header.hop_limit = 9;
    let bytes = encode_header(&header);
    // Version 6, Traffic Class (DSCP and ECN), 20-bit Flow Label.
    assert_eq!(&bytes[..4], &(6u32 << 28 | ((46 << 2 | 2) as u32) << 20 | 0xABCDE).to_be_bytes());
    assert_eq!(&bytes[4..8], &[0x12, 0x34, 17, 9]);
    assert_eq!(&bytes[8..24], &address("2001:db8::1").0);
    assert_eq!(&bytes[24..40], &address("2001:db8::2").0);
    assert_eq!(
        IPv6Header::new(IPv6Address::LOOPBACK, IPv6Address::LOOPBACK, IPProtocol::UDP, 65536),
        Err(IPv6Error::Length)
    );
    assert_eq!(IPv6Header::DEFAULT_HOP_LIMIT, 64);
    assert_eq!(IPv6Header::MINIMUM_MTU, 1280);
}

#[test]
fn invalid_headers_are_refused() {
    let header = IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::UDP, 4).unwrap();
    let mut bytes = encode_header(&header);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    assert!(IPv6Header::decode(&bytes).is_ok());
    assert_eq!(IPv6Header::decode(&bytes[..39]), Err(IPv6Error::Length));
    assert_eq!(IPv6Header::decode(&bytes[..43]), Err(IPv6Error::Length));
    for version in [0x40, 0x70, 0x00, 0xF0] {
        let mut other = bytes.clone();
        other[0] = version | (other[0] & 0x0F);
        assert_eq!(IPv6Header::decode(&other), Err(IPv6Error::Version), "{version:#x}");
    }
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[9; 6]);
    assert_eq!(IPv6Header::decode(&padded).unwrap().1, &[1, 2, 3, 4]);
}

#[test]
fn option_kinds() {
    // RFC 8200 §4.2: the highest two bits are the action, the third whether the data may change.
    assert_eq!(IPv6OptionKind::PAD1.action(), 0);
    assert_eq!(IPv6OptionKind::ROUTER_ALERT.action(), 0);
    assert!(!IPv6OptionKind::ROUTER_ALERT.may_change());
    assert_eq!(IPv6OptionKind::JUMBO_PAYLOAD.action(), 3);
    assert_eq!(IPv6OptionKind::HOME_ADDRESS.action(), 3);
    assert_eq!(IPv6OptionKind(0x63).action(), 1);
    assert!(IPv6OptionKind(0x63).may_change());
    assert_eq!(IPv6OptionKind(0x8B).action(), 2);
}

#[test]
fn options_headers_pad_to_eight_bytes() {
    let mut options = Buffer::new();
    IPv6Option::encode(IPv6OptionKind::ROUTER_ALERT, &[0, 0], &mut options).unwrap();
    let mut header = Buffer::new();
    IPv6OptionsHeader { next_header: IPProtocol::ICMPV6, options: options.as_slice() }.encode(&mut header).unwrap();
    // Next Header, Hdr Ext Len 0, Router Alert, PadN of 0 data bytes.
    assert_eq!(header.as_slice(), &[58, 0, 5, 2, 0, 0, 1, 0]);
    let decoded = IPv6OptionsHeader::decode(header.as_slice()).unwrap();
    assert_eq!(decoded.next_header, IPProtocol::ICMPV6);
    assert_eq!(
        decoded.iter().map(Result::unwrap).map(|option| option.kind).collect::<Vec<_>>(),
        [IPv6OptionKind::ROUTER_ALERT]
    );
    // One byte of padding is Pad1; longer is PadN.
    for length in 0..40 {
        let options = vec![IPv6OptionKind(0x1E).0, length as u8]
            .into_iter()
            .chain(std::iter::repeat_n(7, length))
            .collect::<Vec<_>>();
        let mut header = Buffer::new();
        IPv6OptionsHeader { next_header: IPProtocol::TCP, options: &options }.encode(&mut header).unwrap();
        let bytes = header.as_slice();
        assert_eq!(bytes.len() % 8, 0);
        assert_eq!(bytes.len(), (bytes[1] as usize + 1) * 8);
        let decoded = IPv6OptionsHeader::decode(bytes).unwrap();
        let parsed: Vec<_> = decoded.iter().map(Result::unwrap).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].data.len(), length);
        let padding = bytes.len() - 2 - options.len();
        match padding {
            0 => {}
            1 => assert_eq!(bytes[bytes.len() - 1], 0),
            _ => assert_eq!(&bytes[2 + options.len()..4 + options.len()], &[1, (padding - 2) as u8]),
        }
    }
    // An option that runs past its header.
    assert_eq!(IPv6OptionsHeader::decode(&[6, 0, 5, 9, 0, 0, 0, 0]), Err(IPv6Error::Option));
    assert_eq!(IPv6OptionsHeader::decode(&[6, 1, 0, 0, 0, 0, 0, 0]), Err(IPv6Error::Length));
    assert_eq!(IPv6Option::encode(IPv6OptionKind::PAD1, &[0], &mut Buffer::new()), Err(IPv6Error::Option));
}

#[test]
fn routing_and_fragment_headers() {
    // RFC 8200 §4.4.
    let routing = [17, 2, 4, 1, 0, 0, 0, 0, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let header = IPv6RoutingHeader::decode(&routing).unwrap();
    assert_eq!((header.next_header, header.routing_type, header.segments_left), (IPProtocol::UDP, 4, 1));
    assert_eq!(header.data.len(), 20);
    let mut buffer = Buffer::new();
    header.encode(&mut buffer).unwrap();
    assert_eq!(buffer.as_slice(), &routing);
    assert_eq!(IPv6RoutingHeader::decode(&routing[..16]), Err(IPv6Error::Length));
    assert_eq!(IPv6RoutingHeader { data: &[0; 5], ..header }.encode(&mut Buffer::new()), Err(IPv6Error::Length));
    // RFC 8200 §4.5: offset in the top 13 bits, M in the lowest.
    let fragment = IPv6FragmentHeader {
        next_header: IPProtocol::TCP,
        fragment_offset: 0x1ABC,
        more_fragments: true,
        identification: 0xDEADBEEF,
    };
    let bytes = fragment.to_bytes();
    assert_eq!(bytes, [6, 0, 0xD5, 0xE1, 0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(IPv6FragmentHeader::decode(&bytes), Ok(fragment));
    // The reserved fields are ignored.
    assert_eq!(IPv6FragmentHeader::decode(&[6, 0xFF, 0xD5, 0xE7, 0xDE, 0xAD, 0xBE, 0xEF]), Ok(fragment));
    assert!(IPv6FragmentHeader { fragment_offset: 0, more_fragments: false, ..fragment }.is_atomic());
}

#[test]
fn extension_header_lengths() {
    // RFC 8200 §4: (Hdr Ext Len + 1) × 8; RFC 4302 §2.2: (Payload Len + 2) × 4; Fragment: 8.
    assert_eq!(
        IPv6ExtensionHeader::length(
            IPProtocol::IPV6_DESTINATION_OPTIONS,
            &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        ),
        Ok(16)
    );
    assert_eq!(
        IPv6ExtensionHeader::length(
            IPProtocol::AH,
            &[0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        ),
        Ok(24)
    );
    assert_eq!(IPv6ExtensionHeader::length(IPProtocol::IPV6_FRAGMENT, &[0; 8]), Ok(8));
    assert_eq!(IPv6ExtensionHeader::length(IPProtocol::IPV6_ROUTING, &[0, 1, 0, 0]), Err(IPv6Error::Length));
    // RFC 7045: the registry of extension headers, ESP ending the chain.
    for number in [0, 43, 44, 51, 60, 135, 139, 140, 253, 254] {
        assert!(IPv6ExtensionHeader::is_extension(IPProtocol(number)), "{number}");
    }
    for number in [6, 17, 50, 58, 59] {
        assert!(!IPv6ExtensionHeader::is_extension(IPProtocol(number)), "{number}");
    }
}

#[test]
fn hop_by_hop_must_come_first() {
    // RFC 8200 §4.1: Destination Options, then Hop-by-Hop Options.
    let payload = [0, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0];
    let result: Result<Vec<_>, _> = IPv6ExtensionHeaders::new(IPProtocol::IPV6_DESTINATION_OPTIONS, &payload).collect();
    assert_eq!(result, Err(IPv6Error::ExtensionHeader));
    assert_eq!(
        IPv6ExtensionHeaders::upper_layer(IPProtocol::HOP_BY_HOP_OPTIONS, &payload[8..]),
        Ok((IPProtocol::UDP, 8))
    );
    // A truncated chain.
    assert_eq!(
        IPv6ExtensionHeaders::upper_layer(IPProtocol::HOP_BY_HOP_OPTIONS, &payload[..6]),
        Err(IPv6Error::Length)
    );
    // No Next Header and ESP end the chain.
    assert_eq!(
        IPv6ExtensionHeaders::upper_layer(IPProtocol::IPV6_NO_NEXT_HEADER, &[1, 2, 3]),
        Ok((IPProtocol::IPV6_NO_NEXT_HEADER, 0))
    );
    assert_eq!(IPv6ExtensionHeaders::upper_layer(IPProtocol::ESP, &[1, 2, 3]), Ok((IPProtocol::ESP, 0)));
}

/// The fragments of the capture, by identification, with their headers.
fn fragmented() -> Vec<Vec<(IPv6Header, Vec<u8>)>> {
    let mut fragmented: Vec<Vec<(IPv6Header, Vec<u8>)>> = Vec::new();
    for (_, bytes) in packets() {
        let (header, payload) = IPv6Header::decode(&bytes).unwrap();
        if header.next_header != IPProtocol::IPV6_FRAGMENT {
            continue;
        }
        let identification = IPv6FragmentHeader::decode(payload).unwrap().identification;
        let same = |fragments: &&mut Vec<(IPv6Header, Vec<u8>)>| {
            IPv6FragmentHeader::decode(&fragments[0].1).unwrap().identification == identification
        };
        match fragmented.iter_mut().find(same) {
            Some(fragments) => fragments.push((header, payload.to_vec())),
            None => fragmented.push(vec![(header, payload.to_vec())]),
        }
    }
    fragmented
}

#[test]
fn reassembles_linux_fragments_in_any_order() {
    let packets = fragmented();
    assert_eq!(packets.len(), 2);
    for fragments in &packets {
        assert_eq!(fragments.len(), 3);
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
            let mut result = None;
            for (step, &index) in order.iter().enumerate() {
                let (header, payload) = &fragments[index];
                let output = reassembler.receive(header, payload, Instant::from_nanos(step as u64)).unwrap();
                assert_eq!(output.is_some(), step == 2, "{order:?}");
                result = result.or(output);
            }
            let (header, payload) = result.unwrap();
            // The Fragment header is gone and its Next Header is in its place.
            assert_eq!(header.next_header, IPProtocol::ICMPV6);
            assert_eq!(payload.len(), 3008);
            assert_eq!(header.payload_length, 3008);
            let pseudo =
                IPPseudoHeader::new(header.source.into(), header.destination.into(), IPProtocol::ICMPV6, payload.len())
                    .unwrap();
            let mut checksum = pseudo.checksum();
            checksum.update(&payload);
            assert_eq!(checksum.sum16(), 0xFFFF);
            assert!(reassembler.table.is_empty() && reassembler.table.buffered == 0);
        }
    }
}

#[test]
fn fragments_as_linux_does() {
    for fragments in fragmented() {
        let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
        let mut whole = None;
        for (header, payload) in &fragments {
            whole = whole.or(reassembler.receive(header, payload, Instant::ZERO).unwrap());
        }
        let (header, payload) = whole.unwrap();
        let identification = IPv6FragmentHeader::decode(&fragments[0].1).unwrap().identification;
        let ours: Vec<_> = IPv6Fragmenter::new(header, &payload, identification, 1500).unwrap().collect();
        assert_eq!(ours.len(), fragments.len());
        for (fragment, (theirs, data)) in ours.iter().zip(&fragments) {
            let mut buffer = Buffer::new();
            fragment.encode(&mut buffer).unwrap();
            let mut expected = encode_header(theirs);
            expected.extend_from_slice(data);
            assert_eq!(buffer.as_slice(), expected);
            assert_eq!(fragment.length(), expected.len());
        }
    }
}

/// A packet with a Hop-by-Hop Options header, a Routing header, a
/// Destination Options header and `data` bytes of UDP.
fn packet_with_extensions(data: usize) -> (IPv6Header, Vec<u8>) {
    let mut payload = Buffer::new();
    let mut options = Buffer::new();
    IPv6Option::encode(IPv6OptionKind::ROUTER_ALERT, &[0, 0], &mut options).unwrap();
    IPv6OptionsHeader { next_header: IPProtocol::IPV6_ROUTING, options: options.as_slice() }
        .encode(&mut payload)
        .unwrap();
    let segment = address("2001:db8::99").0;
    let mut routing_data = vec![0; 4];
    routing_data.extend_from_slice(&segment);
    IPv6RoutingHeader {
        next_header: IPProtocol::IPV6_DESTINATION_OPTIONS,
        routing_type: 4,
        segments_left: 1,
        data: &routing_data,
    }
    .encode(&mut payload)
    .unwrap();
    IPv6OptionsHeader { next_header: IPProtocol::UDP, options: &[] }.encode(&mut payload).unwrap();
    let mut payload = payload.into_vec();
    payload.extend((0..data).map(|index| (index * 7) as u8));
    let header =
        IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::HOP_BY_HOP_OPTIONS, payload.len())
            .unwrap();
    (header, payload)
}

#[test]
fn per_fragment_headers_repeat_in_every_fragment() {
    // RFC 8200 §4.5: the headers up to the Routing header repeat; the
    // Destination Options header after it is in the first fragment only.
    let (header, payload) = packet_with_extensions(3000);
    let fragments: Vec<_> = IPv6Fragmenter::new(header, &payload, 7, 1280).unwrap().collect();
    assert!(fragments.len() >= 3);
    let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
    let mut whole = None;
    for (index, fragment) in fragments.iter().enumerate() {
        assert_eq!(fragment.per_fragment, &payload[..32]);
        assert!(fragment.length() <= 1280);
        let mut bytes = Buffer::new();
        fragment.encode(&mut bytes).unwrap();
        let (decoded, packet_payload) = IPv6Header::decode(bytes.as_slice()).unwrap();
        // The headers after the Fragment header of a later fragment are data.
        let mut chain = Vec::new();
        for extension in IPv6ExtensionHeaders::new(decoded.next_header, packet_payload) {
            let kind = extension.unwrap().kind;
            chain.push(kind);
            if kind == IPProtocol::IPV6_FRAGMENT && index > 0 {
                break;
            }
        }
        let mut expected = vec![IPProtocol::HOP_BY_HOP_OPTIONS, IPProtocol::IPV6_ROUTING, IPProtocol::IPV6_FRAGMENT];
        if index == 0 {
            expected.push(IPProtocol::IPV6_DESTINATION_OPTIONS);
        }
        assert_eq!(chain, expected, "fragment {index}");
        let more = index + 1 < fragments.len();
        let fragment_header = fragment.fragment.unwrap();
        assert_eq!(fragment_header.more_fragments, more);
        assert_eq!(fragment_header.next_header, IPProtocol::IPV6_DESTINATION_OPTIONS);
        assert!(!more || fragment.data.len() % 8 == 0);
        whole = whole.or(reassembler.receive(&decoded, packet_payload, Instant::ZERO).unwrap());
    }
    let (reassembled, reassembled_payload) = whole.unwrap();
    assert_eq!(reassembled, header);
    assert_eq!(reassembled_payload, payload);
}

#[test]
fn fragmentation_limits() {
    let (header, payload) = packet_with_extensions(3000);
    // A packet that fits is not fragmented.
    let single: Vec<_> = IPv6Fragmenter::new(header, &payload, 7, 40 + payload.len()).unwrap().collect();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].fragment, None);
    let mut bytes = Buffer::new();
    single[0].encode(&mut bytes).unwrap();
    assert_eq!(&bytes.as_slice()[40..], payload);
    // Room for the per-fragment headers but not 8 bytes of data.
    assert_eq!(IPv6Fragmenter::new(header, &payload, 7, 40 + 32 + 8 + 7).err(), Some(IPv6Error::Fragment));
    // Room for 8 bytes of data, enough for the Destination Options header after the Routing header.
    assert!(IPv6Fragmenter::new(header, &payload, 7, 40 + 32 + 8 + 8).unwrap().count() > 1);
    let mut long = Buffer::new();
    let options: Vec<u8> = [0x1E, 100].into_iter().chain([0; 100]).collect();
    IPv6OptionsHeader { next_header: IPProtocol::UDP, options: &options }.encode(&mut long).unwrap();
    let mut long = long.into_vec();
    long.extend_from_slice(&[0; 2000]);
    let header = IPv6Header::new(
        address("2001:db8::1"),
        address("2001:db8::2"),
        IPProtocol::IPV6_DESTINATION_OPTIONS,
        long.len(),
    )
    .unwrap();
    assert_eq!(IPv6Fragmenter::new(header, &long, 7, 40 + 8 + 64).err(), Some(IPv6Error::HeaderChain));
}

#[test]
fn fragments_are_not_fragmented_again() {
    // RFC 8200 §4.5: only the source fragments a packet; a packet with a
    // Fragment header anywhere in its chain is already a fragment.
    let fragment = IPv6FragmentHeader {
        next_header: IPProtocol::UDP,
        fragment_offset: 0,
        more_fragments: false,
        identification: 3,
    };
    let mut payload = vec![IPProtocol::IPV6_FRAGMENT.0, 0, 0, 0, 0, 0, 0, 0];
    payload.extend_from_slice(&fragment.to_bytes());
    payload.extend_from_slice(&[0; 2000]);
    let header = IPv6Header::new(
        address("2001:db8::1"),
        address("2001:db8::2"),
        IPProtocol::IPV6_DESTINATION_OPTIONS,
        payload.len(),
    )
    .unwrap();
    assert_eq!(IPv6Fragmenter::new(header, &payload, 9, 1280).err(), Some(IPv6Error::ExtensionHeader));
    assert_eq!(IPv6Fragmenter::new(header, &payload, 9, 4000).err(), Some(IPv6Error::ExtensionHeader));
    let (header, payload) = fragment_packet(fragment, &[0; 100]);
    assert_eq!(IPv6Fragmenter::new(header, &payload, 9, 1280).err(), Some(IPv6Error::ExtensionHeader));
}

fn fragment_packet(fragment: IPv6FragmentHeader, data: &[u8]) -> (IPv6Header, Vec<u8>) {
    let mut payload = fragment.to_bytes().to_vec();
    payload.extend_from_slice(data);
    let header =
        IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::IPV6_FRAGMENT, payload.len())
            .unwrap();
    (header, payload)
}

#[test]
fn atomic_fragments_are_processed_on_their_own() {
    // RFC 6946 and RFC 8200 §4.5: offset zero and M zero is a whole packet,
    // even while fragments of the same identification are being reassembled.
    let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
    let pending = IPv6FragmentHeader {
        next_header: IPProtocol::UDP,
        fragment_offset: 0,
        more_fragments: true,
        identification: 5,
    };
    let (header, payload) = fragment_packet(pending, &[1; 16]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Ok(None));
    let atomic = IPv6FragmentHeader { more_fragments: false, ..pending };
    let (header, payload) = fragment_packet(atomic, &[2; 5]);
    let (whole, data) = reassembler.receive(&header, &payload, Instant::ZERO).unwrap().unwrap();
    assert_eq!(whole.next_header, IPProtocol::UDP);
    assert_eq!(whole.payload_length, 5);
    assert_eq!(data, [2; 5]);
    assert_eq!(reassembler.table.len(), 1);
}

#[test]
fn reassembly_errors() {
    let first = IPv6FragmentHeader {
        next_header: IPProtocol::UDP,
        fragment_offset: 0,
        more_fragments: true,
        identification: 9,
    };
    let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
    // A fragment but the last that is not a multiple of 8 bytes.
    let (header, payload) = fragment_packet(first, &[0; 12]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::Length));
    // A first fragment without the whole header chain (RFC 7112).
    let chain = IPv6FragmentHeader { next_header: IPProtocol::IPV6_DESTINATION_OPTIONS, ..first };
    let (header, payload) = fragment_packet(chain, &[17, 2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::HeaderChain));
    // A fragment that would make the payload longer than 65,535 bytes.
    let late = IPv6FragmentHeader { fragment_offset: 8190, ..first };
    let (header, payload) = fragment_packet(late, &[0; 16]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::Reassembly(IPError::Length)));
    // Overlapping fragments abandon the packet (RFC 5722).
    let (header, payload) = fragment_packet(first, &[0; 16]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Ok(None));
    let overlapping = IPv6FragmentHeader { fragment_offset: 1, ..first };
    let (header, payload) = fragment_packet(overlapping, &[0; 16]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::Reassembly(IPError::Overlap)));
    assert_eq!(reassembler.table.buffered, 0);
    // Its fragments, those not yet received too, are dropped (RFC 5722 §4), until the deadline.
    let last = IPv6FragmentHeader { fragment_offset: 2, more_fragments: false, ..first };
    let (header, payload) = fragment_packet(last, &[0; 4]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::Reassembly(IPError::Overlap)));
    let (_, abandoned) = reassembler.expire(Instant::MAX).unwrap();
    assert!(abandoned.abandoned && abandoned.first.is_none());
    assert!(reassembler.table.is_empty());
    // A Hop-by-Hop Options header behind a Fragment header is out of place (RFC 8200 §4.1).
    let hop_by_hop = IPv6FragmentHeader { next_header: IPProtocol::HOP_BY_HOP_OPTIONS, more_fragments: false, ..first };
    let (header, payload) = fragment_packet(hop_by_hop, &[17, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::ExtensionHeader));
    // A packet without a Fragment header is whole.
    let header = IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::UDP, 3).unwrap();
    assert_eq!(reassembler.receive(&header, &[1, 2, 3], Instant::ZERO), Ok(Some((header, vec![1, 2, 3]))));
}

#[test]
fn reassembly_times_out() {
    let config = IPv6ReassemblyConfig::default();
    // RFC 8200 §4.5: 60 seconds from the first-arriving fragment.
    assert_eq!(config.timeout, std::time::Duration::from_secs(60));
    let mut reassembler = IPv6Reassembler::new(config);
    let second = IPv6FragmentHeader {
        next_header: IPProtocol::UDP,
        fragment_offset: 2,
        more_fragments: false,
        identification: 1,
    };
    let (header, payload) = fragment_packet(second, &[0; 4]);
    let start = Instant::from_nanos(5);
    reassembler.receive(&header, &payload, start).unwrap();
    assert_eq!(reassembler.poll_timeout(), Some(start.saturating_add(config.timeout)));
    let (_, reassembly) = reassembler.expire(start.saturating_add(config.timeout)).unwrap();
    // The first fragment did not arrive: no Time Exceeded message is sent for it.
    assert!(reassembly.first.is_none());
    assert!(reassembler.table.is_empty() && reassembler.table.buffered == 0);
}

#[test]
fn reassembly_limits_drop_the_oldest_packets() {
    let fragment = |identification| IPv6FragmentHeader {
        next_header: IPProtocol::UDP,
        fragment_offset: 0,
        more_fragments: true,
        identification,
    };
    let at = |seconds: u64| Instant::ZERO.saturating_add(std::time::Duration::from_secs(seconds));
    let identifications = |reassembler: &IPv6Reassembler| {
        reassembler.table.entries.keys().map(|key| key.identification).collect::<Vec<_>>()
    };
    let config = IPv6ReassemblyConfig { maximum_datagrams: 1, ..IPv6ReassemblyConfig::default() };
    let mut reassembler = IPv6Reassembler::new(config);
    let (header, payload) = fragment_packet(fragment(1), &[0; 8]);
    assert_eq!(reassembler.receive(&header, &payload, at(1)), Ok(None));
    let (header, payload) = fragment_packet(fragment(2), &[0; 8]);
    assert_eq!(reassembler.receive(&header, &payload, at(2)), Ok(None));
    assert_eq!(identifications(&reassembler), [2]);
    // A fragment that alone exceeds the bytes allowed fails.
    let config = IPv6ReassemblyConfig { maximum_buffered: 8, ..IPv6ReassemblyConfig::default() };
    let mut reassembler = IPv6Reassembler::new(config);
    let (header, payload) = fragment_packet(fragment(1), &[0; 16]);
    assert_eq!(reassembler.receive(&header, &payload, Instant::ZERO), Err(IPv6Error::Limit));
    assert!(reassembler.table.is_empty());
    // The accounting covers what is held, the per-fragment headers included.
    let mut reassembler = IPv6Reassembler::new(IPv6ReassemblyConfig::default());
    let (header, payload) = fragment_packet(fragment(3), &[0; 8]);
    reassembler.receive(&header, &payload, Instant::ZERO).unwrap();
    let held: usize = reassembler.table.entries.values().map(|reassembly| reassembly.memory()).sum();
    assert_eq!(reassembler.table.buffered, held);
}

#[test]
fn truncated_packets_as_errors_quote_them() {
    // RFC 4443 §2.4 (c): an error quotes as much of the packet as fits.
    let header = IPv6Header::new(address("2001:db8::1"), address("2001:db8::2"), IPProtocol::UDP, 100).unwrap();
    let mut bytes = encode_header(&header);
    bytes.extend_from_slice(&[5; 30]);
    assert_eq!(IPv6Header::decode(&bytes), Err(IPv6Error::Length));
    assert_eq!(IPv6Header::decode_truncated(&bytes), Ok((header, &[5u8; 30][..])));
    assert_eq!(IPv6Header::decode_truncated(&bytes[..39]), Err(IPv6Error::Length));
}
