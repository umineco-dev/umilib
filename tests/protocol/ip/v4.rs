//! Tests of `umilib::protocol::ip::v4`: the header (RFC 791 §3.1), its
//! options, fragmentation (RFC 791 §3.2) and reassembly (RFC 815,
//! RFC 1122 §3.3.2), against packets of the Linux kernel.

use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::ip::v4::{
    IPv4Error, IPv4Fragmenter, IPv4Header, IPv4OptionKind, IPv4Options, IPv4Reassembler, IPv4ReassemblyConfig,
};
use umilib::protocol::ip::{IPError, IPFragmentBuffer, IPProtocol, IPv4Address, InternetChecksum};
use umilib::runtime::Instant;

use super::super::Capture;

/// The IPv4 packets of the Linux capture: the description and the bytes
/// after the Ethernet header and its tags.
pub fn packets() -> Vec<(String, Vec<u8>)> {
    let mut packets = Vec::new();
    for (description, frame) in Capture::frames("protocol/ethernet/linux.txt") {
        let mut offset = 12;
        while matches!(u16::from_be_bytes([frame[offset], frame[offset + 1]]), 0x8100 | 0x88A8) {
            offset += 4;
        }
        if u16::from_be_bytes([frame[offset], frame[offset + 1]]) == 0x0800 {
            packets.push((description, frame[offset + 2..].to_vec()));
        }
    }
    packets
}

/// The value after `name ` in tcpdump's description of an IPv4 header.
fn field<'a>(description: &'a str, name: &str) -> &'a str {
    let header = &description[description.find("(tos ").unwrap_or_else(|| panic!("no IPv4 header in {description}"))..];
    let start = header.find(&format!(" {name} ")).unwrap_or_else(|| panic!("{name} in {description}")) + name.len() + 2;
    header[start..].split([',', ')']).next().unwrap()
}

fn encode(header: &IPv4Header) -> Vec<u8> {
    let mut buffer = Buffer::new();
    header.encode(&mut buffer).unwrap();
    buffer.into_vec()
}

#[test]
fn decodes_linux_packets() {
    let packets = packets();
    assert!(packets.len() >= 20);
    for (description, bytes) in &packets {
        let (header, payload) = IPv4Header::decode(bytes).unwrap_or_else(|error| panic!("{error}: {description}"));
        assert_eq!(header.time_to_live.to_string(), field(description, "ttl"), "{description}");
        assert_eq!(header.identification.to_string(), field(description, "id"), "{description}");
        assert_eq!(header.total_length.to_string(), field(description, "length"), "{description}");
        let offset = header.fragment_offset as usize * 8;
        assert_eq!(offset.to_string(), field(description, "offset"), "{description}");
        let flags = field(description, "flags");
        assert_eq!(header.dont_fragment, flags.contains("DF"), "{description}");
        assert_eq!(header.more_fragments, flags.contains('+'), "{description}");
        let protocol = field(description, "proto");
        assert_eq!(header.protocol.to_string(), protocol.split(' ').next().unwrap(), "{description}");
        assert_eq!(payload.len(), header.payload_length());
        assert_eq!(header.header_length() + payload.len(), header.total_length as usize);
        // The header written back is the kernel's, checksum included.
        assert_eq!(encode(&header), bytes[..header.header_length()], "{description}");
    }
}

#[test]
fn decodes_record_route_options() {
    // `ping -R`: No Operation, then Record Route (RFC 791 §3.1, type 7)
    // with room for nine addresses.
    let (description, bytes) =
        packets().into_iter().find(|(description, _)| description.contains("options (NOP,RR")).unwrap();
    let (header, _) = IPv4Header::decode(&bytes).unwrap();
    assert_eq!(header.header_length(), 60, "{description}");
    let options: Vec<_> = header.options.iter().map(Result::unwrap).collect();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].kind, IPv4OptionKind::RECORD_ROUTE);
    assert!(!options[0].kind.is_copied());
    assert_eq!(options[0].kind.class(), 0);
    assert_eq!(options[0].kind.number(), 7);
    // The pointer and nine addresses, the first recorded.
    assert_eq!(options[0].data.len(), 1 + 9 * 4);
    assert_eq!(&options[0].data[1..5], &[192, 0, 2, 1]);
}

#[test]
fn option_kinds() {
    // RFC 791 §3.1: copied flag, class and number of the defined options.
    let cases = [
        (IPv4OptionKind::END_OF_OPTIONS, false, 0, 0),
        (IPv4OptionKind::NO_OPERATION, false, 0, 1),
        (IPv4OptionKind::SECURITY, true, 0, 2),
        (IPv4OptionKind::LOOSE_SOURCE_ROUTE, true, 0, 3),
        (IPv4OptionKind::STRICT_SOURCE_ROUTE, true, 0, 9),
        (IPv4OptionKind::RECORD_ROUTE, false, 0, 7),
        (IPv4OptionKind::STREAM_IDENTIFIER, true, 0, 8),
        (IPv4OptionKind::TIMESTAMP, false, 2, 4),
        (IPv4OptionKind::ROUTER_ALERT, true, 0, 20),
    ];
    for (kind, copied, class, number) in cases {
        assert_eq!((kind.is_copied(), kind.class(), kind.number()), (copied, class, number), "{kind:?}");
    }
}

#[test]
fn options_round_trip_and_pad() {
    let mut options = IPv4Options::new();
    options.push(IPv4OptionKind::NO_OPERATION, &[]).unwrap();
    options.push(IPv4OptionKind::ROUTER_ALERT, &[0, 0]).unwrap();
    assert_eq!(options.as_bytes(), &[1, 148, 4, 0, 0]);
    assert_eq!(options.padded_length(), 8);
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(224, 0, 0, 22), IPProtocol::IGMP, 8).unwrap();
    header.options = options;
    header.set_payload_length(8).unwrap();
    let mut bytes = encode(&header);
    // The header length counts 32-bit words; the padding is End of Option List.
    assert_eq!(bytes[0], 0x47);
    assert_eq!(&bytes[20..28], &[1, 148, 4, 0, 0, 0, 0, 0]);
    assert!(InternetChecksum::verify(&bytes));
    bytes.extend_from_slice(&[0; 8]);
    let (decoded, payload) = IPv4Header::decode(&bytes).unwrap();
    assert_eq!(payload.len(), 8);
    assert_eq!(
        decoded.options.iter().map(Result::unwrap).map(|option| option.kind).collect::<Vec<_>>(),
        [IPv4OptionKind::ROUTER_ALERT]
    );
    // More than 40 bytes, and data for a single-octet option.
    let mut options = IPv4Options::new();
    assert!(options.push(IPv4OptionKind(0x99), &[0; 38]).is_ok());
    assert_eq!(options.push(IPv4OptionKind::NO_OPERATION, &[]), Err(IPv4Error::Option));
    assert_eq!(IPv4Options::new().push(IPv4OptionKind::NO_OPERATION, &[1]), Err(IPv4Error::Option));
}

#[test]
fn malformed_options_are_refused() {
    // RFC 791 §3.1: the option-length counts the type and length octets.
    for options in [&[7u8][..], &[7, 1], &[7, 0, 0, 0], &[7, 5, 4, 0], &[1, 1, 1, 68]] {
        assert_eq!(IPv4Options::decode(options), Err(IPv4Error::Option), "{options:?}");
    }
    // Anything after the End of Option List is padding.
    assert!(IPv4Options::decode(&[1, 0, 7, 9]).is_ok());
    assert!(IPv4Options::decode(&[7, 3, 4, 0]).is_ok());
}

fn sample() -> Vec<u8> {
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 4).unwrap();
    let mut bytes = encode(&header);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    bytes
}

#[test]
fn invalid_headers_are_refused() {
    let bytes = sample();
    assert!(IPv4Header::decode(&bytes).is_ok());
    assert_eq!(IPv4Header::decode(&bytes[..19]), Err(IPv4Error::Length));
    // The version must be 4.
    let mut other = bytes.clone();
    other[0] = 0x65;
    assert_eq!(IPv4Header::decode(&other), Err(IPv4Error::Version));
    // A header length below five words.
    let mut short = bytes.clone();
    short[0] = 0x44;
    assert_eq!(IPv4Header::decode(&short), Err(IPv4Error::Length));
    // A total length beyond the bytes, or below the header.
    let mut long = bytes.clone();
    long[3] = 25;
    assert_eq!(IPv4Header::decode(&long), Err(IPv4Error::Length));
    let mut below = bytes.clone();
    below[3] = 19;
    assert_eq!(IPv4Header::decode(&below), Err(IPv4Error::Length));
    // RFC 1122 §3.2.1.2: a wrong checksum.
    for index in [1, 4, 8, 9, 10, 15, 19] {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0x01;
        assert_eq!(IPv4Header::decode(&corrupted), Err(IPv4Error::Checksum), "byte {index}");
    }
    // Bytes after the total length (link padding) are not data.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0; 10]);
    assert_eq!(IPv4Header::decode(&padded).unwrap().1, &[1, 2, 3, 4]);
}

#[test]
fn reserved_flag_is_ignored_and_sent_as_zero() {
    let mut bytes = sample();
    bytes[6] |= 0x80;
    bytes[10..12].copy_from_slice(&[0, 0]);
    let checksum = InternetChecksum::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    let (header, _) = IPv4Header::decode(&bytes).unwrap();
    assert_eq!(encode(&header)[6] & 0x80, 0);
}

#[test]
fn fields_are_placed_as_rfc791_says() {
    let mut header =
        IPv4Header::new(IPv4Address::new(10, 1, 2, 3), IPv4Address::new(10, 4, 5, 6), IPProtocol::TCP, 100).unwrap();
    header.dscp = 46;
    header.ecn = 1;
    header.identification = 0xBEEF;
    header.dont_fragment = true;
    header.time_to_live = 17;
    let bytes = encode(&header);
    assert_eq!(bytes[0], 0x45);
    assert_eq!(bytes[1], 46 << 2 | 1);
    assert_eq!(&bytes[2..4], &120u16.to_be_bytes());
    assert_eq!(&bytes[4..6], &[0xBE, 0xEF]);
    assert_eq!(&bytes[6..8], &[0x40, 0x00]);
    assert_eq!(bytes[8], 17);
    assert_eq!(bytes[9], 6);
    assert_eq!(&bytes[12..20], &[10, 1, 2, 3, 10, 4, 5, 6]);
    assert!(InternetChecksum::verify(&bytes));
    header.more_fragments = true;
    header.dont_fragment = false;
    header.fragment_offset = 0x1ABC;
    assert_eq!(&encode(&header)[6..8], &[0x3A, 0xBC]);
    assert_eq!(
        IPv4Header::new(IPv4Address::LOOPBACK, IPv4Address::LOOPBACK, IPProtocol::UDP, 65516),
        Err(IPv4Error::Length)
    );
    assert!(IPv4Header::new(IPv4Address::LOOPBACK, IPv4Address::LOOPBACK, IPProtocol::UDP, 65515).is_ok());
}

/// The fragmented echo requests of the capture, by identification.
fn fragmented() -> Vec<Vec<(IPv4Header, Vec<u8>)>> {
    let mut datagrams: Vec<Vec<(IPv4Header, Vec<u8>)>> = Vec::new();
    for (_, bytes) in packets() {
        let (header, payload) = IPv4Header::decode(&bytes).unwrap();
        if !header.is_fragment() {
            continue;
        }
        match datagrams.iter_mut().find(|fragments| fragments[0].0.identification == header.identification) {
            Some(fragments) => fragments.push((header, payload.to_vec())),
            None => datagrams.push(vec![(header, payload.to_vec())]),
        }
    }
    datagrams
}

#[test]
fn reassembles_linux_fragments_in_any_order() {
    let datagrams = fragmented();
    assert_eq!(datagrams.len(), 2);
    for fragments in &datagrams {
        assert_eq!(fragments.len(), 3);
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [0, 2, 1]] {
            let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
            let mut result = None;
            for (step, &index) in order.iter().enumerate() {
                let (header, payload) = &fragments[index];
                let output = reassembler.receive(header, payload, Instant::from_nanos(step as u64)).unwrap();
                assert_eq!(output.is_some(), step == 2);
                result = result.or(output);
            }
            let (header, data) = result.unwrap();
            // `ping -s 3000`: an ICMP message of 3,008 bytes whose checksum holds.
            assert_eq!(data.len(), 3008);
            assert!(InternetChecksum::verify(&data));
            assert!(!header.is_fragment());
            assert_eq!(header.total_length, 3028);
            assert_eq!(header.identification, fragments[0].0.identification);
            assert!(reassembler.table.is_empty() && reassembler.table.buffered == 0);
        }
    }
}

#[test]
fn fragments_as_linux_does() {
    for fragments in fragmented() {
        let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
        let mut whole = None;
        for (header, payload) in &fragments {
            whole = whole.or(reassembler.receive(header, payload, Instant::ZERO).unwrap());
        }
        let (header, data) = whole.unwrap();
        let ours: Vec<_> = IPv4Fragmenter::new(header, &data, 1500).unwrap().collect();
        assert_eq!(ours.len(), fragments.len());
        for ((header, payload), (theirs, data)) in ours.iter().zip(&fragments) {
            assert_eq!(encode(header), encode(theirs));
            assert_eq!(payload, data);
        }
    }
}

#[test]
fn fragmentation_rules() {
    let data: Vec<u8> = (0..1000u32).map(|index| index as u8).collect();
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, data.len())
            .unwrap();
    // A datagram that fits is one fragment.
    let single: Vec<_> = IPv4Fragmenter::new(header, &data, 1020).unwrap().collect();
    assert_eq!(single.len(), 1);
    assert!(!single[0].0.is_fragment());
    // RFC 791 §3.2: every part but the last is a multiple of 8 bytes.
    for mtu in [68, 100, 576, 1019] {
        let fragments: Vec<_> = IPv4Fragmenter::new(header, &data, mtu).unwrap().collect();
        let mut offset = 0;
        for (index, (fragment, part)) in fragments.iter().enumerate() {
            let last = index == fragments.len() - 1;
            assert!(fragment.total_length as usize <= mtu);
            assert_eq!(fragment.total_length as usize, 20 + part.len());
            assert_eq!(fragment.fragment_offset as usize * 8, offset);
            assert_eq!(fragment.more_fragments, !last);
            assert!(last || part.len() % 8 == 0);
            assert_eq!(*part, &data[offset..offset + part.len()]);
            offset += part.len();
        }
        assert_eq!(offset, data.len());
    }
    // Don't Fragment, and an MTU that cannot carry 8 bytes.
    let mut forbidden = header;
    forbidden.dont_fragment = true;
    assert_eq!(IPv4Fragmenter::new(forbidden, &data, 576).err(), Some(IPv4Error::Fragment));
    assert!(IPv4Fragmenter::new(forbidden, &data, 1020).is_ok());
    assert_eq!(IPv4Fragmenter::new(header, &data, 27).err(), Some(IPv4Error::Fragment));
    assert!(IPv4Fragmenter::new(header, &data, 28).is_ok());
}

#[test]
fn fragmentation_copies_only_copied_options() {
    let data = [0x5Au8; 200];
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.options.push(IPv4OptionKind::RECORD_ROUTE, &[4, 0, 0, 0, 0]).unwrap();
    header.options.push(IPv4OptionKind::LOOSE_SOURCE_ROUTE, &[4, 192, 0, 2, 9]).unwrap();
    header.set_payload_length(data.len()).unwrap();
    let fragments: Vec<_> = IPv4Fragmenter::new(header, &data, 100).unwrap().collect();
    assert!(fragments.len() > 2);
    let kinds = |header: &IPv4Header| header.options.iter().map(|option| option.unwrap().kind).collect::<Vec<_>>();
    assert_eq!(kinds(&fragments[0].0), [IPv4OptionKind::RECORD_ROUTE, IPv4OptionKind::LOOSE_SOURCE_ROUTE]);
    for (fragment, _) in &fragments[1..] {
        assert_eq!(kinds(fragment), [IPv4OptionKind::LOOSE_SOURCE_ROUTE]);
    }
    // The fragments reassemble into the datagram with the first fragment's options.
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    let mut whole = None;
    for (fragment, part) in fragments.iter().rev() {
        whole = whole.or(reassembler.receive(fragment, part, Instant::ZERO).unwrap());
    }
    let (reassembled, bytes) = whole.unwrap();
    assert_eq!(bytes, data);
    assert_eq!(kinds(&reassembled), kinds(&header));
    assert_eq!(reassembled.total_length, header.total_length);
}

#[test]
fn refragments_fragments() {
    // A fragment fragmented again keeps its offsets and its More Fragments flag.
    let data = [9u8; 400];
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, data.len())
            .unwrap();
    let first: Vec<_> = IPv4Fragmenter::new(header, &data, 220).unwrap().collect();
    let mut again = Vec::new();
    for (fragment, part) in &first {
        again.extend(IPv4Fragmenter::new(*fragment, part, 100).unwrap());
    }
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    let mut whole = None;
    for (fragment, part) in &again {
        whole = whole.or(reassembler.receive(fragment, part, Instant::ZERO).unwrap());
    }
    assert_eq!(whole.unwrap().1, data);
    assert!(again.last().is_some_and(|(fragment, _)| !fragment.more_fragments));
}

#[test]
fn reassembly_refuses_overlaps_and_ignores_duplicates() {
    let data = [3u8; 64];
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, data.len())
            .unwrap();
    let fragments: Vec<_> = IPv4Fragmenter::new(header, &data, 44).unwrap().collect();
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    assert_eq!(reassembler.receive(&fragments[0].0, fragments[0].1, Instant::ZERO), Ok(None));
    assert_eq!(reassembler.receive(&fragments[0].0, fragments[0].1, Instant::ZERO), Ok(None));
    // A fragment that overlaps the first abandons the datagram: its bytes are
    // released, and its fragments, those not yet received too, are dropped
    // until its deadline (RFC 5722 §4).
    let mut overlapping = fragments[1].0;
    overlapping.fragment_offset -= 1;
    assert_eq!(
        reassembler.receive(&overlapping, fragments[1].1, Instant::ZERO),
        Err(IPv4Error::Reassembly(IPError::Overlap))
    );
    assert_eq!(reassembler.table.buffered, 0);
    for (fragment, part) in &fragments {
        assert_eq!(reassembler.receive(fragment, part, Instant::ZERO), Err(IPv4Error::Reassembly(IPError::Overlap)));
    }
    let (_, abandoned) = reassembler.expire(Instant::ZERO.saturating_add(reassembler.config.timeout)).unwrap();
    assert!(abandoned.abandoned && abandoned.first.is_none());
    // After the deadline, the fragments make a new datagram.
    let later = Instant::ZERO.saturating_add(reassembler.config.timeout + Duration::from_secs(1));
    let mut whole = None;
    for (fragment, part) in &fragments {
        whole = whole.or(reassembler.receive(fragment, part, later).unwrap());
    }
    assert_eq!(whole.unwrap().1, data);
    // A fragment but the last must carry a multiple of 8 bytes.
    assert_eq!(reassembler.receive(&fragments[0].0, &fragments[0].1[..20], Instant::ZERO), Err(IPv4Error::Length));
}

#[test]
fn reassembly_times_out_and_reports_the_first_fragment() {
    let data = [3u8; 64];
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, data.len())
            .unwrap();
    let fragments: Vec<_> = IPv4Fragmenter::new(header, &data, 44).unwrap().collect();
    let config = IPv4ReassemblyConfig::default();
    // RFC 1122 §3.3.2 recommends 60 to 120 seconds.
    assert!(config.timeout >= Duration::from_secs(60) && config.timeout <= Duration::from_secs(120));
    assert!(config.maximum_length >= 576);
    let mut reassembler = IPv4Reassembler::new(config);
    let start = Instant::from_nanos(1_000);
    reassembler.receive(&fragments[1].0, fragments[1].1, start).unwrap();
    reassembler.receive(&fragments[0].0, fragments[0].1, start.saturating_add(Duration::from_secs(10))).unwrap();
    // The deadline runs from the first-arriving fragment.
    assert_eq!(reassembler.poll_timeout(), Some(start.saturating_add(config.timeout)));
    assert_eq!(reassembler.expire(start.saturating_add(Duration::from_secs(59))), None);
    let (key, reassembly) = reassembler.expire(start.saturating_add(config.timeout)).unwrap();
    assert_eq!(key.identification, header.identification);
    assert_eq!(reassembly.first.map(|first| first.fragment_offset), Some(0));
    assert_eq!(&reassembly.buffer.data[..8], &data[..8]);
    assert!(reassembler.table.is_empty() && reassembler.table.buffered == 0);
    assert_eq!(reassembler.poll_timeout(), None);
}

#[test]
fn reassembly_limits_drop_the_oldest_datagrams() {
    let data = [3u8; 64];
    let config = IPv4ReassemblyConfig { maximum_datagrams: 2, ..IPv4ReassemblyConfig::default() };
    let fragment = |identification: u16| {
        let mut header =
            IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 16)
                .unwrap();
        header.identification = identification;
        header.more_fragments = true;
        header
    };
    let at = |seconds: u64| Instant::ZERO.saturating_add(Duration::from_secs(seconds));
    let identifications = |reassembler: &IPv4Reassembler| {
        reassembler.table.entries.keys().map(|key| key.identification).collect::<Vec<_>>()
    };
    // A new datagram beyond the limit drops the one with the earliest deadline.
    let mut reassembler = IPv4Reassembler::new(config);
    assert_eq!(reassembler.receive(&fragment(1), &data[..16], at(2)), Ok(None));
    assert_eq!(reassembler.receive(&fragment(2), &data[..16], at(1)), Ok(None));
    assert_eq!(reassembler.receive(&fragment(3), &data[..16], at(3)), Ok(None));
    assert_eq!(identifications(&reassembler), [1, 3]);
    // So do bytes beyond the limit, but a fragment that alone exceeds it fails. The limit holds
    // one 24-byte fragment with its record and the data, but not the record, of another.
    let limit = 24 + IPFragmentBuffer::FRAGMENT_RECORD + 24;
    let config = IPv4ReassemblyConfig { maximum_buffered: limit, ..IPv4ReassemblyConfig::default() };
    let mut reassembler = IPv4Reassembler::new(config);
    assert_eq!(reassembler.receive(&fragment(1), &data[..24], at(1)), Ok(None));
    assert_eq!(reassembler.receive(&fragment(2), &data[..24], at(2)), Ok(None));
    assert_eq!(identifications(&reassembler), [2]);
    assert!(reassembler.table.buffered <= limit);
    assert_eq!(reassembler.receive(&fragment(3), &data[..64], at(3)), Err(IPv4Error::Limit));
    // A datagram beyond the largest to reassemble.
    let config = IPv4ReassemblyConfig { maximum_length: 576, ..IPv4ReassemblyConfig::default() };
    let mut reassembler = IPv4Reassembler::new(config);
    let mut late = fragment(4);
    late.fragment_offset = 70;
    assert_eq!(reassembler.receive(&late, &data[..16], Instant::ZERO), Err(IPv4Error::Reassembly(IPError::Length)));
    assert!(reassembler.table.is_empty());
    // A limit below the smallest header reassembles nothing, without failing otherwise.
    let config = IPv4ReassemblyConfig { maximum_length: 10, ..IPv4ReassemblyConfig::default() };
    let mut reassembler = IPv4Reassembler::new(config);
    assert_eq!(
        reassembler.receive(&fragment(5), &data[..8], Instant::ZERO),
        Err(IPv4Error::Reassembly(IPError::Length))
    );
    // The accounting covers what is held.
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    reassembler.receive(&fragment(6), &data[..16], Instant::ZERO).unwrap();
    let held: usize = reassembler.table.entries.values().map(|reassembly| reassembly.memory()).sum();
    assert_eq!(reassembler.table.buffered, held);
    assert!(held >= 16);
}

#[test]
fn reassembly_adds_no_bytes_for_empty_fragments() {
    // A fragment without data far beyond the others reserves nothing: the
    // datagram is exactly its fragments' data.
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.more_fragments = true;
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    let far = IPv4Header { fragment_offset: 125, ..header };
    assert_eq!(reassembler.receive(&far, &[], Instant::ZERO), Ok(None));
    assert_eq!(reassembler.receive(&header, &[1; 8], Instant::ZERO), Ok(None));
    let last = IPv4Header { fragment_offset: 1, more_fragments: false, ..header };
    let (whole, data) = reassembler.receive(&last, &[2; 8], Instant::ZERO).unwrap().unwrap();
    assert_eq!(data, [[1u8; 8], [2; 8]].concat());
    assert_eq!(whole.total_length, 36);
}

#[test]
fn reassembly_limits_drop_nothing_for_a_fragment_that_cannot_fit() {
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.more_fragments = true;
    let config = IPv4ReassemblyConfig { maximum_buffered: 2000, ..IPv4ReassemblyConfig::default() };
    let mut reassembler = IPv4Reassembler::new(config);
    for identification in 1..=3 {
        let fragment = IPv4Header { identification, ..header };
        assert_eq!(reassembler.receive(&fragment, &[0; 8], Instant::ZERO), Ok(None));
    }
    // Beyond the bytes allowed even alone: refused, the others kept.
    let far = IPv4Header { identification: 4, fragment_offset: 250, ..header };
    assert_eq!(reassembler.receive(&far, &[0; 8], Instant::ZERO), Err(IPv4Error::Limit));
    assert_eq!(reassembler.table.len(), 3);
    // A fragment that fails its own checks drops nothing either.
    let beyond = IPv4Header { identification: 5, fragment_offset: 9000, ..header };
    assert!(reassembler.receive(&beyond, &[0; 8], Instant::ZERO).is_err());
    assert_eq!(reassembler.table.len(), 3);
}

#[test]
fn reassembly_byte_limits_keep_abandoned_datagrams() {
    // An abandoned datagram holds no bytes: making room for bytes does not
    // drop it, so its fragments stay refused until its deadline (RFC 5722 §4).
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.more_fragments = true;
    // Room for one 48-byte fragment with its record and the data, but not the record, of another.
    let limit = 48 + IPFragmentBuffer::FRAGMENT_RECORD + 48;
    let config = IPv4ReassemblyConfig { maximum_buffered: limit, ..IPv4ReassemblyConfig::default() };
    let mut reassembler = IPv4Reassembler::new(config);
    let first = IPv4Header { identification: 1, ..header };
    reassembler.receive(&first, &[0; 16], Instant::ZERO).unwrap();
    let overlapping = IPv4Header { identification: 1, fragment_offset: 1, ..header };
    assert!(reassembler.receive(&overlapping, &[0; 16], Instant::ZERO).is_err());
    let second = IPv4Header { identification: 2, ..header };
    reassembler.receive(&second, &[0; 48], Instant::from_nanos(1)).unwrap();
    let third = IPv4Header { identification: 3, ..header };
    reassembler.receive(&third, &[0; 48], Instant::from_nanos(2)).unwrap();
    let identifications: Vec<u16> = reassembler.table.entries.keys().map(|key| key.identification).collect();
    assert_eq!(identifications, [1, 3]);
    assert_eq!(
        reassembler.receive(&first, &[0; 16], Instant::from_nanos(3)),
        Err(IPv4Error::Reassembly(IPError::Overlap))
    );
}

#[test]
fn reassembly_refuses_fragments_after_the_deadline() {
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.more_fragments = true;
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    assert_eq!(reassembler.receive(&header, &[1; 8], Instant::ZERO), Ok(None));
    let deadline = reassembler.poll_timeout().unwrap();
    let last = IPv4Header { fragment_offset: 1, more_fragments: false, ..header };
    // RFC 1122 §3.3.2: the datagram is given up at its deadline.
    assert_eq!(reassembler.receive(&last, &[2; 8], deadline), Err(IPv4Error::Expired));
    assert!(reassembler.expire(deadline).is_some());
    assert_eq!(reassembler.receive(&last, &[2; 8], deadline), Ok(None));
}

#[test]
fn reassembly_keeps_the_first_header_received() {
    let data = [3u8; 32];
    let header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, data.len())
            .unwrap();
    let fragments: Vec<_> = IPv4Fragmenter::new(header, &data, 36).unwrap().collect();
    let mut reassembler = IPv4Reassembler::new(IPv4ReassemblyConfig::default());
    reassembler.receive(&fragments[0].0, fragments[0].1, Instant::ZERO).unwrap();
    let mut other = fragments[0].0;
    other.time_to_live = 1;
    assert_eq!(reassembler.receive(&other, fragments[0].1, Instant::ZERO), Ok(None));
    let mut whole = None;
    for (fragment, part) in &fragments[1..] {
        whole = whole.or(reassembler.receive(fragment, part, Instant::ZERO).unwrap());
    }
    assert_eq!(whole.unwrap().0.time_to_live, header.time_to_live);
}

#[test]
fn options_longer_than_the_field_do_not_overrun() {
    let mut header =
        IPv4Header::new(IPv4Address::new(192, 0, 2, 1), IPv4Address::new(192, 0, 2, 2), IPProtocol::UDP, 0).unwrap();
    header.options.length = 200;
    assert_eq!(header.options.as_bytes().len(), 40);
    assert_eq!(header.header_length(), 60);
    assert_eq!(encode(&header).len(), 60);
}

#[test]
fn truncated_datagrams_as_errors_quote_them() {
    // RFC 792: an error quotes the header and the start of the data.
    let bytes = sample();
    assert_eq!(IPv4Header::decode_truncated(&bytes[..22]).map(|(_, data)| data.len()), Ok(2));
    assert_eq!(IPv4Header::decode(&bytes[..22]), Err(IPv4Error::Length));
    assert_eq!(IPv4Header::decode_truncated(&bytes), IPv4Header::decode(&bytes));
    // The header itself must be whole and right.
    assert_eq!(IPv4Header::decode_truncated(&bytes[..19]), Err(IPv4Error::Length));
    let mut corrupted = bytes.clone();
    corrupted[8] ^= 1;
    assert_eq!(IPv4Header::decode_truncated(&corrupted[..22]), Err(IPv4Error::Checksum));
}
