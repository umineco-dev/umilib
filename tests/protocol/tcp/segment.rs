//! Segments, options and sequence numbers.

use umilib::bytes::Buffer;
use umilib::protocol::ip::{IPAddress, IPv4Address};
use umilib::protocol::tcp::{
    TCPError, TCPFlags, TCPHeader, TCPOption, TCPOptionKind, TCPOptionSet, TCPOptions, TCPSACKBlock, TCPSegment,
    TCPSequence, TCPTimestamps,
};

use super::packets;

/// The value after `key` in tcpdump's description, as text.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let start = text.find(key)? + key.len();
    let rest = &text[start..];
    let end = rest.find([',', ']', ' ']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The flags of tcpdump's "Flags [S.E]" notation.
fn flags(text: &str) -> TCPFlags {
    let letters = field(text, "Flags [").unwrap();
    let mut flags = TCPFlags::NONE;
    for letter in letters.chars() {
        flags = flags.union(match letter {
            'F' => TCPFlags::FIN,
            'S' => TCPFlags::SYN,
            'R' => TCPFlags::RST,
            'P' => TCPFlags::PSH,
            '.' => TCPFlags::ACK,
            'U' => TCPFlags::URG,
            'E' => TCPFlags::ECE,
            'W' => TCPFlags::CWR,
            _ => panic!("{letter}"),
        });
    }
    flags
}

/// The checksum of RFC 9293 §3.1 computed independently.
fn reference_checksum(source: IPAddress, destination: IPAddress, segment: &[u8]) -> u16 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(source.octets());
    bytes.extend_from_slice(destination.octets());
    match source {
        IPAddress::V4(_) => bytes.extend_from_slice(&[0, 6, (segment.len() >> 8) as u8, segment.len() as u8]),
        IPAddress::V6(_) => {
            bytes.extend_from_slice(&(segment.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 6]);
        }
    }
    bytes.extend_from_slice(&segment[..16]);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&segment[18..]);
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum: u32 = bytes.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn linux_segments() {
    let packets = packets();
    assert_eq!(packets.len(), 241);
    for packet in &packets {
        // The TCP line of tcpdump's description, after the link and IP lines.
        let line = packet.description.lines().find(|line| line.contains("Flags [")).unwrap();
        let text = &line[line.find("Flags [").unwrap()..];
        let segment = TCPSegment::decode(&packet.segment, packet.source, packet.destination)
            .unwrap_or_else(|error| panic!("{error}: {text}"));
        let header = TCPHeader::decode(&packet.segment).unwrap();
        assert_eq!(header.checksum, reference_checksum(packet.source, packet.destination, &packet.segment), "{text}");
        assert_eq!(segment.flags, flags(text), "{text}");
        assert_eq!(segment.window.to_string(), field(text, "win ").unwrap(), "{text}");
        assert_eq!(segment.payload.len().to_string(), field(text, "length ").unwrap_or("0"), "{text}");
        if segment.flags.contains(TCPFlags::SYN) {
            assert_eq!(segment.sequence.0.to_string(), field(text, "seq ").unwrap(), "{text}");
        }
        if segment.flags.contains(TCPFlags::URG) {
            assert_eq!(segment.urgent_pointer.to_string(), field(text, "urg ").unwrap(), "{text}");
        }
        // The options this crate understands are tcpdump's, and written back
        // they are the kernel's bytes, in the kernel's layout.
        let options = segment.option_set().unwrap();
        assert_eq!(options.mss.map(|mss| mss.to_string()).as_deref(), field(text, "mss "), "{text}");
        assert_eq!(options.window_scale.map(|scale| scale.to_string()).as_deref(), field(text, "wscale "), "{text}");
        assert_eq!(options.sack_permitted, text.contains("sackOK"), "{text}");
        let timestamps = options.timestamps.map(|stamps| (stamps.value.to_string(), stamps.echo_reply.to_string()));
        assert_eq!(
            timestamps,
            field(text, "TS val ").map(|value| (value.to_string(), field(text, "ecr ").unwrap().to_string())),
            "{text}"
        );
        assert_eq!(options.sack().len().to_string(), field(text, "sack ").unwrap_or("0"), "{text}");
        let mut written = Buffer::new();
        options.encode(&mut written).unwrap();
        assert_eq!(written.as_slice(), segment.options, "{text}");
        assert_eq!(options.length(), segment.options.len());
        // The segment written back is the kernel's.
        let mut bytes = Buffer::new();
        segment.encode(packet.source, packet.destination, &mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), &packet.segment[..], "{text}");
        assert_eq!(segment.length(), packet.segment.len());
    }
    // The capture holds what the tests rely on.
    let count = |text: &str| packets.iter().filter(|packet| packet.description.contains(text)).count();
    assert!(count("sack ") >= 10 && count("win 0,") >= 3 && count("Flags [SEW]") == 1 && count("Flags [S.E]") == 1);
    assert!(count("Flags [R.]") == 1 && count("Flags [P.U]") == 1);
}

#[test]
fn segment_checks() {
    // RFC 9293 §3.1: the data offset is at least 5 words and within the
    // segment; the checksum covers the pseudo-header (MUST-2, MUST-3).
    let (source, destination) =
        (IPAddress::V4(IPv4Address::new(192, 0, 2, 1)), IPAddress::V4(IPv4Address::new(192, 0, 2, 2)));
    let options = [2, 4, 5, 0xB4];
    let segment = TCPSegment {
        source_port: 40000,
        destination_port: 80,
        sequence: TCPSequence(1000),
        acknowledgment: TCPSequence(0),
        flags: TCPFlags::SYN,
        window: 65535,
        urgent_pointer: 0,
        options: &options,
        payload: &[],
    };
    let mut bytes = Buffer::new();
    segment.encode(source, destination, &mut bytes).unwrap();
    let bytes = bytes.into_vec();
    assert_eq!(bytes[12], 6 << 4);
    assert_eq!(TCPSegment::decode(&bytes, source, destination), Ok(segment));
    assert_eq!(TCPSegment::decode(&bytes[..19], source, destination), Err(TCPError::Length));
    for offset in [0u8, 4, 7] {
        let mut changed = bytes.clone();
        changed[12] = offset << 4;
        assert_eq!(TCPSegment::decode(&changed, source, destination).err(), Some(TCPError::Length), "{offset}");
    }
    let mut wrong = bytes.clone();
    wrong[0] ^= 1;
    assert_eq!(TCPSegment::decode(&wrong, source, destination), Err(TCPError::Checksum));
    let other = IPAddress::V4(IPv4Address::new(192, 0, 2, 3));
    assert_eq!(TCPSegment::decode(&bytes, source, other), Err(TCPError::Checksum));
    // The reserved bits are sent as zero and ignored when received.
    let mut reserved = bytes.clone();
    reserved[12] |= 0x0F;
    let mut checksum = umilib::protocol::ip::IPPseudoHeader::new(
        source,
        destination,
        umilib::protocol::ip::IPProtocol::TCP,
        reserved.len(),
    )
    .unwrap()
    .checksum();
    reserved[16..18].copy_from_slice(&[0, 0]);
    checksum.update(&reserved);
    reserved[16..18].copy_from_slice(&checksum.finish().to_be_bytes());
    assert_eq!(TCPSegment::decode(&reserved, source, destination), Ok(segment));
    assert_eq!(TCPHeader::decode(&reserved).unwrap().reserved, 0x0F);
    // Options are padded with zeros to a multiple of 4 (MUST-69); more than 40 bytes do not fit.
    let odd = TCPSegment { options: &[1, 1, 1], ..segment };
    let mut padded = Buffer::new();
    odd.encode(source, destination, &mut padded).unwrap();
    assert_eq!(&padded.as_slice()[20..24], &[1, 1, 1, 0]);
    let long = [1u8; 41];
    assert_eq!(
        TCPSegment { options: &long, ..segment }.encode(source, destination, &mut Buffer::new()),
        Err(TCPError::Option)
    );
    // SEG.LEN counts SYN and FIN (RFC 9293 §3.4).
    assert_eq!(segment.sequence_length(), 1);
    assert_eq!(
        TCPSegment { flags: TCPFlags::FIN.union(TCPFlags::ACK), payload: b"abc", ..segment }.sequence_length(),
        4
    );
}

#[test]
fn options() {
    // RFC 9293 §3.2: End of Option List ends the options; No-Operation is
    // one byte; every other option has a length of at least 2 (MUST-68), an
    // illegal one is an error (MUST-7); options need not be aligned (MUST-64).
    let bytes = [1, 2, 4, 5, 0xB4, 3, 3, 7, 0, 9, 9];
    let parsed: Vec<_> = TCPOptions::new(&bytes).map(Result::unwrap).collect();
    assert_eq!(
        parsed,
        [
            TCPOption { kind: TCPOptionKind::NOP, data: &[] },
            TCPOption { kind: TCPOptionKind::MSS, data: &[5, 0xB4] },
            TCPOption { kind: TCPOptionKind::WINDOW_SCALE, data: &[7] },
        ]
    );
    let set = TCPOptionSet::decode(&bytes).unwrap();
    assert_eq!((set.mss, set.window_scale), (Some(1460), Some(7)));
    for illegal in [&[2u8][..], &[2, 0], &[2, 1], &[2, 5, 5, 0xB4], &[200, 4, 0]] {
        assert_eq!(TCPOptions::check(illegal), Err(TCPError::Option), "{illegal:?}");
        assert_eq!(TCPOptionSet::decode(illegal), Err(TCPError::Option), "{illegal:?}");
    }
    // Unknown options are ignored (MUST-6), as are known ones of another size.
    let ignored = TCPOptionSet::decode(&[200, 4, 1, 2, 2, 3, 5, 3, 2, 4, 3, 0]).unwrap();
    assert_eq!(ignored, TCPOptionSet::default());
    // RFC 7323 §2.3: a shift count above 14 is read as 14.
    assert_eq!(TCPOptionSet::decode(&[3, 3, 15]).unwrap().window_scale, Some(14));
    let mut out = Buffer::new();
    assert_eq!(
        TCPOptionSet { window_scale: Some(15), ..TCPOptionSet::default() }.encode(&mut out),
        Err(TCPError::Option)
    );
    // RFC 2018 §3: SACK blocks of 8 bytes; RFC 7323 §3.2: Timestamps of 10.
    let blocks = [
        TCPSACKBlock { left: TCPSequence(100), right: TCPSequence(200) },
        TCPSACKBlock { left: TCPSequence(300), right: TCPSequence(400) },
        TCPSACKBlock { left: TCPSequence(500), right: TCPSequence(600) },
    ];
    let full = TCPOptionSet { timestamps: Some(TCPTimestamps { value: 7, echo_reply: 9 }), ..TCPOptionSet::default() }
        .with_sack(&blocks);
    let mut written = Buffer::new();
    full.encode(&mut written).unwrap();
    assert_eq!(written.len(), 12 + 4 + 24);
    assert_eq!(TCPOptionSet::decode(written.as_slice()), Ok(full));
    let crowded = full.with_sack(&[blocks[0]; 4]);
    assert_eq!(crowded.encode(&mut Buffer::new()), Err(TCPError::Option));
    let mut no_timestamps = Buffer::new();
    TCPOptionSet::default().with_sack(&[blocks[0]; 4]).encode(&mut no_timestamps).unwrap();
    assert_eq!(no_timestamps.len(), 36);
    let mut raw = Buffer::new();
    TCPOption::encode(TCPOptionKind(200), &[1, 2], &mut raw).unwrap();
    TCPOption::encode(TCPOptionKind::NOP, &[], &mut raw).unwrap();
    assert_eq!(raw.as_slice(), &[200, 4, 1, 2, 1]);
    assert_eq!(TCPOption::encode(TCPOptionKind::NOP, &[1], &mut raw), Err(TCPError::Option));
}

#[test]
fn sequence_numbers() {
    // RFC 9293 §3.4: comparisons modulo 2^32.
    let a = TCPSequence(u32::MAX - 10);
    let b = a.add(20);
    assert_eq!(b, TCPSequence(9));
    assert!(a.is_before(b) && b.is_after(a) && !b.is_before(a));
    assert_eq!(b.distance(a), 20);
    assert_eq!(b.sub(20), a);
    assert!(TCPSequence(5).is_in(a, b) && !b.is_in(a, b) && a.is_in(a, b));
    assert_eq!(a.max(b), b);
    assert_eq!(a.min(b), a);
    assert!(a.is_at_or_before(a) && a.is_at_or_after(a));
    // Numbers 2^31 apart compare as the RFC's arithmetic leaves them.
    assert!(TCPSequence(0).is_before(TCPSequence(0x7FFF_FFFF)));
    assert!(TCPSequence(0x8000_0001).is_before(TCPSequence(0)));
}
