//! Variable-length integers, packet numbers, headers and frames (RFC 9000
//! §12.4, §16, §17, §19, Appendix A; RFC 9221 §4; RFC 8999).

use umilib::bytes::Reader;
use umilib::protocol::quic::{
    QUICACKFrame, QUICConnectionID, QUICECNCounts, QUICErrorCode, QUICFrame, QUICFrameType, QUICFrames, QUICHeader,
    QUICInvariantHeader, QUICLongHeader, QUICPacket, QUICPacketNumber, QUICPacketType, QUICRetry, QUICShortHeader,
    QUICStreamID, QUICVarint, QUICVersion, QUICVersionNegotiation,
};

use super::QUICVectors;
use crate::{RFC, Vectors};

fn varint(bytes: &[u8]) -> (u64, usize) {
    QUICVarint::read_with_length(&mut Reader::new(bytes)).unwrap()
}

fn encoded(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    QUICVarint::write(&mut out, value).unwrap();
    out
}

fn frame_error(bytes: &[u8]) -> QUICErrorCode {
    match QUICFrame::decode(&mut Reader::new(bytes)) {
        Err(umilib::protocol::quic::QUICError::Transport(error)) => error.code,
        other => panic!("{bytes:02x?}: {other:?}"),
    }
}

fn round_trip(frame: QUICFrame<'_>) {
    let mut out = Vec::new();
    frame.encode(&mut out).unwrap();
    assert_eq!(out.len(), frame.encoded_length());
    let mut reader = Reader::new(&out);
    assert_eq!(QUICFrame::decode(&mut reader).unwrap(), frame);
    assert!(reader.is_empty());
}

#[test]
fn variable_length_integers() {
    // RFC 9000 Appendix A.1.
    let text = Vectors::read(&QUICVectors::path(9000));
    assert!(text.contains("0xc2197c5eff14e88c decodes to"));
    assert_eq!(varint(&Vectors::hex("c2197c5eff14e88c")), (151_288_809_941_952_652, 8));
    assert_eq!(varint(&Vectors::hex("9d7f3e7d")), (494_878_333, 4));
    assert_eq!(varint(&Vectors::hex("7bbd")), (15_293, 2));
    assert_eq!(varint(&Vectors::hex("25")), (37, 1));
    assert_eq!(varint(&Vectors::hex("4025")), (37, 2));
    // The shortest encodings (RFC 9000 §16, Table 4).
    assert_eq!(encoded(151_288_809_941_952_652), Vectors::hex("c2197c5eff14e88c"));
    assert_eq!(encoded(494_878_333), Vectors::hex("9d7f3e7d"));
    assert_eq!(encoded(15_293), Vectors::hex("7bbd"));
    assert_eq!(encoded(37), Vectors::hex("25"));
    for (value, length) in [(0, 1), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (1_073_741_823, 4)] {
        assert_eq!(QUICVarint::length(value), Some(length), "{value}");
        assert_eq!(varint(&encoded(value)), (value, length));
    }
    assert_eq!(QUICVarint::length(QUICVarint::MAXIMUM), Some(8));
    assert_eq!(QUICVarint::length(QUICVarint::MAXIMUM + 1), None);
    assert!(QUICVarint::write(&mut Vec::new(), 1 << 62).is_err());
    let mut out = Vec::new();
    QUICVarint::write_with_length(&mut out, 37, 2).unwrap();
    assert_eq!(out, Vectors::hex("4025"));
    assert!(QUICVarint::write_with_length(&mut Vec::new(), 64, 1).is_err());
    assert!(QUICVarint::read(&mut Reader::new(&[0x40])).is_err());
}

#[test]
fn packet_numbers() {
    // RFC 9000 Appendix A.2: 16 bits for 0xac5c02, 24 for 0xace8fe, after 0xabe8b3.
    assert_eq!(QUICPacketNumber::length(0xAC_5C02, Some(0xAB_E8B3)), Some(2));
    assert_eq!(QUICPacketNumber::length(0xAC_E8FE, Some(0xAB_E8B3)), Some(3));
    // The whole number before any acknowledgment (RFC 9000 §17.1).
    assert_eq!(QUICPacketNumber::length(0, None), Some(1));
    assert_eq!(QUICPacketNumber::length(127, None), Some(1));
    assert_eq!(QUICPacketNumber::length(128, None), Some(2));
    assert_eq!(QUICPacketNumber::length(1 << 31, Some(0)), Some(4));
    assert_eq!(QUICPacketNumber::length((1 << 31) + 1, Some(0)), None);
    // RFC 9000 Appendix A.3.
    assert_eq!(QUICPacketNumber::decode(0x9B32, 2, Some(0xA82F_30EA)), 0xA82F_9B32);
    // Within half a window of the expected number, either way.
    assert_eq!(QUICPacketNumber::decode(0x00, 1, Some(0xFF)), 0x100);
    assert_eq!(QUICPacketNumber::decode(0xFF, 1, Some(0x100)), 0xFF);
    assert_eq!(QUICPacketNumber::decode(0x05, 1, None), 5);
    assert_eq!(QUICPacketNumber::decode(2, 4, None), 2);
    // Every number a sender encodes as A.2 asks is recovered (A.3).
    for (largest_acknowledged, number) in
        [(Some(0), 1u64), (Some(1000), 1200), (Some(0xAB_E8B3), 0xAC_E8FE), (None, 300)]
    {
        let length = QUICPacketNumber::length(number, largest_acknowledged).unwrap();
        let truncated = number & ((1 << (8 * length)) - 1);
        let largest_received = largest_acknowledged.or(Some(0));
        assert_eq!(QUICPacketNumber::decode(truncated, length, largest_received), number);
    }
}

#[test]
fn long_headers_of_rfc_9001() {
    // The unprotected header of RFC 9001 Appendix A.2.
    let header = QUICVectors::block(9001, "packet number of 2:");
    let mut datagram = header.clone();
    datagram.resize(header.len() - 4 + 1182, 0);
    let QUICPacket::Protected(packet) = QUICPacket::decode(&datagram, 0).unwrap() else { panic!() };
    let QUICHeader::Long(long) = packet.header else { panic!() };
    assert_eq!(long.packet_type, QUICPacketType::Initial);
    assert_eq!(long.version, QUICVersion::V1);
    assert_eq!(long.destination.as_slice(), Vectors::hex("8394c8f03e515708"));
    assert!(long.source.is_empty() && long.token.is_empty());
    assert_eq!(packet.number_offset, 18);
    assert_eq!(packet.length, datagram.len());
    assert!(packet.fixed);
    // Writing it back gives the same bytes.
    let mut out = Vec::new();
    let offset = packet.header.encode(true, 2, 4, 1182 - 4, &mut out).unwrap();
    assert_eq!((offset, out), (18, header));
    // The server's Initial of A.3: a 2-byte packet number.
    let header = QUICVectors::block(9001, "packet number encoding for a packet number of 1:");
    let mut datagram = header.clone();
    datagram.resize(header.len() - 2 + 0x75, 0);
    let QUICPacket::Protected(packet) = QUICPacket::decode(&datagram, 0).unwrap() else { panic!() };
    let QUICHeader::Long(long) = packet.header else { panic!() };
    assert_eq!(long.source.as_slice(), Vectors::hex("f067a5502a4262b5"));
    assert!(long.destination.is_empty());
    let mut out = Vec::new();
    packet.header.encode(true, 1, 2, 0x75 - 2, &mut out).unwrap();
    assert_eq!(out, header);
    // A Length past the datagram is discarded (RFC 9000 §12.2).
    assert!(QUICPacket::decode(&datagram[..datagram.len() - 1], 0).is_err());
}

#[test]
fn coalesced_packets() {
    // RFC 9000 §12.2: a long header's Length ends it, and what follows is
    // the next packet.
    let first = QUICHeader::Long(QUICLongHeader {
        packet_type: QUICPacketType::Handshake,
        version: QUICVersion::V1,
        destination: QUICConnectionID::new(&[1, 2, 3, 4]).unwrap(),
        source: QUICConnectionID::new(&[5]).unwrap(),
        token: &[],
    });
    let second = QUICHeader::Short(QUICShortHeader {
        destination: QUICConnectionID::new(&[1, 2, 3, 4]).unwrap(),
        spin: true,
        key_phase: false,
    });
    let mut datagram = Vec::new();
    first.encode(true, 7, 1, 20, &mut datagram).unwrap();
    datagram.extend_from_slice(&[0xAA; 20]);
    let end = datagram.len();
    second.encode(true, 9, 2, 0, &mut datagram).unwrap();
    datagram.extend_from_slice(&[0xBB; 20]);
    let packet = QUICPacket::decode(&datagram, 4).unwrap();
    assert_eq!(packet.length(&datagram), end);
    let QUICPacket::Protected(rest) = QUICPacket::decode(&datagram[end..], 4).unwrap() else { panic!() };
    let QUICHeader::Short(short) = rest.header else { panic!() };
    assert!(short.spin);
    assert_eq!(short.destination.as_slice(), &[1, 2, 3, 4]);
    assert_eq!((rest.number_offset, rest.length), (5, datagram.len() - end));
}

#[test]
fn connection_ids_above_twenty_bytes() {
    // RFC 9000 §17.2: a version 1 long header with a connection ID above 20
    // bytes is dropped; the invariants allow up to 255 (RFC 8999 §5.1).
    let mut datagram = vec![0xC0, 0, 0, 0, 1, 21];
    datagram.extend_from_slice(&[7; 21]);
    datagram.extend_from_slice(&[0, 0, 1, 0]);
    assert!(QUICPacket::decode(&datagram, 0).is_err());
    let QUICInvariantHeader::Long { destination, .. } = QUICInvariantHeader::decode(&datagram, 0).unwrap() else {
        panic!()
    };
    assert_eq!(destination.len(), 21);
    assert!(QUICConnectionID::new(&[0; 21]).is_none());
    assert_eq!(QUICConnectionID::new(&[0; 20]).unwrap().len(), 20);
}

#[test]
fn unknown_versions_and_version_negotiation() {
    // A packet of an unknown version is read only as far as the invariants
    // (RFC 8999 §5.1), and answered with the connection IDs swapped (RFC
    // 9000 §17.2.1) and the bit 0x40 set.
    let mut datagram = vec![0xC0, 0x1A, 0x2A, 0x3A, 0x4A, 3, 1, 2, 3, 2, 9, 8];
    datagram.resize(1200, 0);
    let QUICPacket::Unsupported(invariant) = QUICPacket::decode(&datagram, 0).unwrap() else { panic!() };
    let QUICInvariantHeader::Long { version, destination, source } = invariant else { panic!() };
    assert!(version.is_reserved() && !version.is_supported());
    let mut answer = Vec::new();
    let versions = [QUICVersion::V1, QUICVersion::V2, QUICVersion(0x0A0A_0A0A)];
    QUICVersionNegotiation::encode(destination, source, &versions, 0x15, &mut answer).unwrap();
    assert_eq!(answer[0] & 0xC0, 0xC0);
    assert_eq!(&answer[1..5], &[0, 0, 0, 0]);
    let QUICPacket::VersionNegotiation(negotiation) = QUICPacket::decode(&answer, 0).unwrap() else { panic!() };
    assert_eq!((negotiation.destination, negotiation.source), (&[9u8, 8][..], &[1u8, 2, 3][..]));
    assert_eq!(negotiation.versions().collect::<Vec<_>>(), versions);
    // A list that is not of whole versions is malformed.
    answer.push(0);
    assert!(QUICPacket::decode(&answer, 0).is_err());
    // Reserved versions follow 0x?a?a?a?a (RFC 9000 §15).
    assert!(QUICVersion(0x5A6A_7A8A).is_reserved());
    assert!(!QUICVersion::V1.is_reserved() && !QUICVersion::V2.is_reserved());
}

#[test]
fn retry_of_rfc_9001() {
    // RFC 9001 Appendix A.4: the token "token" and the tag in the last 16 bytes.
    let bytes = QUICVectors::block(9001, "value is not included in the final Retry packet:");
    let QUICPacket::Retry(retry) = QUICPacket::decode(&bytes, 0).unwrap() else { panic!() };
    assert_eq!(retry.version, QUICVersion::V1);
    assert!(retry.destination.is_empty());
    assert_eq!(retry.source.as_slice(), Vectors::hex("f067a5502a4262b5"));
    assert_eq!(retry.token, b"token");
    assert_eq!(&retry.tag[..], &bytes[bytes.len() - 16..]);
    let mut out = Vec::new();
    retry.encode(bytes[0] & 0x0F, &mut out).unwrap();
    assert_eq!(out, bytes);
    // In version 2 the Retry type bits are 0b00 (RFC 9369 §3.2).
    let retry = QUICRetry { version: QUICVersion::V2, ..retry };
    let mut out = Vec::new();
    retry.encode(0, &mut out).unwrap();
    assert_eq!(out[0] & 0x30, 0x00);
    assert!(matches!(QUICPacket::decode(&out, 0).unwrap(), QUICPacket::Retry(_)));
}

#[test]
fn long_header_types_of_each_version() {
    // RFC 9000 Table 5 and RFC 9369 §3.2.
    let types = [QUICPacketType::Initial, QUICPacketType::ZeroRTT, QUICPacketType::Handshake];
    for (version, bits) in [(QUICVersion::V1, [0u8, 1, 2]), (QUICVersion::V2, [1, 2, 3])] {
        for (packet_type, bits) in types.into_iter().zip(bits) {
            let header = QUICHeader::Long(QUICLongHeader {
                packet_type,
                version,
                destination: QUICConnectionID::EMPTY,
                source: QUICConnectionID::EMPTY,
                token: &[],
            });
            let mut out = Vec::new();
            header.encode(true, 0, 1, 20, &mut out).unwrap();
            assert_eq!((out[0] >> 4) & 0x03, bits, "{version:?} {packet_type:?}");
            out.resize(out.len() + 20, 0);
            let QUICPacket::Protected(packet) = QUICPacket::decode(&out, 0).unwrap() else { panic!() };
            assert_eq!(packet.header.packet_type(), packet_type);
        }
    }
    assert_eq!(QUICVersion::V2, QUICVersion(0x6B33_43CF));
}

#[test]
fn frame_table() {
    // RFC 9000 §12.4 Table 3: the packet types of each frame type (I, H, 0,
    // 1, "ih" for the transport CONNECTION_CLOSE only) and the N, C and P rules.
    let text = RFC::section(&QUICVectors::path(9000), "12.4.  Frames and Frame Types", "12.5.");
    let mut rows = 0;
    for line in text.lines().filter(|line| line.trim_start().starts_with("| 0x")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (values, packets, spec) = (cells[1], cells[4], cells[5]);
        let (first, last) = match values.split_once('-') {
            Some((first, last)) => (first, last),
            None => (values, values),
        };
        let parse = |value: &str| u64::from_str_radix(value.trim_start_matches("0x"), 16).unwrap();
        for raw in parse(first)..=parse(last) {
            let frame_type = QUICFrameType(raw);
            let packet = |index: usize, letter: char| match packets.chars().nth(index).unwrap() {
                '_' => false,
                // "ih": the transport variant only (RFC 9000 §12.4).
                'i' | 'h' => raw == 0x1C,
                found => found == letter,
            };
            let expected = [
                (QUICPacketType::Initial, packet(0, 'I')),
                (QUICPacketType::Handshake, packet(1, 'H')),
                // RETIRE_CONNECTION_ID is not in 0-RTT either (RFC 9000 §12.5).
                (QUICPacketType::ZeroRTT, packet(2, '0') && raw != 0x19),
                (QUICPacketType::OneRTT, packet(3, '1')),
            ];
            for (packet_type, permitted) in expected {
                assert_eq!(frame_type.permits(packet_type), permitted, "{raw:#x} in {packet_type:?}");
            }
            assert!(!frame_type.permits(QUICPacketType::Retry));
            assert_eq!(frame_type.is_ack_eliciting(), !spec.contains('N'), "{raw:#x} N");
            assert_eq!(frame_type.is_congestion_exempt(), spec.contains('C'), "{raw:#x} C");
            assert_eq!(frame_type.is_probing(), spec.contains('P'), "{raw:#x} P");
            assert_eq!(frame_type.is_stream(), spec.contains('F'), "{raw:#x} F");
            assert!(frame_type.is_known());
            rows += 1;
        }
    }
    assert_eq!(rows, 0x1F);
    // 0-RTT never carries ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN,
    // PATH_RESPONSE or RETIRE_CONNECTION_ID (RFC 9000 §12.5).
    for raw in [0x02, 0x03, 0x06, 0x1E, 0x07, 0x1B, 0x19] {
        assert!(!QUICFrameType(raw).permits(QUICPacketType::ZeroRTT), "{raw:#x}");
    }
    // DATAGRAM: 0-RTT and 1-RTT, ack-eliciting (RFC 9221 §4, §5.2).
    for frame_type in [QUICFrameType::DATAGRAM, QUICFrameType::DATAGRAM_WITH_LENGTH] {
        assert!(frame_type.permits(QUICPacketType::ZeroRTT) && frame_type.permits(QUICPacketType::OneRTT));
        assert!(!frame_type.permits(QUICPacketType::Initial) && !frame_type.permits(QUICPacketType::Handshake));
        assert!(frame_type.is_ack_eliciting() && frame_type.is_known());
    }
    assert!(!QUICFrameType(0x1F).is_known() && !QUICFrameType(0x1F).permits(QUICPacketType::OneRTT));
}

#[test]
fn frames_of_rfc_9001() {
    // The CRYPTO frame and padding of RFC 9001 Appendix A.2.
    let crypto = QUICVectors::block(9001, "frames to make a 1162-byte payload:");
    let mut payload = crypto.clone();
    payload.resize(1162, 0);
    let frames: Vec<QUICFrame<'_>> = QUICFrames::new(&payload).map(Result::unwrap).collect();
    let [QUICFrame::Crypto { offset: 0, data }, QUICFrame::Padding { length }] = frames[..] else {
        panic!("{frames:?}")
    };
    assert_eq!(data.len(), 0xF1);
    assert_eq!(length, 1162 - crypto.len());
    let mut out = Vec::new();
    frames[0].encode(&mut out).unwrap();
    assert_eq!(out, crypto);
    // The ACK and CRYPTO frames of A.3.
    let payload = QUICVectors::block(9001, "frame, a CRYPTO frame, and no PADDING frames:");
    let frames: Vec<QUICFrame<'_>> = QUICFrames::new(&payload).map(Result::unwrap).collect();
    let [QUICFrame::ACK(ack), QUICFrame::Crypto { offset: 0, data }] = frames[..] else { panic!("{frames:?}") };
    assert_eq!((ack.largest, ack.delay, ack.first_range, ack.range_count), (0, 0, 0, 0));
    assert_eq!(ack.ranges().collect::<Vec<_>>(), vec![0..=0]);
    assert_eq!(data.len(), 0x5A);
}

#[test]
fn ack_ranges() {
    // RFC 9000 §19.3.1: smallest = largest - ack_range, and the next
    // largest = previous_smallest - gap - 2.
    let ranges = [50..=60, 20..=40, 5..=5];
    let mut out = Vec::new();
    QUICACKFrame::encode_ranges(&ranges, 12, Some(QUICECNCounts { ect0: 3, ect1: 0, ce: 1 }), &mut out).unwrap();
    // Largest 60, delay 12, two ranges, first range 10, gap 8, length 20,
    // gap 13, length 0, and the ECN counts.
    assert_eq!(out, [0x03, 60, 12, 2, 10, 8, 20, 13, 0, 3, 0, 1]);
    let QUICFrame::ACK(frame) = QUICFrame::decode(&mut Reader::new(&out)).unwrap() else { panic!() };
    assert_eq!(frame.ranges().collect::<Vec<_>>(), ranges);
    assert_eq!(frame.smallest(), 5);
    assert_eq!(frame.ecn, Some(QUICECNCounts { ect0: 3, ect1: 0, ce: 1 }));
    round_trip(QUICFrame::ACK(frame));
    // A computed packet number below zero is FRAME_ENCODING_ERROR.
    assert_eq!(frame_error(&[0x02, 5, 0, 0, 6]), QUICErrorCode::FRAME_ENCODING_ERROR);
    // Largest 10, first range 2 (8 to 10), then a gap of 7 or a range below 0.
    assert_eq!(frame_error(&[0x02, 10, 0, 1, 2, 7, 0]), QUICErrorCode::FRAME_ENCODING_ERROR);
    assert_eq!(frame_error(&[0x02, 10, 0, 1, 2, 6, 1]), QUICErrorCode::FRAME_ENCODING_ERROR);
    let QUICFrame::ACK(frame) = QUICFrame::decode(&mut Reader::new(&[0x02, 10, 0, 1, 2, 6, 0])).unwrap() else {
        panic!()
    };
    assert_eq!(frame.ranges().collect::<Vec<_>>(), [8..=10, 0..=0]);
    // Ranges that touch or overlap cannot be written.
    assert!(QUICACKFrame::encode_ranges(&[5..=10, 3..=4], 0, None, &mut Vec::new()).is_err());
    assert!(QUICACKFrame::encode_ranges(&[], 0, None, &mut Vec::new()).is_err());
}

#[test]
fn every_frame_round_trips() {
    let stream = QUICStreamID(4);
    let id = QUICConnectionID::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let frames = [
        QUICFrame::Padding { length: 3 },
        QUICFrame::Ping,
        QUICFrame::ResetStream { stream, error: 7, final_size: 1 << 40 },
        QUICFrame::StopSending { stream, error: 0 },
        QUICFrame::Crypto { offset: 100, data: b"hello" },
        QUICFrame::NewToken { token: b"t" },
        QUICFrame::Stream { stream, offset: 0, data: b"abc", fin: false },
        QUICFrame::Stream { stream, offset: 9, data: b"", fin: true },
        QUICFrame::MaxData { maximum: 1 << 30 },
        QUICFrame::MaxStreamData { stream, maximum: 5 },
        QUICFrame::MaxStreams { bidirectional: true, maximum: 1 << 60 },
        QUICFrame::MaxStreams { bidirectional: false, maximum: 0 },
        QUICFrame::DataBlocked { maximum: 9 },
        QUICFrame::StreamDataBlocked { stream, maximum: 9 },
        QUICFrame::StreamsBlocked { bidirectional: true, maximum: 2 },
        QUICFrame::StreamsBlocked { bidirectional: false, maximum: 3 },
        QUICFrame::NewConnectionID { sequence: 3, retire_prior_to: 2, id, reset_token: [9; 16] },
        QUICFrame::RetireConnectionID { sequence: 1 },
        QUICFrame::PathChallenge { data: [1; 8] },
        QUICFrame::PathResponse { data: [2; 8] },
        QUICFrame::ConnectionClose {
            error: QUICErrorCode::PROTOCOL_VIOLATION,
            frame_type: QUICFrameType::STREAM,
            reason: b"why",
        },
        QUICFrame::ApplicationClose { error: 0x100, reason: b"" },
        QUICFrame::HandshakeDone,
        QUICFrame::Datagram { data: b"datagram" },
    ];
    for frame in frames {
        round_trip(frame);
    }
    // The types written: OFF only with an offset, LEN, FIN (RFC 9000 §19.8).
    let mut out = Vec::new();
    QUICFrame::Stream { stream, offset: 9, data: b"x", fin: true }.encode(&mut out).unwrap();
    assert_eq!(out[0], 0x0F);
    // The last frame of a packet may leave out its Length and run to the end.
    let mut out = Vec::new();
    QUICFrame::Stream { stream, offset: 0, data: b"tail", fin: false }.encode_last(&mut out).unwrap();
    assert_eq!(out, [0x08, 4, b't', b'a', b'i', b'l']);
    let mut out = Vec::new();
    QUICFrame::Datagram { data: b"tail" }.encode_last(&mut out).unwrap();
    assert_eq!(out, [0x30, b't', b'a', b'i', b'l']);
    assert_eq!(QUICFrame::decode(&mut Reader::new(&out)).unwrap(), QUICFrame::Datagram { data: b"tail" });
}

#[test]
fn malformed_frames() {
    // RFC 9000 §12.4: an unknown type is FRAME_ENCODING_ERROR; a type not in
    // its shortest encoding may be PROTOCOL_VIOLATION.
    assert_eq!(frame_error(&[0x1F]), QUICErrorCode::FRAME_ENCODING_ERROR);
    assert_eq!(frame_error(&[0x40, 0x01]), QUICErrorCode::PROTOCOL_VIOLATION);
    // Cut short.
    for bytes in [&[0x04, 1, 2][..], &[0x06, 0, 5, 1], &[0x1A, 1, 2, 3], &[0x18, 1, 0, 8, 1], &[0x1C, 1, 0, 3, b'a']] {
        assert_eq!(frame_error(bytes), QUICErrorCode::FRAME_ENCODING_ERROR, "{bytes:02x?}");
    }
    // An empty NEW_TOKEN (RFC 9000 §19.7).
    assert_eq!(frame_error(&[0x07, 0]), QUICErrorCode::FRAME_ENCODING_ERROR);
    // NEW_CONNECTION_ID of 0 or 21 bytes, or retiring past its own number (RFC 9000 §19.15).
    let mut frame = vec![0x18, 1, 0, 0];
    frame.extend_from_slice(&[0; 16]);
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    let mut frame = vec![0x18, 1, 0, 21];
    frame.extend_from_slice(&[0; 37]);
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    let mut frame = vec![0x18, 1, 2, 1, 7];
    frame.extend_from_slice(&[0; 16]);
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    // More than 2^60 streams (RFC 9000 §19.11, §19.14).
    let mut frame = vec![0x12];
    QUICVarint::write(&mut frame, (1 << 60) + 1).unwrap();
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    frame[0] = 0x17;
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    // Data past 2^62 - 1 (RFC 9000 §19.6, §19.8).
    let mut frame = vec![0x0E, 0];
    QUICVarint::write(&mut frame, QUICVarint::MAXIMUM).unwrap();
    frame.extend_from_slice(&[1, b'x']);
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    frame[0] = 0x0E;
    frame.truncate(frame.len() - 2);
    frame.push(0);
    assert!(QUICFrame::decode(&mut Reader::new(&frame)).is_ok(), "an empty frame at 2^62 - 1");
    let mut frame = vec![0x06];
    QUICVarint::write(&mut frame, QUICVarint::MAXIMUM).unwrap();
    frame.extend_from_slice(&[1, b'x']);
    assert_eq!(frame_error(&frame), QUICErrorCode::FRAME_ENCODING_ERROR);
    // A reason phrase past the packet.
    assert_eq!(frame_error(&[0x1D, 0, 9, b'a']), QUICErrorCode::FRAME_ENCODING_ERROR);
    // The error names the frame type that caused it (RFC 9000 §19.19).
    let Err(umilib::protocol::quic::QUICError::Transport(error)) = QUICFrame::decode(&mut Reader::new(&[0x07, 0]))
    else {
        panic!()
    };
    assert_eq!(error.frame_type, QUICFrameType::NEW_TOKEN);
    // The iterator stops after an error.
    let mut frames = QUICFrames::new(&[0x01, 0x1F, 0x01]);
    assert!(frames.next().unwrap().is_ok());
    assert!(frames.next().unwrap().is_err());
    assert!(frames.next().is_none());
}

#[test]
fn stream_ids() {
    // RFC 9000 §2.1, Table 1: the two low bits.
    use umilib::protocol::quic::QUICRole;
    let kinds = [
        (QUICRole::Client, true, 0x00),
        (QUICRole::Server, true, 0x01),
        (QUICRole::Client, false, 0x02),
        (QUICRole::Server, false, 0x03),
    ];
    for (initiator, bidirectional, bits) in kinds {
        let stream = QUICStreamID::new(initiator, bidirectional, 5);
        assert_eq!(stream.0, (5 << 2) | bits);
        assert_eq!((stream.initiator(), stream.is_bidirectional(), stream.index()), (initiator, bidirectional, 5));
    }
    // RFC 9000 §19.11: a unidirectional limit of 3 lets a server open 3, 7 and 11.
    let opened: Vec<u64> = (0..3).map(|index| QUICStreamID::new(QUICRole::Server, false, index).0).collect();
    assert_eq!(opened, [3, 7, 11]);
}

#[test]
fn ack_frames_made_by_hand() {
    // RFC 9000 §19.3.1: a range past zero cannot exist; a frame made with
    // one, not decoded, yields the ranges that can and stops.
    let mut gaps = Vec::new();
    QUICVarint::write_all(&mut gaps, &[0, 2, 100, 0]).unwrap();
    let frame = QUICACKFrame { largest: 10, delay: 0, first_range: 2, range_count: 2, ranges_field: &gaps, ecn: None };
    assert_eq!(frame.ranges().collect::<Vec<_>>(), [8..=10, 4..=6]);
    let frame = QUICACKFrame { first_range: 11, ..frame };
    assert_eq!(frame.ranges().count(), 0);
}

#[test]
fn random_connection_ids() {
    // RFC 9000 §17.2: 20 bytes at most.
    let mut random = crate::tls::handshake::Fixture::random(1);
    assert_eq!(QUICConnectionID::random(20, &mut *random).unwrap().len(), 20);
    assert_eq!(QUICConnectionID::random(0, &mut *random).unwrap(), QUICConnectionID::EMPTY);
    assert!(matches!(QUICConnectionID::random(21, &mut *random), Err(umilib::protocol::quic::QUICError::Config)));
}
