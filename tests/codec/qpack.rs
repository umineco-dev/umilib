//! QPACK (RFC 9204): the examples of Appendix B decoded, the static table
//! of Appendix A, the Required Insert Count of §4.5.1.1, every rule that
//! makes an instruction or a field section invalid, and the encoder's
//! sections and instructions decoded back.

use umilib::codec::hpack::HPACKField;
use umilib::codec::qpack::{
    QPACKDecoded, QPACKDecoder, QPACKDecoderConfig, QPACKDynamicTable, QPACKEncoder, QPACKEncoderConfig, QPACKError,
    QPACKStaticTable,
};

use crate::Vectors;

const PATH: &str = "codec/qpack/rfc9204.txt";

/// The hexadecimal data of the example lines of Appendix B that follow
/// the line `marker` (the lines of "Data | Interpretation" up to a blank one).
fn data(section: &str, marker: &str) -> Vec<u8> {
    let text = Vectors::read(PATH);
    let start = text.find(&format!("\n{section}")).unwrap();
    let start = start + text[start..].find(marker).unwrap();
    let mut hex = String::new();
    for line in text[start..].lines().skip(1) {
        let Some((data, _)) = line.split_once('|') else { break };
        hex.push_str(data);
    }
    Vectors::hex(&hex)
}

fn table(decoder: &QPACKDecoder) -> Vec<(u64, String, String)> {
    let first = decoder.table.first();
    decoder
        .table
        .entries
        .iter()
        .enumerate()
        .map(|(offset, entry)| {
            let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).unwrap();
            (first + offset as u64, text(entry.name()), text(entry.value()))
        })
        .collect()
}

fn fields(decoded: QPACKDecoded) -> Vec<(Vec<u8>, Vec<u8>)> {
    let QPACKDecoded::Fields(fields) = decoded else { panic!("blocked") };
    fields.into_iter().map(|field| (field.name, field.value)).collect()
}

fn entry(index: u64, name: &str, value: &str) -> (u64, String, String) {
    (index, name.into(), value.into())
}

#[test]
fn the_static_table_of_appendix_a() {
    let text = Vectors::read(PATH);
    let start = text.find("Appendix A.  Static Table\n\n").unwrap();
    let end = text.find("Appendix B.  Encoding and Decoding Examples\n\n").unwrap();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Option<Vec<String>> = None;
    for line in text[start..end].lines().map(str::trim) {
        if line.starts_with('+') {
            rows.extend(row.take());
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line.trim_matches('|').split('|').map(|cell| cell.trim().to_string()).collect();
        if cells[0] == "Index" {
            continue;
        }
        // A cell folded over lines: after a hyphen or slash the parts join, otherwise with a space.
        row = Some(match row {
            None => cells,
            Some(row) => row
                .into_iter()
                .zip(cells)
                .map(|(before, after)| match () {
                    _ if after.is_empty() => before,
                    _ if before.ends_with('-') || before.ends_with('/') => before + &after,
                    _ => before + " " + &after,
                })
                .collect(),
        });
    }
    assert_eq!(rows.len(), 99);
    for row in &rows {
        let index: u64 = row[0].parse().unwrap();
        let (name, value) = QPACKStaticTable::get(index).unwrap();
        assert_eq!((name, value), (row[1].as_bytes(), row[2].as_bytes()), "index {index}");
    }
    assert_eq!(QPACKStaticTable::get(99), None);
    assert_eq!(QPACKStaticTable::find(b":method", b"GET"), Some((17, true)));
}

#[test]
fn the_examples_of_appendix_b() {
    let config = QPACKDecoderConfig { maximum_table_capacity: 220, ..QPACKDecoderConfig::default() };
    let mut decoder = QPACKDecoder::new(config);
    // B.1: a literal with a static name reference, without the dynamic table.
    let section = data("B.1.", "Stream: 0");
    assert_eq!(fields(decoder.decode(0, &section).unwrap()), [(b":path".to_vec(), b"/index.html".to_vec())]);
    assert!(decoder.take_instructions().is_empty());
    // B.2: two inserts, then a section with post-base indices, acknowledged.
    decoder.receive_encoder_stream(&data("B.2.", "Stream: Encoder")).unwrap();
    assert_eq!(decoder.table.capacity, 220);
    assert_eq!(table(&decoder), [entry(0, ":authority", "www.example.com"), entry(1, ":path", "/sample/path")]);
    assert_eq!(decoder.table.size, 106);
    let section = data("B.2.", "Stream: 4");
    assert_eq!(
        fields(decoder.decode(4, &section).unwrap()),
        [(b":authority".to_vec(), b"www.example.com".to_vec()), (b":path".to_vec(), b"/sample/path".to_vec())]
    );
    // The inserts (an Insert Count Increment of 2, which may come earlier
    // than the RFC's decoder sends it), then the Section Acknowledgment of B.2.
    let instructions = decoder.take_instructions();
    assert_eq!(instructions, [&[0x02u8][..], &data("B.2.", "Stream: Decoder")[..]].concat());
    // B.3: a speculative insert with a literal name, and its Insert Count Increment.
    decoder.receive_encoder_stream(&data("B.3.", "Stream: Encoder")).unwrap();
    assert_eq!(decoder.table.size, 160);
    assert_eq!(decoder.take_instructions(), data("B.3.", "Stream: Decoder"));
    // B.4: the section of stream 8 arrives before the Duplicate it needs:
    // blocked, then cancelled.
    let section = data("B.4.", "Stream: 8");
    assert_eq!(decoder.decode(8, &section).unwrap(), QPACKDecoded::Blocked);
    assert!(decoder.blocked.contains(&8));
    decoder.cancel_stream(8);
    assert_eq!(decoder.take_instructions(), data("B.4.", "Stream: Decoder"));
    decoder.receive_encoder_stream(&data("B.4.", "Stream: Encoder")).unwrap();
    assert_eq!(table(&decoder)[3], entry(3, ":authority", "www.example.com"));
    assert_eq!(decoder.table.size, 217);
    // Had it not been cancelled, the section decodes now.
    assert_eq!(
        fields(decoder.decode(8, &section).unwrap()),
        [
            (b":authority".to_vec(), b"www.example.com".to_vec()),
            (b":path".to_vec(), b"/".to_vec()),
            (b"custom-key".to_vec(), b"custom-value".to_vec())
        ]
    );
    // B.5: an insert with a dynamic name reference evicts the oldest entry.
    decoder.receive_encoder_stream(&data("B.5.", "Stream: Encoder")).unwrap();
    assert_eq!(
        table(&decoder),
        [
            entry(1, ":path", "/sample/path"),
            entry(2, "custom-key", "custom-value"),
            entry(3, ":authority", "www.example.com"),
            entry(4, "custom-key", "custom-value2"),
        ]
    );
    assert_eq!(decoder.table.size, 215);
}

#[test]
fn required_insert_counts() {
    // §4.5.1.1: a table of 100 bytes encodes modulo 6; after 10 inserts, 4 is 9.
    let mut decoder =
        QPACKDecoder::new(QPACKDecoderConfig { maximum_table_capacity: 100, ..QPACKDecoderConfig::default() });
    decoder.table.inserted = 10;
    assert_eq!(decoder.required_insert_count(4), Ok(9));
    assert_eq!(decoder.required_insert_count(0), Ok(0));
    // Above 2 × MaxEntries, or one that cannot have been encoded, is invalid.
    assert!(matches!(decoder.required_insert_count(7), Err(QPACKError::DecompressionFailed(_))));
    decoder.table.inserted = 0;
    assert!(matches!(decoder.required_insert_count(5), Err(QPACKError::DecompressionFailed(_))));
    // What a conformant encoder encodes, the decoder recovers, over many
    // wraps: Required Insert Counts of entries the decoder can still hold
    // (MaxEntries 3), up to those it has not received yet.
    for inserted in 0..40u64 {
        decoder.table.inserted = inserted;
        for required in inserted.saturating_sub(2).max(1)..=inserted + 3 {
            let encoded = required % 6 + 1;
            assert_eq!(decoder.required_insert_count(encoded), Ok(required), "{inserted} {required}");
        }
    }
}

#[test]
fn invalid_encoder_instructions() {
    // §4.3.1: a capacity above the maximum; §3.2.2: an entry larger than the
    // capacity; §2.2.3: a reference to no entry. Each is QPACK_ENCODER_STREAM_ERROR.
    let config = QPACKDecoderConfig { maximum_table_capacity: 100, ..QPACKDecoderConfig::default() };
    let error = |bytes: &[u8]| QPACKDecoder::new(config).receive_encoder_stream(bytes).unwrap_err();
    assert!(matches!(error(&[0x3F, 0x46]), QPACKError::EncoderStream(_)));
    assert_eq!(error(&[0x3F, 0x46]).code(), Some(QPACKError::ENCODER_STREAM_ERROR));
    let mut large = vec![0x3F, 0x45, 0x41, b'n', 0x7F, 0x00];
    large.extend([b'v'; 127]);
    assert!(matches!(error(&large), QPACKError::EncoderStream(_)));
    assert!(matches!(error(&[0x3F, 0x45, 0x80, 0x01, b'x']), QPACKError::EncoderStream(_)));
    assert!(matches!(error(&[0x3F, 0x45, 0x00]), QPACKError::EncoderStream(_)));
    assert!(matches!(error(&[0xFF, 0x24, 0x00]), QPACKError::EncoderStream(_)));
    // Without a capacity, nothing may be inserted (§3.2.2).
    assert!(matches!(error(&[0xC0, 0x01, b'x']), QPACKError::EncoderStream(_)));
    // An instruction cut anywhere waits for the rest.
    let mut decoder = QPACKDecoder::new(config);
    let whole = [0x3F, 0x45, 0xC0, 0x03, b'a', b'b', b'c'];
    for byte in whole {
        decoder.receive_encoder_stream(&[byte]).unwrap();
    }
    assert_eq!(decoder.table.inserted, 1);
    assert_eq!(decoder.take_instructions(), [0x01]);
}

#[test]
fn invalid_field_sections() {
    let config =
        QPACKDecoderConfig { maximum_table_capacity: 220, blocked_streams: 1, ..QPACKDecoderConfig::default() };
    let mut decoder = QPACKDecoder::new(config);
    decoder.receive_encoder_stream(&data("B.2.", "Stream: Encoder")).unwrap();
    let failed = |decoder: &mut QPACKDecoder, section: &[u8]| {
        matches!(decoder.decode(0, section), Err(QPACKError::DecompressionFailed(_)))
    };
    // §2.2.3: an index at or above the Required Insert Count (here 1, with entry 1).
    assert!(failed(&mut decoder, &[0x02, 0x00, 0x11]));
    // §3.1: a static index of no entry.
    assert!(failed(&mut decoder, &[0x00, 0x00, 0xFF, 0x24]));
    // §4.5.1.2: a negative Base.
    assert!(failed(&mut decoder, &[0x02, 0x81, 0x10]));
    // A relative index before the first entry.
    assert!(failed(&mut decoder, &[0x02, 0x00, 0x81]));
    // A section cut short.
    assert!(failed(&mut decoder, &[0x00, 0x00, 0x51, 0x05, b'x']));
    // §2.1.2: more blocked streams than allowed.
    assert_eq!(decoder.decode(4, &[0x05, 0x00, 0x80]).unwrap(), QPACKDecoded::Blocked);
    assert!(failed(&mut decoder, &[0x05, 0x00, 0x80]));
    // Fields larger than the limit end the stream, not the connection.
    let small = QPACKDecoderConfig { maximum_field_list_size: 40, ..QPACKDecoderConfig::default() };
    let section = [0x00, 0x00, 0x51, 0x0B, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l'];
    let error = QPACKDecoder::new(small).decode(0, &section).unwrap_err();
    assert_eq!((error, error.code()), (QPACKError::FieldListTooLarge, None));
}

#[test]
fn never_indexed_fields() {
    // §4.5.4 to §4.5.6: the 'N' bit is kept by decoders and encoders alike.
    let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
    let mut decoder = QPACKDecoder::new(QPACKDecoderConfig::default());
    encoder.set_peer_settings(4096, 16);
    decoder.receive_encoder_stream(&encoder.take_instructions()).unwrap();
    let sent = [
        HPACKField::sensitive(b"authorization", b"secret"),
        HPACKField::sensitive(b"x-secret", b"value"),
        HPACKField::sensitive(b":method", b"GET"),
    ];
    let section = encoder.encode(0, &sent);
    assert!(encoder.table.entries.is_empty());
    assert_eq!(decoder.decode(0, &section).unwrap(), QPACKDecoded::Fields(sent.to_vec()));
}

/// Moves the instructions of both streams across.
fn exchange(encoder: &mut QPACKEncoder, decoder: &mut QPACKDecoder) {
    decoder.receive_encoder_stream(&encoder.take_instructions()).unwrap();
    encoder.receive_decoder_stream(&decoder.take_instructions()).unwrap();
}

#[test]
fn the_encoder_with_the_decoder() {
    // Requests that repeat fields: inserts, references, acknowledgments,
    // evictions of entries no section needs; the tables agree.
    for blocking in [true, false] {
        let config = QPACKEncoderConfig { maximum_table_capacity: 300, blocking, ..QPACKEncoderConfig::default() };
        let mut encoder = QPACKEncoder::new(config);
        let mut decoder =
            QPACKDecoder::new(QPACKDecoderConfig { maximum_table_capacity: 1000, ..QPACKDecoderConfig::default() });
        encoder.set_peer_settings(1000, 4);
        assert_eq!(encoder.table.capacity, 300);
        for request in 0..30u64 {
            let fields = [
                HPACKField::new(b":method", b"GET"),
                HPACKField::new(b":authority", b"www.example.com"),
                HPACKField::new(b":path", format!("/item/{}", request % 7).as_bytes()),
                HPACKField::new(b"x-request", format!("{request}").as_bytes()),
                HPACKField::new(b"user-agent", b"umilib test"),
            ];
            let stream = request * 4;
            let section = encoder.encode(stream, &fields);
            if !blocking {
                // Never a reference the decoder may lack (§2.1.2).
                assert_eq!(decoder.decode(stream, &section).unwrap(), QPACKDecoded::Fields(fields.to_vec()));
                exchange(&mut encoder, &mut decoder);
                continue;
            }
            match decoder.decode(stream, &section).unwrap() {
                QPACKDecoded::Blocked => {
                    exchange(&mut encoder, &mut decoder);
                    assert_eq!(decoder.decode(stream, &section).unwrap(), QPACKDecoded::Fields(fields.to_vec()));
                }
                decoded => assert_eq!(decoded, QPACKDecoded::Fields(fields.to_vec())),
            }
            exchange(&mut encoder, &mut decoder);
            assert!(encoder.blocking_streams().len() <= 4);
        }
        assert_eq!(encoder.table.entries, decoder.table.entries, "blocking {blocking}");
        assert!(encoder.sections.is_empty() && encoder.references.is_empty());
        assert!(encoder.table.inserted > 5, "the table was used");
    }
}

#[test]
fn entries_still_referenced_are_not_evicted() {
    // §2.1.1, §3.2.2: an entry a section waiting for acknowledgment refers
    // to stays; the encoder sends literals instead of evicting it.
    let config = QPACKEncoderConfig { maximum_table_capacity: 100, ..QPACKEncoderConfig::default() };
    let mut encoder = QPACKEncoder::new(config);
    encoder.set_peer_settings(100, 4);
    let first = [HPACKField::new(b"x-first", b"value one")];
    let first_section = encoder.encode(0, &first);
    assert_eq!(encoder.table.inserted, 1);
    let second = [HPACKField::new(b"x-second", b"value two, a longer one")];
    let second_section = encoder.encode(4, &second);
    assert_eq!(encoder.table.inserted, 1, "no room without evicting the referenced entry");
    let mut decoder =
        QPACKDecoder::new(QPACKDecoderConfig { maximum_table_capacity: 100, ..QPACKDecoderConfig::default() });
    decoder.receive_encoder_stream(&encoder.take_instructions()).unwrap();
    assert_eq!(decoder.decode(4, &second_section).unwrap(), QPACKDecoded::Fields(second.to_vec()));
    assert_eq!(decoder.decode(0, &first_section).unwrap(), QPACKDecoded::Fields(first.to_vec()));
    // Once acknowledged, the entry may go: the next insert evicts it.
    encoder.receive_decoder_stream(&decoder.take_instructions()).unwrap();
    encoder.encode(8, &second);
    assert_eq!((encoder.table.inserted, encoder.table.first()), (2, 1));
    assert_eq!(QPACKDynamicTable::new(100).capacity, 0, "a table starts without capacity (§3.2.2)");
}

#[test]
fn invalid_decoder_instructions() {
    // §4.4.1: an acknowledgment of a stream without sections; §4.4.3: an
    // increment of 0 or past the inserts. Each is QPACK_DECODER_STREAM_ERROR.
    let error = |bytes: &[u8]| {
        let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
        encoder.set_peer_settings(4096, 16);
        encoder.encode(0, &[HPACKField::new(b"x-a", b"1")]);
        encoder.receive_decoder_stream(bytes).unwrap_err()
    };
    assert!(matches!(error(&[0x84]), QPACKError::DecoderStream(_)));
    assert!(matches!(error(&[0x00]), QPACKError::DecoderStream(_)));
    assert!(matches!(error(&[0x02]), QPACKError::DecoderStream(_)));
    assert_eq!(error(&[0x02]).code(), Some(QPACKError::DECODER_STREAM_ERROR));
}

#[test]
fn sections_too_large_are_still_acknowledged() {
    // RFC 9204 §2.2.2.1: a decoder emits a Section Acknowledgment after
    // decoding a section that refers to the dynamic table, so that the
    // encoder can release the entries; one too large for this end is
    // decoded whole all the same (RFC 9114 §4.2.2: answered with 431).
    let mut decoder =
        QPACKDecoder::new(QPACKDecoderConfig { maximum_field_list_size: 100, ..QPACKDecoderConfig::default() });
    // B.2: two entries inserted, then a section of stream 4 that refers to both.
    decoder
        .receive_encoder_stream(&Vectors::hex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"))
        .unwrap();
    decoder.take_instructions();
    // The two references (47 + 44 bytes), then "x-large" with a literal value of 60 bytes.
    let mut section = Vectors::hex("03811011");
    section.extend_from_slice(&[0x27, 0x00]);
    section.extend_from_slice(b"x-large");
    section.push(60);
    section.extend_from_slice(&[b'v'; 60]);
    assert_eq!(decoder.decode(4, &section), Err(QPACKError::FieldListTooLarge));
    assert_eq!(decoder.take_instructions(), [0x84], "a Section Acknowledgment of stream 4");
}

#[test]
fn encoder_streams_in_pieces() {
    // RFC 9204 §4.3: instructions may be split anywhere by the stream.
    let stream = Vectors::hex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
    let mut whole = QPACKDecoder::new(QPACKDecoderConfig::default());
    whole.receive_encoder_stream(&stream).unwrap();
    let mut pieces = QPACKDecoder::new(QPACKDecoderConfig::default());
    for byte in &stream {
        pieces.receive_encoder_stream(std::slice::from_ref(byte)).unwrap();
    }
    assert_eq!(table(&pieces), table(&whole));
    // An instruction that could never fit the table is refused before it ends.
    let mut small =
        QPACKDecoder::new(QPACKDecoderConfig { maximum_table_capacity: 64, ..QPACKDecoderConfig::default() });
    let mut long = vec![0x3F, 0x21];
    long.extend_from_slice(&[0x5F, 0xFF, 0x7F]);
    long.extend_from_slice(&[b'a'; 400]);
    assert!(matches!(small.receive_encoder_stream(&long), Err(QPACKError::EncoderStream(_))));
}
