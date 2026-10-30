//! LZMA (lzma-specification) and LZMA2: the streams of liblzma and xz, the
//! checks of the specification, and round trips.

use umilib::codec::lzma::{
    LZMA2Compressor, LZMA2Decompressor, LZMA2DecompressorConfig, LZMACompressor, LZMAConfig, LZMADecompressor,
    LZMADecompressorConfig, LZMAFormat, LZMAModel, LZMAProperties,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Streaming};

/// The .lzma vectors: (stream, input).
const ALONE: [(&str, &str); 8] = [
    ("text.preset6", "text"),
    ("text.preset0", "text"),
    ("repetitive.extreme", "repetitive"),
    ("repetitive.xz6", "repetitive"),
    ("random", "random"),
    ("empty", "empty"),
    ("text.lc0lp2pb0", "text"),
    ("text.lc4pb4", "text"),
];

#[test]
fn lzma_decompressors_read_the_files_of_liblzma_and_xz() {
    for (stream, input) in ALONE {
        let data = Vectors::bytes(&format!("codec/deflate/{input}.bin"));
        let stream = Vectors::bytes(&format!("codec/lzma/{stream}.lzma"));
        assert_eq!(LZMADecompressor::default().decompress_to_vec(&stream, data.len()).unwrap(), data, "{input}");
        Streaming::check(&mut LZMADecompressor::default(), &stream, &data, Ending::Marked);
    }
}

#[test]
fn lzma_decompressors_read_the_test_files_of_xz_utils() {
    // The good files (section 3.1 of their README) hold "Hello\nWorld!\n", as xz decodes them: an
    // end marker with an unknown size, a known size without it, and a known size with it.
    for name in ["good-unknown_size-with_eopm", "good-known_size-without_eopm", "good-known_size-with_eopm"] {
        let stream = Vectors::bytes(&format!("codec/lzma/xz-utils/{name}.lzma"));
        Streaming::check(&mut LZMADecompressor::default(), &stream, b"Hello\nWorld!\n", Ending::Marked);
    }
    // The bad files: no end marker with an unknown size, an end marker before the size, data after it.
    for name in [
        "bad-unknown_size-without_eopm",
        "bad-too_big_size-with_eopm",
        "bad-too_small_size-without_eopm-1",
        "bad-too_small_size-without_eopm-2",
        "bad-too_small_size-without_eopm-3",
    ] {
        let stream = Vectors::bytes(&format!("codec/lzma/xz-utils/{name}.lzma"));
        let result = LZMADecompressor::default().decompress_to_vec(&stream, 1 << 16);
        assert!(result.is_err(), "{name}: {result:?}");
    }
}

#[test]
fn lzma_properties_follow_the_specification() {
    // (pb × 5 + lp) × 9 + lc: 0x5D is lc = 3, lp = 0, pb = 2.
    let properties = LZMAProperties::from_byte(0x5D).unwrap();
    assert_eq!(properties, LZMAProperties { literal_context_bits: 3, literal_position_bits: 0, position_bits: 2 });
    assert_eq!(properties.to_byte(), 0x5D);
    for byte in 0..225u8 {
        assert_eq!(LZMAProperties::from_byte(byte).unwrap().to_byte(), byte);
    }
    assert!(LZMAProperties::from_byte(225).is_err());
    // The size of the probability arrays: 1846 + 768 × 2^(lc + lp) of the specification, and one unused.
    assert_eq!(LZMAModel::new(properties).probabilities.len(), 1846 + 1 + 768 * 8);
    // Distance slots: 0 to 3 are themselves; then 2 per bit length.
    for (distance, slot) in
        [(0u32, 0u32), (3, 3), (4, 4), (5, 4), (6, 5), (7, 5), (8, 6), (12, 7), (1 << 31, 62), (u32::MAX, 63)]
    {
        assert_eq!(LZMAModel::distance_slot(distance), slot, "{distance}");
    }
}

#[test]
fn lzma_decompressors_check_the_stream() {
    let stream = Vectors::bytes("codec/lzma/text.preset6.lzma");
    let text = Vectors::bytes("codec/deflate/text.bin");
    let invalid = |reason| Err(CompressionError::InvalidData { reason });
    // Properties of 225 and beyond.
    let mut corrupt = stream.clone();
    corrupt[0] = 225;
    assert_eq!(LZMADecompressor::default().decompress_to_vec(&corrupt, text.len()), invalid("invalid properties"));
    // A first byte of the range coder other than 0.
    let mut corrupt = stream.clone();
    corrupt[13] = 1;
    assert_eq!(
        LZMADecompressor::default().decompress_to_vec(&corrupt, text.len()),
        invalid("invalid first byte of the range coder")
    );
    // A dictionary larger than the limit.
    let limited = LZMADecompressorConfig { maximum_dictionary_size: 1 << 20 };
    assert_eq!(
        LZMADecompressor::new(limited).decompress_to_vec(&stream, text.len()),
        Err(CompressionError::LimitExceeded { limit: 1 << 20 })
    );
    // A size in the header shorter than the data, and longer.
    for size in [text.len() as u64 - 1, text.len() as u64 + 1] {
        let mut sized = stream.clone();
        sized[5..13].copy_from_slice(&size.to_le_bytes());
        assert!(LZMADecompressor::default().decompress_to_vec(&sized, usize::MAX).is_err(), "size {size}");
    }
    // With the exact size, the end marker after it is read.
    let mut sized = stream.clone();
    sized[5..13].copy_from_slice(&(text.len() as u64).to_le_bytes());
    assert_eq!(LZMADecompressor::default().decompress_to_vec(&sized, usize::MAX).unwrap(), text);
}

#[test]
fn lzma_files_round_trip() {
    for level in [0, 1, 6, 9] {
        let mut compressor = LZMACompressor::new(LZMAConfig { level, ..LZMAConfig::default() }).unwrap();
        Streaming::round_trip(&mut compressor, &mut LZMADecompressor::default(), Ending::Marked, false);
    }
    let properties = LZMAProperties { literal_context_bits: 0, literal_position_bits: 2, position_bits: 0 };
    let mut compressor = LZMACompressor::new(LZMAConfig {
        level: 3,
        properties,
        dictionary_size: Some(1 << 16),
        uncompressed_size: None,
    })
    .unwrap();
    Streaming::round_trip(&mut compressor, &mut LZMADecompressor::default(), Ending::Marked, false);
    // A known size: no end marker.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let config = LZMAConfig { uncompressed_size: Some(text.len() as u64), ..LZMAConfig::default() };
    let stream = LZMACompressor::new(config).unwrap().compress_to_vec(&text).unwrap();
    assert_eq!(LZMADecompressor::default().decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(
        LZMACompressor::new(config).unwrap().compress_to_vec(&text[1..]),
        Err(CompressionError::InvalidParameter)
    );
    // Compared with liblzma's preset 6, the stream is at most a fifth larger.
    let reference = Vectors::bytes("codec/lzma/text.preset6.lzma");
    let ours = LZMACompressor::new(LZMAConfig::default()).unwrap().compress_to_vec(&text).unwrap();
    assert!(ours.len() <= reference.len() + reference.len() / 5, "{} against {}", ours.len(), reference.len());
}

#[test]
fn lzma2_decompressors_read_the_streams_of_liblzma() {
    for (stream, input, dictionary) in [
        ("text", "text", 1 << 23),
        ("repetitive", "repetitive", 1 << 16),
        ("random", "random", 1 << 20),
        ("empty", "empty", 1 << 12),
    ] {
        let data = Vectors::bytes(&format!("codec/deflate/{input}.bin"));
        let stream = Vectors::bytes(&format!("codec/lzma/{stream}.raw.lzma2"));
        let config = LZMA2DecompressorConfig { dictionary_size: dictionary };
        assert_eq!(
            LZMA2Decompressor::new(config).unwrap().decompress_to_vec(&stream, data.len()).unwrap(),
            data,
            "{input}"
        );
        Streaming::check(&mut LZMA2Decompressor::new(config).unwrap(), &stream, &data, Ending::Marked);
    }
    // The dictionary sizes of the LZMA2 properties byte of the xz format.
    assert_eq!(LZMAFormat::lzma2_dictionary_size(0), Some(4 << 10));
    assert_eq!(LZMAFormat::lzma2_dictionary_size(1), Some(6 << 10));
    assert_eq!(LZMAFormat::lzma2_dictionary_size(36), Some(1 << 30));
    assert_eq!(LZMAFormat::lzma2_dictionary_size(39), Some(3 << 30));
    assert_eq!(LZMAFormat::lzma2_dictionary_size(40), Some(u32::MAX as u64));
    assert_eq!(LZMAFormat::lzma2_dictionary_size(41), None);
    assert_eq!(LZMAFormat::lzma2_dictionary_byte(1 << 23), 22);
    assert_eq!(LZMAFormat::lzma2_dictionary_byte((1 << 23) + 1), 23);
}

#[test]
fn lzma2_decompressors_check_the_chunks() {
    let invalid = |reason| Err(CompressionError::InvalidData { reason });
    let mut decompressor = LZMA2Decompressor::default();
    let mut check = |stream: &[u8], expected: Result<Vec<u8>, CompressionError>| {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(stream, 100), expected, "{stream:02x?}");
    };
    // Uncompressed chunks: with a dictionary reset, then without.
    check(&[0x01, 0x00, 0x01, b'h', b'i', 0x02, 0x00, 0x00, b'!', 0x00], Ok(b"hi!".to_vec()));
    // Control bytes 3 to 0x7F, a first chunk without a dictionary reset.
    check(&[0x03], invalid("invalid control byte"));
    check(&[0x7F], invalid("invalid control byte"));
    check(&[0x02, 0x00, 0x00, b'x', 0x00], invalid("no dictionary reset in the first chunk"));
    check(&[0x80, 0x00, 0x00, 0x00, 0x04], invalid("no dictionary reset in the first chunk"));
    // An LZMA chunk after an uncompressed one with a dictionary reset must set properties.
    check(&[0x01, 0x00, 0x00, b'x', 0xA0, 0x00, 0x00, 0x00, 0x04], invalid("no properties after a dictionary reset"));
    // Properties with lc + lp above 4 (lc = 3, lp = 2).
    check(&[0xE0, 0x00, 0x00, 0x00, 0x04, 21], invalid("invalid properties"));
    // A chunk whose compressed size is larger than its symbols.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let stream = LZMA2Compressor::new(LZMAConfig::default()).unwrap().compress_to_vec(&text[..100]).unwrap();
    assert_eq!(stream[0], 0xE0);
    let mut longer = stream.clone();
    longer[4] += 1;
    longer.insert(stream.len() - 1, 0);
    check(&longer, invalid("chunk sizes do not match its data"));
    let mut shorter = stream.clone();
    shorter[4] -= 1;
    assert!(LZMA2Decompressor::default().decompress_to_vec(&shorter, 100).is_err());
}

#[test]
fn lzma2_streams_round_trip() {
    for level in [0, 6, 9] {
        let config = LZMAConfig { level, dictionary_size: Some(1 << 20), ..LZMAConfig::default() };
        let mut compressor = LZMA2Compressor::new(config).unwrap();
        let decompressor_config = LZMA2DecompressorConfig { dictionary_size: compressor.dictionary_size() };
        Streaming::round_trip(
            &mut compressor,
            &mut LZMA2Decompressor::new(decompressor_config).unwrap(),
            Ending::Marked,
            true,
        );
    }
    // Random data is stored in uncompressed chunks; the LZMA chunk after them resets the state.
    let random = Vectors::bytes("codec/deflate/random.bin");
    let text = Vectors::bytes("codec/deflate/text.bin");
    let data = [&random[..], &text[..], &random[..]].concat();
    let mut compressor = LZMA2Compressor::new(LZMAConfig::default()).unwrap();
    let mut stream = Vec::new();
    let mut out = vec![0u8; 1 << 20];
    for (piece, flush) in [
        (&random[..], umilib::codec::Flush::Sync),
        (&text[..], umilib::codec::Flush::Sync),
        (&random[..], umilib::codec::Flush::Finish),
    ] {
        let progress = compressor.compress(piece, &mut out, flush).unwrap();
        assert_eq!(progress.consumed, piece.len());
        stream.extend_from_slice(&out[..progress.produced]);
    }
    assert_eq!(stream[0], 0x01);
    assert_eq!(LZMA2Decompressor::default().decompress_to_vec(&stream, data.len()).unwrap(), data);
    assert!(
        LZMA2Compressor::new(LZMAConfig {
            properties: LZMAProperties { literal_context_bits: 4, literal_position_bits: 1, position_bits: 2 },
            ..LZMAConfig::default()
        })
        .is_err()
    );
    // Compared with liblzma's preset 6, the stream is at most a fifth larger.
    let reference = Vectors::bytes("codec/lzma/text.raw.lzma2");
    let ours = LZMA2Compressor::new(LZMAConfig::default()).unwrap().compress_to_vec(&text).unwrap();
    assert!(ours.len() <= reference.len() + reference.len() / 5, "{} against {}", ours.len(), reference.len());
}
