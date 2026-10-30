//! Zstandard (RFC 8878): the decoding tables of Appendix A, the Huffman
//! example of section 4.2.2, the frames of the zstd tool, and round trips.

use umilib::codec::zstandard::{
    FSEDecodingTable, FSEDistribution, ZstandardCompressor, ZstandardConfig, ZstandardDecompressor,
    ZstandardDecompressorConfig, ZstandardDictionary, ZstandardFormat, ZstandardHuffman, ZstandardOffsets,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Samples, Streaming};

/// The rows (state, symbol, bits, base) of each table of Appendix A, without the first row.
fn appendix_tables() -> Vec<Vec<(usize, u8, u8, u16)>> {
    let text = Vectors::read("codec/zstandard/rfc8878-appendix-a.txt");
    let mut tables: Vec<Vec<(usize, u8, u8, u16)>> = Vec::new();
    for line in text.lines() {
        if line.contains("| State |") {
            tables.push(Vec::new());
            continue;
        }
        let fields: Vec<&str> = line.split('|').map(str::trim).filter(|field| !field.is_empty()).collect();
        if fields.len() == 4 && fields.iter().all(|field| field.parse::<u32>().is_ok()) {
            let values: Vec<u32> = fields.iter().map(|field| field.parse().unwrap()).collect();
            tables.last_mut().unwrap().push((values[0] as usize, values[1] as u8, values[2] as u8, values[3] as u16));
        }
    }
    tables.into_iter().map(|table| table[1..].to_vec()).collect()
}

#[test]
fn predefined_tables_follow_appendix_a() {
    let tables = appendix_tables();
    let defaults: [(&[i16], u32); 3] = [
        (&ZstandardFormat::LITERALS_LENGTH_DEFAULT, ZstandardFormat::LITERALS_LENGTH_DEFAULT_LOG),
        (&ZstandardFormat::MATCH_LENGTH_DEFAULT, ZstandardFormat::MATCH_LENGTH_DEFAULT_LOG),
        (&ZstandardFormat::OFFSET_DEFAULT, ZstandardFormat::OFFSET_DEFAULT_LOG),
    ];
    assert_eq!(tables.len(), 3);
    for (rows, (probabilities, log)) in tables.iter().zip(defaults) {
        let table =
            FSEDecodingTable::new(&FSEDistribution { accuracy_log: log, probabilities: probabilities.to_vec() });
        assert_eq!(rows.len(), 1 << log);
        for (state, symbol, bits, base) in rows {
            let entry = table.entries[*state];
            assert_eq!(
                (entry.symbol, entry.bits, entry.baseline),
                (*symbol, *bits, *base),
                "state {state} of the table of log {log}"
            );
        }
    }
}

#[test]
fn table_descriptions_round_trip() {
    let mut samples = Samples::new(8);
    for round in 0..200 {
        let symbols = 2 + samples.below(50) as usize;
        let counts: Vec<u32> = (0..symbols)
            .map(|_| if samples.below(4) == 0 { 0 } else { 1 + samples.below(1 << (round % 12)) as u32 })
            .collect();
        if counts.iter().filter(|count| **count > 0).count() < 2 {
            continue;
        }
        let log = (5 + samples.below(5) as u32).max(64 - (symbols as u64).leading_zeros());
        let distribution = FSEDistribution::normalize(&counts, log);
        let total: i32 = distribution
            .probabilities
            .iter()
            .map(|probability| if *probability == -1 { 1 } else { *probability as i32 })
            .sum();
        assert_eq!(total, 1 << log);
        let mut bytes = Vec::new();
        distribution.write(&mut bytes);
        bytes.push(0xAA);
        let (read, used) = FSEDistribution::read(&bytes, 9, 64).unwrap();
        assert_eq!(read, distribution);
        assert_eq!(used, bytes.len() - 1);
    }
    // An accuracy log above the limit, a total above the scale.
    assert!(FSEDistribution::read(&[0x0F], 9, 64).is_err());
    assert!(FSEDistribution::read(&[], 9, 64).is_err());
}

#[test]
fn huffman_codes_follow_section_4_2() {
    // Tables 23 and 25: the weights 4, 3, 2, 0, 1 and the implied 1 of symbol 5.
    let code = ZstandardHuffman::from_weights(&[4, 3, 2, 0, 1]).unwrap();
    assert_eq!(code.maximum_bits, 4);
    assert_eq!(code.weights, [4, 3, 2, 0, 1, 1]);
    let codes = code.codes();
    assert_eq!([codes[0], codes[1], codes[2], codes[4], codes[5]], [(1, 1), (1, 2), (1, 3), (0, 4), (1, 4)]);
    // Section 4.2.2: "0145" written in reverse order, then the final 1 bit. (Table 26 of the RFC
    // gives 4 and 5 the codes the other has in Table 25 and in the reference decoder; this
    // follows Table 25: 5 is 0001, 4 is 0000, 1 is 01, 0 is 1.)
    let stream = ZstandardHuffman::encode_stream(&codes, &[0, 1, 4, 5]);
    assert_eq!(stream, [0b0000_0001, 0b0000_1101]);
    let mut out = Vec::new();
    code.decode_stream(&stream, 4, &mut out).unwrap();
    assert_eq!(out, [0, 1, 4, 5]);
    // A stream not consumed exactly, weights that do not complete a code.
    assert!(code.decode_stream(&stream, 3, &mut Vec::new()).is_err());
    assert!(ZstandardHuffman::from_weights(&[2, 2, 1]).is_err());
    assert!(ZstandardHuffman::from_weights(&[]).is_err());
    // Descriptions round trip, directly and FSE-compressed.
    let mut samples = Samples::new(4);
    for spread in [20u64, 200, 256] {
        let mut frequencies = [0u32; 256];
        for _ in 0..5000 {
            frequencies[(samples.below(spread) * samples.below(spread) / spread) as usize] += 1;
        }
        let code = ZstandardHuffman::from_frequencies(&frequencies);
        let description = code.write().expect("a description");
        let (read, used) = ZstandardHuffman::read(&description).unwrap();
        assert_eq!(used, description.len());
        assert_eq!(read.table, code.table);
    }
}

#[test]
fn repeat_offsets_follow_section_3_1_1_5() {
    // The prose of the section (Table 18 of the RFC has errors in two of its rows).
    let mut offsets = ZstandardOffsets::new();
    for (value, literals, expected, state) in [
        (1114u32, 11u32, 1111u32, [1111u32, 1, 4]),
        (1, 22, 1111, [1111, 1, 4]),
        (2225, 22, 2222, [2222, 1111, 1]),
        (1114, 111, 1111, [1111, 2222, 1111]),
        (3336, 33, 3333, [3333, 1111, 2222]),
        (2, 22, 1111, [1111, 3333, 2222]),
        (3, 33, 2222, [2222, 1111, 3333]),
        (3, 0, 2221, [2221, 2222, 1111]),
        (1, 0, 2222, [2222, 2221, 1111]),
        (2, 0, 1111, [1111, 2222, 2221]),
    ] {
        assert_eq!(offsets.resolve(value, literals).unwrap(), expected);
        assert_eq!(offsets.offsets, state);
    }
    let mut one = ZstandardOffsets { offsets: [1, 4, 8] };
    assert!(one.resolve(3, 0).is_err());
}

const FRAMES: [(&str, &str); 9] = [
    ("text.level1", "text"),
    ("text.level3", "text"),
    ("text.nocheck", "text"),
    ("text.streamed", "text"),
    ("repetitive.level19", "repetitive"),
    ("random.level3", "random"),
    ("zeros.level3", "zeros"),
    ("empty", "empty"),
    ("skippable", "text"),
];

#[test]
fn zstandard_decompressors_read_the_frames_of_zstd() {
    for (file, input) in FRAMES {
        let data = Vectors::bytes(&format!("codec/deflate/{input}.bin"));
        let stream = Vectors::bytes(&format!("codec/zstandard/{file}.zst"));
        Streaming::check(&mut ZstandardDecompressor::default(), &stream, &data, Ending::Input);
        if file != "skippable" {
            let single =
                ZstandardDecompressorConfig { multiple_frames: false, ..ZstandardDecompressorConfig::default() };
            Streaming::check(&mut ZstandardDecompressor::new(single), &stream, &data, Ending::Marked);
        }
    }
    let text = Vectors::bytes("codec/deflate/text.bin");
    let random = Vectors::bytes("codec/deflate/random.bin");
    let mut decompressor = ZstandardDecompressor::default();
    assert_eq!(
        decompressor.decompress_to_vec(&Vectors::bytes("codec/zstandard/frames.zst"), usize::MAX).unwrap(),
        [&text[..], &random[..]].concat()
    );
    assert_eq!(decompressor.frames(), 2);
    // Frames of several blocks: the levels agree, and the long window needs its limit.
    let mut decoded = Vec::new();
    for file in ["large.level9", "large.level22", "large.long"] {
        let stream = Vectors::bytes(&format!("codec/zstandard/{file}.zst"));
        let data = ZstandardDecompressor::default().decompress_to_vec(&stream, usize::MAX).unwrap();
        assert_eq!(data.len(), 284409, "{file}");
        decoded.push(data);
    }
    assert!(decoded[0] == decoded[1] && decoded[1] == decoded[2]);
    // A window of 2^28 bytes, above the default limit of 2^27 (an empty frame).
    let mut frame = ZstandardFormat::MAGIC.to_le_bytes().to_vec();
    frame.extend([0x00, (28 - 10) << 3, 0x01, 0x00, 0x00]);
    assert_eq!(
        ZstandardDecompressor::default().decompress_to_vec(&frame, 10),
        Err(CompressionError::LimitExceeded { limit: 1 << 27 })
    );
    let large = ZstandardDecompressorConfig { maximum_window: 1 << 28, ..ZstandardDecompressorConfig::default() };
    assert_eq!(ZstandardDecompressor::new(large).decompress_to_vec(&frame, 10).unwrap(), b"");
}

#[test]
fn zstandard_decompressors_use_dictionaries() {
    let text = Vectors::bytes("codec/deflate/text.bin");
    let trained = ZstandardDictionary::new(&Vectors::bytes("codec/zstandard/dictionary.trained")).unwrap();
    assert_ne!(trained.identifier, 0);
    assert!(trained.huffman.is_some());
    let stream = Vectors::bytes("codec/zstandard/text.dictionary.zst");
    let config =
        ZstandardDecompressorConfig { dictionary: Some(trained.clone()), ..ZstandardDecompressorConfig::default() };
    assert_eq!(ZstandardDecompressor::new(config).decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(
        ZstandardDecompressor::default().decompress_to_vec(&stream, usize::MAX),
        Err(CompressionError::MissingDictionary { identifier: trained.identifier })
    );
    let raw = ZstandardDictionary::new(&Vectors::bytes("codec/deflate/dictionary.bin")).unwrap();
    assert_eq!(raw.identifier, 0);
    let stream = Vectors::bytes("codec/zstandard/text.rawdictionary.zst");
    let config = ZstandardDecompressorConfig { dictionary: Some(raw), ..ZstandardDecompressorConfig::default() };
    assert_eq!(ZstandardDecompressor::new(config).decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert!(ZstandardDictionary::new(b"short").is_err());
}

#[test]
fn zstandard_decompressors_check_frames() {
    let stream = Vectors::bytes("codec/zstandard/text.level3.zst");
    let text = Vectors::bytes("codec/deflate/text.bin");
    let invalid = |reason| Err(CompressionError::InvalidData { reason });
    let check = |change: &dyn Fn(&mut Vec<u8>), expected: Result<Vec<u8>, CompressionError>| {
        let mut corrupt = stream.clone();
        change(&mut corrupt);
        assert_eq!(ZstandardDecompressor::default().decompress_to_vec(&corrupt, usize::MAX), expected);
    };
    check(&|bytes| bytes[0] ^= 1, invalid("unknown magic number"));
    check(&|bytes| bytes[4] |= 0x08, invalid("reserved bit set"));
    check(&|bytes| *bytes.last_mut().unwrap() ^= 1, Err(CompressionError::ChecksumMismatch));
    // The header: descriptor 0x64 (a single segment, so no window descriptor; a 2-byte content
    // size; a checksum); the first block header follows at byte 7.
    assert_eq!(stream[4], 0x64);
    check(&|bytes| bytes[7] |= 0x06, invalid("reserved block type"));
    // One byte more in the content size (which, for a single segment, is also the window).
    let larger = (text.len() + 1 - 256) as u16;
    check(&|bytes| bytes[5..7].copy_from_slice(&larger.to_le_bytes()), invalid("content size mismatch"));
    // An empty frame with a block larger than the window of 1 KiB.
    let mut frame = ZstandardFormat::MAGIC.to_le_bytes().to_vec();
    frame.extend([0x00, 0x00]);
    frame.extend(((1u32 << 3) | 2048 << 3 | 1).to_le_bytes()[..3].iter());
    assert_eq!(
        ZstandardDecompressor::default().decompress_to_vec(&frame, 10_000),
        invalid("block larger than the maximum")
    );
    let _ = text;
}

#[test]
fn zstandard_frames_round_trip() {
    for (level, window_log) in [(1, None), (3, None), (9, Some(17)), (19, Some(20))] {
        let config = ZstandardConfig { level, window_log, ..ZstandardConfig::default() };
        let mut compressor = ZstandardCompressor::new(config).unwrap();
        Streaming::round_trip(&mut compressor, &mut ZstandardDecompressor::default(), Ending::Input, true);
    }
    let text = Vectors::bytes("codec/deflate/text.bin");
    // The content size, the checksum off, a dictionary with its identifier.
    let trained = ZstandardDictionary::new(&Vectors::bytes("codec/zstandard/dictionary.trained")).unwrap();
    let config = ZstandardConfig {
        content_size: Some(text.len() as u64),
        content_checksum: false,
        dictionary: Some(trained.clone()),
        ..ZstandardConfig::default()
    };
    let stream = ZstandardCompressor::new(config.clone()).unwrap().compress_to_vec(&text).unwrap();
    let decompressor_config =
        ZstandardDecompressorConfig { dictionary: Some(trained), ..ZstandardDecompressorConfig::default() };
    assert_eq!(ZstandardDecompressor::new(decompressor_config).decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(
        ZstandardCompressor::new(config).unwrap().compress_to_vec(&text[1..]),
        Err(CompressionError::InvalidParameter)
    );
    for invalid in [
        ZstandardConfig { level: 0, ..ZstandardConfig::default() },
        ZstandardConfig { level: 20, ..ZstandardConfig::default() },
        ZstandardConfig { window_log: Some(9), ..ZstandardConfig::default() },
    ] {
        assert!(ZstandardCompressor::new(invalid).is_err());
    }
    // Compared with zstd's level 3, the frame is at most a fifth larger.
    let reference = Vectors::bytes("codec/zstandard/text.level3.zst");
    let ours = ZstandardCompressor::new(ZstandardConfig::default()).unwrap().compress_to_vec(&text).unwrap();
    assert!(ours.len() <= reference.len() + reference.len() / 5, "{} against {}", ours.len(), reference.len());
}
