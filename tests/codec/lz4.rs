//! LZ4: the block format against lz4_Block_format.md, and the frames of the lz4 tool.

use umilib::codec::lz4::{
    LZ4Block, LZ4BlockSize, LZ4Compressor, LZ4Config, LZ4Decompressor, LZ4DecompressorConfig, LZ4FrameFormat,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};
use umilib::hash::xxhash::xxh32::XXH32;

use crate::Vectors;
use crate::compression::{Ending, Samples, Streaming};

#[test]
fn lz4_blocks_follow_the_block_format() {
    // Examples 1 to 3: literal lengths 48, 280 and 15.
    for (length, encoding) in [(48usize, vec![0xF0u8, 33]), (280, vec![0xF0, 255, 10]), (15, vec![0xF0, 0])] {
        let mut out = Vec::new();
        LZ4Block::write_sequence(&vec![b'x'; length], None, &mut out);
        assert_eq!(out[..encoding.len()], encoding[..], "literal length {length}");
        assert_eq!(LZ4Block::decompress(&out, length).unwrap(), vec![b'x'; length]);
    }
    // Empty input is a single zero token.
    assert_eq!(LZ4Block::compress(b"", 1).unwrap(), [0]);
    assert_eq!(LZ4Block::decompress(&[0], 0).unwrap(), b"");
    // "abcabcabc...": 3 literals, then a match of offset 3 (overlapping), then the last 5 literals.
    let block = [0x36, b'a', b'b', b'c', 3, 0, 0x50, b'b', b'c', b'a', b'b', b'c'];
    assert_eq!(LZ4Block::decompress(&block, 100).unwrap(), b"abcabcabcabcabcabc");
    // Offsets of 0 and beyond the data, truncated blocks, and the limit.
    let invalid = |reason| Err(CompressionError::InvalidData { reason });
    assert_eq!(LZ4Block::decompress(&[0x10, b'a', 0, 0, 0x00], 100), invalid("invalid offset"));
    assert_eq!(LZ4Block::decompress(&[0x10, b'a', 2, 0, 0x00], 100), invalid("invalid offset"));
    assert_eq!(LZ4Block::decompress(&[0x30, b'a'], 100), invalid("truncated block"));
    assert_eq!(LZ4Block::decompress(&[0x1F, b'a', 1, 0], 100), invalid("truncated block"));
    assert_eq!(LZ4Block::decompress(&[], 100), invalid("truncated block"));
    assert_eq!(LZ4Block::decompress(&block, 17), Err(CompressionError::LimitExceeded { limit: 17 }));
}

/// Checks the end-of-block conditions: the last sequence has only literals, at least 5 (or the
/// whole input when shorter), and the last match starts at least 12 bytes before the end.
fn check_end_conditions(block: &[u8], length: usize) {
    let mut position = 0;
    let (mut produced, mut last_match_start) = (0usize, None);
    loop {
        let token = block[position];
        position += 1;
        let mut literals = (token >> 4) as usize;
        if literals == 15 {
            literals += LZ4Block::read_length(block, &mut position).unwrap();
        }
        position += literals;
        produced += literals;
        if position == block.len() {
            assert!(literals >= 5.min(length), "the last sequence has {literals} literals");
            break;
        }
        position += 2;
        let mut match_length = (token & 15) as usize;
        if match_length == 15 {
            match_length += LZ4Block::read_length(block, &mut position).unwrap();
        }
        last_match_start = Some(produced);
        produced += match_length + 4;
    }
    assert_eq!(produced, length);
    if let Some(start) = last_match_start {
        assert!(start + 12 <= length, "the last match starts at {start} of {length}");
    }
}

#[test]
fn lz4_blocks_keep_the_end_of_block_conditions() {
    let mut samples = Samples::new(12);
    for length in [0, 1, 4, 5, 12, 13, 14, 20, 100, 70_000] {
        let data = samples.repetitive(length);
        for level in [1, 9, 12] {
            let block = LZ4Block::compress(&data, level).unwrap();
            check_end_conditions(&block, data.len());
            assert_eq!(LZ4Block::decompress(&block, data.len()).unwrap(), data);
        }
    }
    let zeros = vec![0u8; 1000];
    let block = LZ4Block::compress(&zeros, 1).unwrap();
    check_end_conditions(&block, 1000);
    assert!(block.len() < 20);
    assert_eq!(LZ4Block::compress(b"", 13), Err(CompressionError::InvalidParameter));
}

#[test]
fn lz4_decompressors_read_the_frames_of_the_lz4_tool() {
    let text = Vectors::bytes("codec/deflate/text.bin");
    let random = Vectors::bytes("codec/deflate/random.bin");
    let repetitive = Vectors::bytes("codec/deflate/repetitive.bin");
    let single = LZ4DecompressorConfig { multiple_frames: false, ..LZ4DecompressorConfig::default() };
    for (file, data) in [
        ("text.level1", &text),
        ("text.level9", &text),
        ("repetitive.level12", &repetitive),
        ("random.level1", &random),
        ("text.nocrc", &text),
        ("empty", &Vec::new()),
    ] {
        let stream = Vectors::bytes(&format!("codec/lz4/{file}.lz4"));
        Streaming::check(&mut LZ4Decompressor::default(), &stream, data, Ending::Input);
        Streaming::check(&mut LZ4Decompressor::new(single.clone()), &stream, data, Ending::Marked);
    }
    let frames = Vectors::bytes("codec/lz4/frames.lz4");
    let mut decompressor = LZ4Decompressor::default();
    assert_eq!(decompressor.decompress_to_vec(&frames, usize::MAX).unwrap(), [&text[..], &random[..]].concat());
    assert_eq!(decompressor.frames(), 2);
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&Vectors::bytes("codec/lz4/skippable.lz4"), usize::MAX).unwrap(), text);
    assert_eq!(decompressor.frames(), 2);
    // A legacy frame, which ends with the input, needs blocks of 8 MiB.
    let legacy = Vectors::bytes("codec/lz4/text.legacy.lz4");
    let large = LZ4DecompressorConfig { maximum_block_size: 8 << 20, ..LZ4DecompressorConfig::default() };
    assert_eq!(LZ4Decompressor::new(large).decompress_to_vec(&legacy, usize::MAX).unwrap(), text);
    assert_eq!(
        LZ4Decompressor::default().decompress_to_vec(&legacy, usize::MAX),
        Err(CompressionError::LimitExceeded { limit: 4 << 20 })
    );
    // A dictionary passed off-band.
    let dictionary = Vectors::bytes("codec/deflate/dictionary.bin");
    let config = LZ4DecompressorConfig { dictionary: Some(dictionary), ..LZ4DecompressorConfig::default() };
    let stream = Vectors::bytes("codec/lz4/text.dictionary.lz4");
    assert_eq!(LZ4Decompressor::new(config).decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(
        LZ4Decompressor::default().decompress_to_vec(&stream, usize::MAX),
        Err(CompressionError::InvalidData { reason: "invalid offset" })
    );
    // Linked blocks, block checksums with the content size, and blocks of 256 KiB give the same data, which their content checksums check.
    let mut decoded = Vec::new();
    for file in ["large.linked", "large.checksums", "large.block256"] {
        let stream = Vectors::bytes(&format!("codec/lz4/{file}.lz4"));
        let data = LZ4Decompressor::default().decompress_to_vec(&stream, usize::MAX).unwrap();
        assert_eq!(data.len(), 284409);
        Streaming::check(&mut LZ4Decompressor::default(), &stream, &data, Ending::Input);
        decoded.push(data);
    }
    assert!(decoded[0] == decoded[1] && decoded[1] == decoded[2]);
}

#[test]
fn lz4_decompressors_check_frames() {
    let stream = Vectors::bytes("codec/lz4/large.checksums.lz4");
    let mut decompressor = LZ4Decompressor::default();
    let mut check = |index: usize, change: u8, error: CompressionError| {
        let mut corrupt = stream.clone();
        corrupt[index] ^= change;
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&corrupt, usize::MAX), Err(error), "byte {index}");
    };
    let invalid = |reason| CompressionError::InvalidData { reason };
    // The magic number; the header checksum guards the descriptor.
    check(0, 1, invalid("unknown magic number"));
    check(4, 0x02, CompressionError::ChecksumMismatch);
    check(14, 1, CompressionError::ChecksumMismatch);
    // The first block's checksum, then its data.
    // The magic (4 bytes), FLG, BD, the content size (8 bytes) and HC take 15 bytes.
    let size = u32::from_le_bytes(stream[15..19].try_into().unwrap()) as usize & 0x7FFF_FFFF;
    check(19 + size, 1, CompressionError::ChecksumMismatch);
    check(30, 1, CompressionError::ChecksumMismatch);
    // The content checksum.
    check(stream.len() - 1, 1, CompressionError::ChecksumMismatch);
    // A descriptor with reserved bits, another version, a reserved block size, re-checksummed.
    let descriptor = |flags: u8, block: u8| {
        let mut frame = LZ4FrameFormat::MAGIC.to_le_bytes().to_vec();
        frame.extend([flags, block, (XXH32::hash(0, &[flags, block]) >> 8) as u8]);
        frame.extend([0, 0, 0, 0]);
        frame
    };
    for (flags, block, error) in [
        (0x62, 0x40, invalid("reserved bits set")),
        (0x60, 0xC0, invalid("reserved bits set")),
        (0x60, 0x41, invalid("reserved bits set")),
        (0x80, 0x40, invalid("unsupported version")),
        (0x60, 0x30, invalid("invalid block maximum size")),
    ] {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&descriptor(flags, block), 100), Err(error), "{flags:#x} {block:#x}");
    }
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&descriptor(0x60, 0x40), 100).unwrap(), b"");
    let limited = LZ4DecompressorConfig { maximum_block_size: 1 << 16, ..LZ4DecompressorConfig::default() };
    assert_eq!(
        LZ4Decompressor::new(limited).decompress_to_vec(&descriptor(0x60, 0x70), 100),
        Err(CompressionError::LimitExceeded { limit: 1 << 16 })
    );
    // A block larger than the maximum, and an empty uncompressed block (valid, not an end mark).
    let mut frame = descriptor(0x60, 0x40);
    frame.truncate(7);
    frame.extend(((1u32 << 16) + 1).to_le_bytes());
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&frame, 100), Err(invalid("block larger than the maximum")));
    let mut frame = descriptor(0x60, 0x40);
    frame.truncate(7);
    frame.extend(0x8000_0000u32.to_le_bytes());
    frame.extend([0, 0, 0, 0]);
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&frame, 100).unwrap(), b"");
}

#[test]
fn lz4_frames_round_trip() {
    let configs = [
        LZ4Config::default(),
        LZ4Config { level: 9, independent_blocks: false, block_checksum: true, ..LZ4Config::default() },
        LZ4Config {
            level: 12,
            block_size: LZ4BlockSize::Maximum256KiB,
            content_checksum: false,
            ..LZ4Config::default()
        },
    ];
    for config in configs {
        let mut compressor = LZ4Compressor::new(config).unwrap();
        Streaming::round_trip(&mut compressor, &mut LZ4Decompressor::default(), Ending::Input, true);
        let single = LZ4DecompressorConfig { multiple_frames: false, ..LZ4DecompressorConfig::default() };
        compressor.reset();
        Streaming::round_trip(&mut compressor, &mut LZ4Decompressor::new(single), Ending::Marked, true);
    }
    // The content size and the dictionary with its identifier.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let dictionary = Vectors::bytes("codec/deflate/dictionary.bin");
    let config = LZ4Config {
        content_size: Some(text.len() as u64),
        dictionary: Some(dictionary.clone()),
        dictionary_identifier: Some(7),
        ..LZ4Config::default()
    };
    let stream = LZ4Compressor::new(config.clone()).unwrap().compress_to_vec(&text).unwrap();
    let decompressor_config = LZ4DecompressorConfig {
        dictionary: Some(dictionary.clone()),
        dictionary_identifier: Some(7),
        ..LZ4DecompressorConfig::default()
    };
    assert_eq!(LZ4Decompressor::new(decompressor_config).decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(
        LZ4Decompressor::default().decompress_to_vec(&stream, usize::MAX),
        Err(CompressionError::MissingDictionary { identifier: 7 })
    );
    let other = LZ4DecompressorConfig {
        dictionary: Some(dictionary),
        dictionary_identifier: Some(8),
        ..LZ4DecompressorConfig::default()
    };
    assert_eq!(
        LZ4Decompressor::new(other).decompress_to_vec(&stream, usize::MAX),
        Err(CompressionError::MissingDictionary { identifier: 7 })
    );
    assert_eq!(
        LZ4Compressor::new(config).unwrap().compress_to_vec(&text[1..]),
        Err(CompressionError::InvalidParameter)
    );
}
