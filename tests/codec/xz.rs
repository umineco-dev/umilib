//! .xz (The .xz File Format 1.2.1): the test files of XZ Utils, the files of
//! the xz tool with every filter and check, the structure of the fields,
//! and round trips.

use umilib::codec::filter::bcj::BCJArchitecture;
use umilib::codec::lzma::LZMAConfig;
use umilib::codec::xz::{
    XZBlockHeader, XZCheck, XZCompressor, XZConfig, XZDecompressor, XZDecompressorConfig, XZFilter, XZFormat,
    XZIntegerReader,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};
use umilib::hash::Digest;
use umilib::hash::sha::v2::SHA256;

use crate::Vectors;
use crate::compression::{Ending, Streaming};

fn decode(stream: &[u8]) -> Result<Vec<u8>, CompressionError> {
    XZDecompressor::default().decompress_to_vec(stream, 1 << 21)
}

fn invalid(reason: &'static str) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::InvalidData { reason })
}

fn file(name: &str) -> Vec<u8> {
    Vectors::bytes(&format!("codec/xz/xz-utils/{name}.xz"))
}

#[test]
fn integers_follow_section_1_2() {
    for (value, bytes) in [
        (0u64, &[0x00][..]),
        (0x7F, &[0x7F]),
        (0x80, &[0x80, 0x01]),
        (0x3FFF, &[0xFF, 0x7F]),
        (XZFormat::MAXIMUM_INTEGER, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
    ] {
        let mut out = Vec::new();
        XZFormat::write_integer(value, &mut out);
        assert_eq!(out, bytes);
        assert_eq!(XZFormat::read_integer(bytes), Ok((value, bytes.len())));
    }
    // A superfluous zero byte, a tenth byte, a truncated integer.
    assert!(XZFormat::read_integer(&[0x80, 0x00]).is_err());
    assert!(XZFormat::read_integer(&[0xFF; 10]).is_err());
    assert!(XZFormat::read_integer(&[0x80]).is_err());
    let mut reader = XZIntegerReader::new();
    assert_eq!(reader.push(0x81), Ok(None));
    assert_eq!(reader.push(0x01), Ok(Some(0x81)));
    assert_eq!(reader.push(0x05), Ok(Some(5)));
}

#[test]
fn checks_follow_section_2_1_1_2() {
    for (check, id, size) in
        [(XZCheck::None, 0x00, 0), (XZCheck::CRC32, 0x01, 4), (XZCheck::CRC64, 0x04, 8), (XZCheck::SHA256, 0x0A, 32)]
    {
        assert_eq!((check.id(), check.size(), XZFormat::check_size(id)), (id, size, size));
        assert_eq!(XZCheck::from_id(id), Ok(check));
    }
    for id in [0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F] {
        assert!(matches!(XZCheck::from_id(id), Err(CompressionError::Unsupported { .. })));
    }
    assert_eq!([0x02, 0x05, 0x07, 0x0B, 0x0D].map(XZFormat::check_size), [4, 8, 16, 32, 64]);
}

#[test]
fn block_headers_follow_section_3_1() {
    let header = XZBlockHeader {
        compressed_size: Some(1000),
        uncompressed_size: Some(5),
        filters: vec![
            XZFilter::Delta { distance: 4 },
            XZFilter::BCJ { architecture: BCJArchitecture::ARM64, start_offset: 4096 },
            XZFilter::LZMA2 { dictionary_size: 1 << 23 },
        ],
    };
    let bytes = header.encode();
    assert_eq!(bytes.len() % 4, 0);
    assert_eq!(XZBlockHeader::size(bytes[0]), bytes.len());
    // Three filters and both sizes.
    assert_eq!(bytes[1], 0x02 | 0x40 | 0x80);
    assert_eq!(XZBlockHeader::decode(&bytes), Ok(header.clone()));
    // A CRC32 mismatch, a reserved flag (the CRC32 recomputed), an unknown filter, LZMA2 not last.
    let mut corrupt = bytes.clone();
    corrupt[2] ^= 1;
    assert!(matches!(XZBlockHeader::decode(&corrupt), Err(CompressionError::InvalidData { .. })));
    let mut reserved = bytes.clone();
    reserved[1] |= 0x04;
    let crc = XZFormat::crc32(&reserved[..reserved.len() - 4]);
    let end = reserved.len();
    reserved[end - 4..].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(XZBlockHeader::decode(&reserved), Err(CompressionError::Unsupported { .. })));
    // The LZMA2 dictionary sizes of section 5.3.1.
    for (byte, size) in [(0u8, 4096u64), (1, 6144), (2, 8192), (35, 768 << 20), (39, 3072 << 20), (40, u32::MAX as u64)]
    {
        assert_eq!(XZFilter::from_flags(0x21, &[byte]), Ok(XZFilter::LZMA2 { dictionary_size: size }));
    }
    assert!(matches!(XZFilter::from_flags(0x21, &[41]), Err(CompressionError::Unsupported { .. })));
    assert!(matches!(XZFilter::from_flags(0x21, &[0x40]), Err(CompressionError::Unsupported { .. })));
    assert!(matches!(XZFilter::from_flags(0x7F, &[]), Err(CompressionError::Unsupported { .. })));
    // BCJ start offsets: 0 or 4 bytes, a multiple of the alignment; Delta: distance - 1.
    assert_eq!(
        XZFilter::from_flags(0x07, &[0x10, 0, 0, 0]),
        Ok(XZFilter::BCJ { architecture: BCJArchitecture::ARM, start_offset: 16 })
    );
    assert!(XZFilter::from_flags(0x07, &[0x11, 0, 0, 0]).is_err());
    assert!(XZFilter::from_flags(0x07, &[0x10, 0]).is_err());
    assert_eq!(XZFilter::from_flags(0x03, &[0xFF]), Ok(XZFilter::Delta { distance: 256 }));
}

/// The good files of XZ Utils with their outputs.
const GOOD: [&str; 21] = [
    "good-0-empty",
    "good-0cat-empty",
    "good-0catpad-empty",
    "good-0pad-empty",
    "good-1-3delta-lzma2",
    "good-1-arm64-lzma2-1",
    "good-1-arm64-lzma2-2",
    "good-1-block_header-1",
    "good-1-block_header-2",
    "good-1-block_header-3",
    "good-1-check-crc32",
    "good-1-check-crc64",
    "good-1-check-none",
    "good-1-check-sha256",
    "good-1-empty-bcj-lzma2",
    "good-1-lzma2-1",
    "good-1-lzma2-2",
    "good-1-lzma2-3",
    "good-1-lzma2-4",
    "good-1-lzma2-5",
    "good-2-lzma2",
];

#[test]
fn xz_decompressors_read_the_good_files_of_xz_utils() {
    for name in GOOD {
        let data = Vectors::bytes(&format!("codec/xz/xz-utils/{name}.out"));
        Streaming::check(&mut XZDecompressor::default(), &file(name), &data, Ending::Input);
    }
    let image = XZDecompressor::default().decompress_to_vec(&file("good-1-delta-lzma2.tiff"), 1 << 20).unwrap();
    let expected = Vectors::read("codec/xz/xz-utils/good-1-delta-lzma2.tiff.sha256");
    assert_eq!(Vectors::hex(expected.trim()), SHA256::digest(&image));
}

#[test]
fn xz_decompressors_reject_the_bad_and_unsupported_files_of_xz_utils() {
    for (name, expected) in [
        ("unsupported-check", Err(CompressionError::Unsupported { feature: "reserved check type" })),
        ("unsupported-block_header", Err(CompressionError::Unsupported { feature: "non-zero block header padding" })),
        ("unsupported-filter_flags-1", Err(CompressionError::Unsupported { feature: "unknown filter" })),
        ("unsupported-filter_flags-2", Err(CompressionError::Unsupported { feature: "filter chain" })),
        ("unsupported-filter_flags-3", Err(CompressionError::Unsupported { feature: "filter chain" })),
        ("bad-0-empty-truncated", Err(CompressionError::UnexpectedEnd)),
        // Five bytes of Stream Padding at the end: the input ends inside a four-byte unit.
        ("bad-0pad-empty", Err(CompressionError::UnexpectedEnd)),
        ("bad-0catpad-empty", invalid("stream padding not a multiple of four bytes")),
        ("bad-0cat-alone", invalid("not a .xz stream")),
        ("bad-0cat-header_magic", invalid("not a .xz stream")),
        ("bad-0-header_magic", invalid("not a .xz stream")),
        ("bad-0-footer_magic", invalid("stream footer magic mismatch")),
        // The Record of a Block that is not there has an Unpadded Size of 0.
        ("bad-0-nonempty_index", invalid("invalid unpadded size")),
        ("bad-0-backward_size", invalid("backward size does not match the index")),
        // A huge Number of Records: the bytes after it are read as a Record, of an Unpadded Size of 0.
        ("bad-0-index-1", invalid("invalid unpadded size")),
        ("bad-1-stream_flags-1", invalid("stream flags of the header and footer differ")),
        ("bad-1-stream_flags-2", invalid("stream header CRC32 mismatch")),
        ("bad-1-stream_flags-3", invalid("stream footer CRC32 mismatch")),
        ("bad-1-vli-1", invalid("integer with a superfluous zero byte")),
        ("bad-1-vli-2", invalid("integer longer than 9 bytes")),
        ("bad-1-block_header-1", invalid("filter properties beyond the block header")),
        ("bad-1-block_header-3", invalid("block header CRC32 mismatch")),
        ("bad-1-block_header-4", invalid("compressed size too large")),
        ("bad-1-block_header-5", invalid("compressed size of zero")),
        ("bad-2-index-1", invalid("index does not match the blocks")),
        ("bad-2-index-2", invalid("index does not match the blocks")),
        ("bad-2-index-3", invalid("non-zero index padding")),
        ("bad-2-index-4", invalid("index CRC32 mismatch")),
        ("bad-2-index-5", invalid("invalid unpadded size")),
        ("bad-3-index-uncomp-overflow", invalid("data larger than 2^63 - 1 bytes")),
        ("bad-2-compressed_data_padding", invalid("non-zero block padding")),
        ("bad-1-check-crc32", Err(CompressionError::ChecksumMismatch)),
        ("bad-1-check-crc32-2", Err(CompressionError::ChecksumMismatch)),
        ("bad-1-check-crc64", Err(CompressionError::ChecksumMismatch)),
        ("bad-1-check-sha256", Err(CompressionError::ChecksumMismatch)),
    ] {
        assert_eq!(decode(&file(name)), expected, "{name}");
    }
    // The other bad files fail too (their reasons come from the LZMA2 decoder and the sizes).
    for name in [
        "bad-1-block_header-2",
        "bad-1-block_header-6",
        "bad-1-index-huge-uncomp",
        "bad-1-lzma2-1",
        "bad-1-lzma2-2",
        "bad-1-lzma2-3",
        "bad-1-lzma2-4",
        "bad-1-lzma2-5",
        "bad-1-lzma2-6",
        "bad-1-lzma2-7",
        "bad-1-lzma2-8",
        "bad-1-lzma2-9",
        "bad-1-lzma2-10",
        "bad-1-lzma2-11",
    ] {
        let result = decode(&file(name));
        assert!(result.is_err(), "{name}: {result:?}");
    }
}

const STREAMS: [(&str, &str); 22] = [
    ("bcj.x86", "codec/xz/bcj.bin"),
    ("bcj.powerpc", "codec/xz/bcj.bin"),
    ("bcj.ia64", "codec/xz/bcj.bin"),
    ("bcj.arm", "codec/xz/bcj.bin"),
    ("bcj.armthumb", "codec/xz/bcj.bin"),
    ("bcj.sparc", "codec/xz/bcj.bin"),
    ("bcj.arm64", "codec/xz/bcj.bin"),
    ("bcj.riscv", "codec/xz/bcj.bin"),
    ("bcj.x86-start", "codec/xz/bcj.bin"),
    ("bcj.arm64-start", "codec/xz/bcj.bin"),
    ("bcj.riscv-start", "codec/xz/bcj.bin"),
    ("bcj.chain", "codec/xz/bcj.bin"),
    ("bcj.plain", "codec/xz/bcj.bin"),
    ("text.none", "codec/deflate/text.bin"),
    ("text.crc32", "codec/deflate/text.bin"),
    ("text.crc64", "codec/deflate/text.bin"),
    ("text.sha256", "codec/deflate/text.bin"),
    ("text.level0", "codec/deflate/text.bin"),
    ("text.level9", "codec/deflate/text.bin"),
    ("text.blocks", "codec/deflate/text.bin"),
    ("text.threads", "codec/deflate/text.bin"),
    ("random", "codec/deflate/random.bin"),
];

#[test]
fn xz_decompressors_read_the_files_of_xz() {
    for (name, input) in STREAMS {
        let data = Vectors::bytes(input);
        let stream = Vectors::bytes(&format!("codec/xz/{name}.xz"));
        Streaming::check(&mut XZDecompressor::default(), &stream, &data, Ending::Input);
        let single = XZDecompressorConfig { multiple_streams: false, ..XZDecompressorConfig::default() };
        Streaming::check(&mut XZDecompressor::new(single), &stream, &data, Ending::Marked);
    }
    // Two Streams with Stream Padding between and after them.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let mut decompressor = XZDecompressor::default();
    let stream = Vectors::bytes("codec/xz/text.concatenated.xz");
    assert_eq!(decompressor.decompress_to_vec(&stream, usize::MAX).unwrap(), text);
    assert_eq!(decompressor.streams(), 2);
    // One Stream: what follows is not consumed.
    let single = XZDecompressorConfig { multiple_streams: false, ..XZDecompressorConfig::default() };
    let mut decompressor = XZDecompressor::new(single);
    let mut out = vec![0u8; text.len() + 1];
    let progress = decompressor.decompress(&stream, &mut out).unwrap();
    assert!(progress.finished);
    assert_eq!(progress.consumed, Vectors::bytes("codec/xz/text.crc64.xz").len());
    // A dictionary above the limit: xz -9 uses 64 MiB.
    let limited = XZDecompressorConfig { maximum_dictionary_size: 1 << 20, ..XZDecompressorConfig::default() };
    assert_eq!(
        XZDecompressor::new(limited).decompress_to_vec(&Vectors::bytes("codec/xz/text.level9.xz"), usize::MAX),
        Err(CompressionError::LimitExceeded { limit: 1 << 20 })
    );
}

#[test]
fn xz_streams_round_trip() {
    let configs = [
        XZConfig::default(),
        XZConfig { check: XZCheck::None, ..XZConfig::default() },
        XZConfig {
            check: XZCheck::CRC32,
            lzma: LZMAConfig { level: 0, ..LZMAConfig::default() },
            ..XZConfig::default()
        },
        XZConfig { check: XZCheck::SHA256, block_size: Some(1000), ..XZConfig::default() },
        XZConfig {
            filters: vec![
                XZFilter::Delta { distance: 2 },
                XZFilter::BCJ { architecture: BCJArchitecture::X86, start_offset: 0 },
            ],
            ..XZConfig::default()
        },
        XZConfig {
            filters: vec![XZFilter::BCJ { architecture: BCJArchitecture::RISCV, start_offset: 2 }],
            block_size: Some(3333),
            ..XZConfig::default()
        },
    ];
    for config in configs {
        let mut compressor = XZCompressor::new(config).unwrap();
        Streaming::round_trip(&mut compressor, &mut XZDecompressor::default(), Ending::Input, true);
    }
    // The empty stream is the same as that of xz: its fields leave no choice.
    assert_eq!(XZCompressor::default().compress_to_vec(b"").unwrap(), Vectors::bytes("codec/xz/empty.xz"));
    // Every BCJ filter, against the input of the xz files.
    let data = Vectors::bytes("codec/xz/bcj.bin");
    for architecture in BCJArchitecture::ALL {
        let config = XZConfig { filters: vec![XZFilter::BCJ { architecture, start_offset: 0 }], ..XZConfig::default() };
        let stream = XZCompressor::new(config).unwrap().compress_to_vec(&data).unwrap();
        assert_eq!(decode(&stream).unwrap(), data, "{architecture:?}");
    }
    for invalid in [
        XZConfig { block_size: Some(0), ..XZConfig::default() },
        XZConfig { filters: vec![XZFilter::LZMA2 { dictionary_size: 1 << 20 }], ..XZConfig::default() },
        XZConfig { filters: vec![XZFilter::Delta { distance: 0 }], ..XZConfig::default() },
        XZConfig {
            filters: vec![XZFilter::BCJ { architecture: BCJArchitecture::ARM, start_offset: 2 }],
            ..XZConfig::default()
        },
        XZConfig { filters: vec![XZFilter::Delta { distance: 1 }; 4], ..XZConfig::default() },
    ] {
        assert!(XZCompressor::new(invalid).is_err());
    }
    // Compared with xz -6, at most a fifth larger, as the .lzma files of this LZMA encoder.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let reference = Vectors::bytes("codec/xz/text.crc64.xz");
    let ours = XZCompressor::default().compress_to_vec(&text).unwrap();
    assert!(ours.len() <= reference.len() + reference.len() / 5, "{} against {}", ours.len(), reference.len());
}
