//! gzip (RFC 1952): the files of Python and GNU gzip, headers and their
//! optional fields, members, and the CRC-32 and size trailer.

use umilib::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};
use umilib::codec::gzip::{GzipCompressor, GzipConfig, GzipDecompressor, GzipDecompressorConfig, GzipHeader};
use umilib::codec::{CompressionError, Compressor, Decompressor};
use umilib::hash::crc::{CRC, CRCCatalogue};

use crate::Vectors;
use crate::compression::{Ending, Streaming};

#[test]
fn gzip_decompressors_read_the_files_of_python_and_gzip() {
    let text = Vectors::bytes("codec/deflate/text.bin");
    let repetitive = Vectors::bytes("codec/deflate/repetitive.bin");
    for (file, data) in [
        ("text.python", &text),
        ("text.named", &text),
        ("repetitive.command", &repetitive),
        ("empty.python", &Vec::new()),
    ] {
        let stream = Vectors::bytes(&format!("codec/gzip/{file}.gz"));
        Streaming::check(&mut GzipDecompressor::default(), &stream, data, Ending::Input);
        let single = GzipDecompressorConfig { multiple_members: false, ..GzipDecompressorConfig::default() };
        Streaming::check(&mut GzipDecompressor::new(single).unwrap(), &stream, data, Ending::Marked);
    }
    let mut decompressor = GzipDecompressor::default();
    decompressor.decompress_to_vec(&Vectors::bytes("codec/gzip/text.named.gz"), text.len()).unwrap();
    let header = decompressor.header();
    assert_eq!(
        (header.name.as_deref(), header.modification_time, header.operating_system),
        (Some(&b"text.bin"[..]), 1761350400, 255)
    );
    // Members follow each other; zero bytes after the last are padding.
    let members = Vectors::bytes("codec/gzip/members.gz");
    let mut decompressor = GzipDecompressor::default();
    assert_eq!(
        decompressor.decompress_to_vec(&members, usize::MAX).unwrap(),
        [&text[..1000], &repetitive[..]].concat()
    );
    assert_eq!(decompressor.members(), 2);
    decompressor.reset();
    assert_eq!(
        decompressor.decompress_to_vec(&Vectors::bytes("codec/gzip/members.padded.gz"), usize::MAX).unwrap(),
        &text[..1000]
    );
    let mut garbage = Vectors::bytes("codec/gzip/members.padded.gz");
    garbage.push(1);
    decompressor.reset();
    assert_eq!(
        decompressor.decompress_to_vec(&garbage, usize::MAX),
        Err(CompressionError::InvalidData { reason: "data after the padding of the last member" })
    );
    // A single member leaves what follows it.
    let mut single =
        GzipDecompressor::new(GzipDecompressorConfig { multiple_members: false, ..GzipDecompressorConfig::default() })
            .unwrap();
    assert_eq!(single.decompress_to_vec(&members, usize::MAX).unwrap(), &text[..1000]);
    // No member at all is not a gzip file.
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[], 10), Err(CompressionError::UnexpectedEnd));
}

#[test]
fn gzip_headers_follow_rfc1952() {
    let header = GzipHeader {
        text: true,
        modification_time: 0x0102_0304,
        extra_flags: 0,
        operating_system: 3,
        extra: Some(b"AB\x02\x00xy".to_vec()),
        name: Some(b"name.txt".to_vec()),
        comment: Some(b"a comment\n".to_vec()),
        header_checksum: true,
    };
    let compressor = GzipCompressor::new(GzipConfig {
        deflate: DeflateConfig { level: 9, window_bits: 15 },
        header: header.clone(),
    })
    .unwrap();
    let bytes = compressor.header_bytes();
    // ID1 ID2 CM FLG MTIME XFL OS, XLEN and the extra field, the name, the comment, the CRC16.
    let mut expected = vec![0x1F, 0x8B, 8, 0x01 | 0x02 | 0x04 | 0x08 | 0x10, 4, 3, 2, 1, 2, 3, 6, 0];
    expected.extend(b"AB\x02\x00xy");
    expected.extend(b"name.txt\0a comment\n\0");
    let crc16 = CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, &expected) as u16;
    expected.extend(crc16.to_le_bytes());
    assert_eq!(bytes, expected);
    let mut compressor =
        GzipCompressor::new(GzipConfig { deflate: DeflateConfig::default(), header: header.clone() }).unwrap();
    let stream = compressor.compress_to_vec(b"payload").unwrap();
    let mut decompressor = GzipDecompressor::default();
    assert_eq!(decompressor.decompress_to_vec(&stream, 100).unwrap(), b"payload");
    assert_eq!(decompressor.header(), &header);
    // A corrupt header CRC, reserved flags, another method, another magic, a wrong CRC-32 or size.
    for (index, change, error) in [
        (bytes.len() - 1, 1u8, CompressionError::ChecksumMismatch),
        (3, 0x20, CompressionError::InvalidData { reason: "reserved flags set" }),
        (2, 1, CompressionError::InvalidData { reason: "invalid compression method" }),
        (1, 1, CompressionError::InvalidData { reason: "not a gzip member" }),
        (stream.len() - 8, 1, CompressionError::ChecksumMismatch),
        (stream.len() - 1, 1, CompressionError::ChecksumMismatch),
    ] {
        let mut corrupt = stream.clone();
        corrupt[index] ^= change;
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&corrupt, 100), Err(error), "byte {index}");
    }
    // A window smaller than the distances of the member's matches (RFC 1951 §3.2.5): gzip does
    // not announce its window, so the member fails; the whole 32 KiB, the default, reads it.
    let text = Vectors::bytes("codec/deflate/text.bin");
    let mut compressor = GzipCompressor::new(GzipConfig::default()).unwrap();
    let far = compressor.compress_to_vec(&[&text[..], &text[..]].concat()).unwrap();
    let small = GzipDecompressorConfig {
        deflate: DeflateDecompressorConfig { window_bits: 8 },
        ..GzipDecompressorConfig::default()
    };
    let result = GzipDecompressor::new(small).unwrap().decompress_to_vec(&far, usize::MAX);
    assert_eq!(result, Err(CompressionError::LimitExceeded { limit: 256 }));
    assert_eq!(
        GzipDecompressor::default().decompress_to_vec(&far, usize::MAX).unwrap(),
        [&text[..], &text[..]].concat()
    );
    let invalid = GzipDecompressorConfig {
        deflate: DeflateDecompressorConfig { window_bits: 16 },
        ..GzipDecompressorConfig::default()
    };
    assert!(GzipDecompressor::new(invalid).is_err());
    // Fields beyond the limit, and names with a zero byte.
    let mut limited =
        GzipDecompressor::new(GzipDecompressorConfig { maximum_field: 4, ..GzipDecompressorConfig::default() })
            .unwrap();
    assert_eq!(limited.decompress_to_vec(&stream, 100), Err(CompressionError::LimitExceeded { limit: 4 }));
    let zero = GzipHeader { name: Some(b"a\0b".to_vec()), ..GzipHeader::new() };
    assert!(GzipCompressor::new(GzipConfig { deflate: DeflateConfig::default(), header: zero }).is_err());
    // XFL follows the level unless set.
    let fast = GzipCompressor::new(GzipConfig {
        deflate: DeflateConfig { level: 1, window_bits: 15 },
        header: GzipHeader::new(),
    })
    .unwrap();
    assert_eq!(fast.header_bytes()[8], 4);
}

#[test]
fn gzip_files_round_trip() {
    for level in [0, 6, 9] {
        let config = GzipConfig { deflate: DeflateConfig { level, window_bits: 15 }, header: GzipHeader::new() };
        let mut compressor = GzipCompressor::new(config).unwrap();
        Streaming::round_trip(&mut compressor, &mut GzipDecompressor::default(), Ending::Input, true);
        let single = GzipDecompressorConfig { multiple_members: false, ..GzipDecompressorConfig::default() };
        compressor.reset();
        Streaming::round_trip(&mut compressor, &mut GzipDecompressor::new(single).unwrap(), Ending::Marked, true);
    }
}
