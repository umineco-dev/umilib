//! LZSS against the streams of Haruhiko Okumura's reference, lzss.c.

use umilib::codec::lzss::{LZSSCompressor, LZSSConfig, LZSSDecompressor};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Streaming};

const NAMES: [&str; 4] = ["text", "binary", "spaces", "one"];

#[test]
fn lzss_decompressors_read_the_streams_of_the_reference() {
    for (suffix, config) in
        [("11-4", LZSSConfig::default()), ("10-5", LZSSConfig { position_bits: 10, length_bits: 5 })]
    {
        for name in NAMES {
            let data = Vectors::bytes(&format!("codec/lzss/{name}.bin"));
            let stream = Vectors::bytes(&format!("codec/lzss/{name}.{suffix}.lzss"));
            let mut decompressor = LZSSDecompressor::new(config).unwrap();
            assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).unwrap(), data, "{name}.{suffix}");
            Streaming::check(&mut decompressor, &stream, &data, Ending::Input);
        }
    }
}

#[test]
fn lzss_compressors_write_the_streams_of_the_reference() {
    // The reference encodes greedily with the nearest of the longest matches within N - F
    // bytes, as the compressor does; on these inputs its chains cover every candidate.
    for (suffix, config) in
        [("11-4", LZSSConfig::default()), ("10-5", LZSSConfig { position_bits: 10, length_bits: 5 })]
    {
        for name in NAMES {
            let data = Vectors::bytes(&format!("codec/lzss/{name}.bin"));
            let stream = Vectors::bytes(&format!("codec/lzss/{name}.{suffix}.lzss"));
            let mut compressor = LZSSCompressor::new(config).unwrap();
            assert_eq!(compressor.compress_to_vec(&data).unwrap(), stream, "{name}.{suffix}");
        }
    }
}

#[test]
fn lzss_streams_follow_their_format() {
    // "A": a literal, 1 then the 8 bits of 0x41, most significant first, padded with zeros.
    let stream = LZSSCompressor::new(LZSSConfig::default()).unwrap().compress_to_vec(b"A").unwrap();
    assert_eq!(stream, [0b1010_0000, 0b1000_0000]);
    // Four spaces: a match of the spaces the ring starts with, at the position just before
    // N - F = 2031 (EI = 11), of length 4 (j = 2): 0, 2030 in 11 bits, 2 in 4 bits.
    let stream = LZSSCompressor::new(LZSSConfig::default()).unwrap().compress_to_vec(b"    ").unwrap();
    let bits = format!("0{:011b}{:04b}", 2030, 2);
    let expected: Vec<u8> =
        (0..2).map(|index| u8::from_str_radix(&bits[8 * index..8 * index + 8], 2).unwrap()).collect();
    assert_eq!(stream, expected);
    // The input may end with fewer than 8 zero bits, not with more or with other bits.
    let mut decompressor = LZSSDecompressor::new(LZSSConfig::default()).unwrap();
    assert_eq!(decompressor.decompress_to_vec(&[0b1010_0000, 0b1000_0000], 10).unwrap(), b"A");
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[0b1010_0000, 0b1000_0001], 10), Err(CompressionError::UnexpectedEnd));
    decompressor.reset();
    assert_eq!(
        decompressor.decompress_to_vec(&[0b1010_0000, 0b1000_0000, 0], 10),
        Err(CompressionError::UnexpectedEnd)
    );
}

#[test]
fn lzss_streams_round_trip() {
    for config in [
        LZSSConfig::default(),
        LZSSConfig { position_bits: 10, length_bits: 5 },
        LZSSConfig { position_bits: 5, length_bits: 2 },
    ] {
        let mut compressor = LZSSCompressor::new(config).unwrap();
        Streaming::round_trip(&mut compressor, &mut LZSSDecompressor::new(config).unwrap(), Ending::Input, false);
    }
    for invalid in [
        LZSSConfig { position_bits: 4, length_bits: 4 },
        LZSSConfig { position_bits: 4, length_bits: 2 },
        LZSSConfig { position_bits: 25, length_bits: 4 },
        LZSSConfig { position_bits: 11, length_bits: 0 },
    ] {
        assert_eq!(LZSSCompressor::new(invalid), Err(CompressionError::InvalidParameter));
        assert_eq!(LZSSDecompressor::new(invalid), Err(CompressionError::InvalidParameter));
    }
}
