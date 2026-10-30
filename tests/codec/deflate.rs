//! Deflate (RFC 1951): the streams zlib makes with every block kind, level,
//! flush and dictionary, the checks of the format, and round trips.

use umilib::codec::deflate::{
    DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig, DeflateFormat,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Streaming};

const INPUTS: [&str; 6] = ["empty", "one", "text", "random", "zeros", "repetitive"];

/// The vectors: (input name, stream name).
fn streams() -> Vec<(String, String)> {
    let mut streams = Vec::new();
    for name in INPUTS {
        for level in [0, 1, 6, 9] {
            streams.push((name.to_string(), format!("{name}.level{level}")));
        }
    }
    for name in ["text", "repetitive"] {
        for kind in ["huffman", "rle", "fixed", "sync", "full"] {
            streams.push((name.to_string(), format!("{name}.{kind}")));
        }
    }
    streams
}

#[test]
fn deflate_decompressors_read_the_streams_of_zlib() {
    for (input, stream) in streams() {
        let data = Vectors::bytes(&format!("codec/deflate/{input}.bin"));
        let stream = Vectors::bytes(&format!("codec/deflate/{stream}.deflate"));
        let mut decompressor = DeflateDecompressor::default();
        assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).unwrap(), data, "{input}");
        Streaming::check(&mut decompressor, &stream, &data, Ending::Marked);
    }
    // A window of 2^9 bytes is enough for the streams made with it, not for the others.
    for name in ["text", "repetitive"] {
        let data = Vectors::bytes(&format!("codec/deflate/{name}.bin"));
        let small = Vectors::bytes(&format!("codec/deflate/{name}.window9.deflate"));
        let mut decompressor = DeflateDecompressor::new(DeflateDecompressorConfig { window_bits: 9 }).unwrap();
        assert_eq!(decompressor.decompress_to_vec(&small, data.len()).unwrap(), data);
        decompressor.reset();
        let large = Vectors::bytes(&format!("codec/deflate/{name}.level9.deflate"));
        assert_eq!(
            decompressor.decompress_to_vec(&large, data.len()),
            Err(CompressionError::LimitExceeded { limit: 512 })
        );
    }
    // A preset dictionary is the history before the data.
    let data = Vectors::bytes("codec/deflate/text.bin");
    let stream = Vectors::bytes("codec/deflate/text.dictionary.deflate");
    let mut decompressor = DeflateDecompressor::default();
    decompressor.set_dictionary(&Vectors::bytes("codec/deflate/dictionary.bin"));
    assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).unwrap(), data);
    decompressor.reset();
    assert_eq!(
        decompressor.decompress_to_vec(&stream, data.len()),
        Err(CompressionError::InvalidData { reason: "distance too far back" })
    );
}

#[test]
fn deflate_formats_map_lengths_and_distances_to_their_symbols() {
    // Section 3.2.5: every length and distance falls in the range of its symbol.
    for length in 3..=258 {
        let index = DeflateFormat::length_index(length);
        let base = DeflateFormat::LENGTH_BASES[index] as usize;
        assert!(length >= base && length - base < 1 << DeflateFormat::LENGTH_EXTRA_BITS[index], "length {length}");
    }
    assert_eq!(DeflateFormat::length_index(258), 28);
    assert_eq!(DeflateFormat::length_index(257), 27);
    for distance in 1..=32768 {
        let symbol = DeflateFormat::distance_symbol(distance);
        let base = DeflateFormat::DISTANCE_BASES[symbol] as usize;
        assert!(
            distance >= base && distance - base < 1 << DeflateFormat::DISTANCE_EXTRA_BITS[symbol],
            "distance {distance}"
        );
    }
    // Section 3.2.6: the fixed literal/length code.
    let lengths = DeflateFormat::fixed_literal_length_lengths();
    assert_eq!(
        (lengths[143], lengths[144], lengths[255], lengths[256], lengths[279], lengths[280], lengths[287]),
        (8, 9, 9, 7, 7, 8, 8)
    );
}

/// A stream of bits written least significant first, from fields (value, bits).
fn bits(fields: &[(u32, u32)]) -> Vec<u8> {
    let mut writer = umilib::bytes::BitWriter::new();
    for (value, count) in fields {
        writer.write(*value as u64, *count);
    }
    writer.finish()
}

#[test]
fn deflate_decompressors_check_the_format() {
    let mut decompressor = DeflateDecompressor::default();
    let mut check = |stream: Vec<u8>, error: CompressionError| {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&stream, 1000), Err(error));
    };
    let invalid = |reason| CompressionError::InvalidData { reason };
    // BTYPE 11 (section 3.2.3).
    check(bits(&[(1, 1), (3, 2)]), invalid("invalid block type"));
    // A stored block whose NLEN is not the complement of LEN.
    check(vec![0x01, 0x05, 0x00, 0xFA, 0xFE, 1, 2, 3, 4, 5], invalid("invalid stored block lengths"));
    // HLIT of 287 and 288 codes, HDIST of 31 and 32 codes.
    check(bits(&[(1, 1), (2, 2), (30, 5), (0, 5), (0, 4)]), invalid("too many length or distance codes"));
    check(bits(&[(1, 1), (2, 2), (0, 5), (30, 5), (0, 4)]), invalid("too many length or distance codes"));
    // A code length code with lengths 1, 1, 1 (for 16, 17, 18) is over-subscribed; with one length of 1 it is incomplete.
    check(
        bits(&[(1, 1), (2, 2), (0, 5), (0, 5), (0, 4), (1, 3), (1, 3), (1, 3), (0, 3)]),
        invalid("over-subscribed code lengths"),
    );
    check(
        bits(&[(1, 1), (2, 2), (0, 5), (0, 5), (0, 4), (0, 3), (0, 3), (1, 3), (0, 3)]),
        invalid("incomplete code lengths"),
    );
    // Code length code: 16 and 18 of 1 bit (16 is 0, 18 is 1); a first 16 has no length to repeat.
    let header = [(1, 1), (2, 2), (0, 5), (0, 5), (0, 4), (1, 3), (0, 3), (1, 3), (0, 3)];
    check(bits(&[&header[..], &[(0, 1), (0, 2)]].concat()), invalid("repeat with no previous length"));
    // 18 with 138 zeros twice is beyond the 258 lengths.
    check(bits(&[&header[..], &[(1, 1), (127, 7), (1, 1), (127, 7)]].concat()), invalid("too many code lengths"));
    // 258 zeros: no code for the end of the block.
    check(
        bits(&[&header[..], &[(1, 1), (127, 7), (1, 1), (109, 7)]].concat()),
        invalid("no code for the end of the block"),
    );
    // Fixed codes: the literal/length symbols 286 and 287 (codes 11000110 and 11000111) do not occur in data.
    check(bits(&[(1, 1), (1, 2), (0b0110_0011, 8)]), invalid("invalid literal/length symbol"));
    check(bits(&[(1, 1), (1, 2), (0b1110_0011, 8)]), invalid("invalid literal/length symbol"));
    // Fixed codes: a match of 3 (symbol 257, code 0000001) at distance symbol 30 (11110), then one 1 back with nothing before.
    check(bits(&[(1, 1), (1, 2), (0b100_0000, 7), (0b01111, 5)]), invalid("invalid distance symbol"));
    check(bits(&[(1, 1), (1, 2), (0b100_0000, 7), (0, 5)]), invalid("distance too far back"));
    // A stream that ends before its last block.
    check(bits(&[(0, 1), (1, 2), (0, 7)]), CompressionError::UnexpectedEnd);
}

#[test]
fn deflate_decompressors_accept_what_the_format_allows() {
    let mut decompressor = DeflateDecompressor::default();
    // An empty fixed block (zlib's empty stream), and stored blocks of 0 bytes before a last one.
    assert_eq!(decompressor.decompress_to_vec(&[0x03, 0x00], 10).unwrap(), b"");
    decompressor.reset();
    let stream = [0x00, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x02, 0x00, 0xFD, 0xFF, b'h', b'i'];
    assert_eq!(decompressor.decompress_to_vec(&stream, 10).unwrap(), b"hi");
    // The bits after the 3 bits of a stored block header are ignored.
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[0xF9, 0x01, 0x00, 0xFE, 0xFF, b'x'], 10).unwrap(), b"x");
}

#[test]
fn deflate_compressors_write_streams_of_every_level() {
    for name in INPUTS {
        let data = Vectors::bytes(&format!("codec/deflate/{name}.bin"));
        for level in 0..=9 {
            let mut compressor = DeflateCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap();
            let stream = compressor.compress_to_vec(&data).unwrap();
            let mut decompressor = DeflateDecompressor::default();
            assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).unwrap(), data, "{name} level {level}");
            // zlib's level 9 is the reference: the compressor stays within a few percent of it.
            if level == 9 {
                let reference = Vectors::bytes(&format!("codec/deflate/{name}.level9.deflate"));
                assert!(
                    stream.len() <= reference.len() + reference.len() / 20 + 8,
                    "{name}: {} against {}",
                    stream.len(),
                    reference.len()
                );
            }
        }
    }
    // The empty stream is an empty fixed block, as zlib writes it.
    assert_eq!(DeflateCompressor::new(DeflateConfig::default()).unwrap().compress_to_vec(b"").unwrap(), [0x03, 0x00]);
    // A small window keeps every distance within it.
    let data = Vectors::bytes("codec/deflate/repetitive.bin");
    let stream =
        DeflateCompressor::new(DeflateConfig { level: 6, window_bits: 9 }).unwrap().compress_to_vec(&data).unwrap();
    let mut decompressor = DeflateDecompressor::new(DeflateDecompressorConfig { window_bits: 9 }).unwrap();
    assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).unwrap(), data);
    // Dictionaries.
    let dictionary = Vectors::bytes("codec/deflate/dictionary.bin");
    let text = Vectors::bytes("codec/deflate/text.bin");
    let mut compressor = DeflateCompressor::new(DeflateConfig::default()).unwrap();
    compressor.set_dictionary(&dictionary);
    let stream = compressor.compress_to_vec(&text).unwrap();
    let mut decompressor = DeflateDecompressor::default();
    decompressor.set_dictionary(&dictionary);
    assert_eq!(decompressor.decompress_to_vec(&stream, text.len()).unwrap(), text);
    for invalid in [
        DeflateConfig { level: 10, window_bits: 15 },
        DeflateConfig { level: 6, window_bits: 16 },
        DeflateConfig { level: 6, window_bits: 7 },
    ] {
        assert_eq!(DeflateCompressor::new(invalid), Err(CompressionError::InvalidParameter));
    }
}

#[test]
fn deflate_streams_round_trip() {
    for level in [0, 1, 4, 6, 9] {
        let mut compressor = DeflateCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap();
        Streaming::round_trip(&mut compressor, &mut DeflateDecompressor::default(), Ending::Marked, true);
    }
}

#[test]
fn streams_that_follow_the_last_block() {
    // RFC 1951 §3.2.3: BFINAL ends a stream; `resume` reads blocks that
    // follow at the next byte, their matches reaching back (RFC 7692 §7.2.3.4).
    use umilib::codec::Decompressor;
    use umilib::codec::deflate::{DeflateDecompressor, DeflateDecompressorConfig};
    let mut decompressor = DeflateDecompressor::new(DeflateDecompressorConfig::default()).unwrap();
    let mut out = [0u8; 64];
    // "Hello" with BFINAL (fixed codes), then "Hello" again as a match 5 back, with BFINAL.
    let progress = decompressor.decompress(&[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], &mut out).unwrap();
    assert!(progress.finished);
    assert_eq!(&out[..progress.produced], b"Hello");
    decompressor.resume();
    let progress = decompressor.decompress(&[0xf3, 0x00, 0x11, 0x00, 0x00], &mut out).unwrap();
    assert!(progress.finished);
    assert_eq!(&out[..progress.produced], b"Hello");
}
