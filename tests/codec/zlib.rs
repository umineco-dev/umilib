//! zlib (RFC 1950): the streams of zlib, the header checks, dictionaries and the Adler-32 trailer.

use umilib::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};
use umilib::codec::zlib::{ZlibCompressor, ZlibDecompressor, ZlibFormat};
use umilib::codec::{CompressionError, Compressor, Decompressor};
use umilib::hash::adler32::Adler32;

use crate::Vectors;
use crate::compression::{Ending, Streaming};

#[test]
fn zlib_decompressors_read_the_streams_of_zlib() {
    let text = Vectors::bytes("codec/deflate/text.bin");
    for level in [0, 1, 6, 9] {
        let stream = Vectors::bytes(&format!("codec/zlib/text.level{level}.zz"));
        Streaming::check(&mut ZlibDecompressor::default(), &stream, &text, Ending::Marked);
    }
    Streaming::check(&mut ZlibDecompressor::default(), &Vectors::bytes("codec/zlib/empty.zz"), b"", Ending::Marked);
    let repetitive = Vectors::bytes("codec/deflate/repetitive.bin");
    let small = Vectors::bytes("codec/zlib/repetitive.window9.zz");
    let config = DeflateDecompressorConfig { window_bits: 9 };
    assert_eq!(ZlibDecompressor::new(config).unwrap().decompress_to_vec(&small, repetitive.len()).unwrap(), repetitive);
    // A header that announces a larger window than the decompressor keeps.
    let large = Vectors::bytes("codec/zlib/text.level9.zz");
    assert_eq!(
        ZlibDecompressor::new(config).unwrap().decompress_to_vec(&large, text.len()),
        Err(CompressionError::LimitExceeded { limit: 512 })
    );
    // The dictionary named by its Adler-32.
    let dictionary = Vectors::bytes("codec/deflate/dictionary.bin");
    let stream = Vectors::bytes("codec/zlib/text.dictionary.zz");
    let identifier = Adler32::checksum(&dictionary);
    assert_eq!(u32::from_be_bytes(stream[2..6].try_into().unwrap()), identifier);
    let mut decompressor =
        ZlibDecompressor::with_dictionary(DeflateDecompressorConfig::default(), &dictionary).unwrap();
    assert_eq!(decompressor.decompress_to_vec(&stream, text.len()).unwrap(), text);
    assert_eq!(
        ZlibDecompressor::default().decompress_to_vec(&stream, text.len()),
        Err(CompressionError::MissingDictionary { identifier })
    );
    let mut other = ZlibDecompressor::with_dictionary(DeflateDecompressorConfig::default(), b"other").unwrap();
    assert_eq!(other.decompress_to_vec(&stream, text.len()), Err(CompressionError::MissingDictionary { identifier }));
}

#[test]
fn zlib_headers_follow_rfc1950() {
    // CMF: CM 8, CINFO 7; FLG: FCHECK makes CMF × 256 + FLG a multiple of 31.
    for (window_bits, level, dictionary) in [(15, 6, false), (15, 9, true), (9, 1, false), (8, 0, true)] {
        let [method, flags] = ZlibFormat::header(window_bits, level, dictionary);
        assert_eq!(method, 8 | ((window_bits - 8) as u8) << 4);
        assert_eq!((method as u16 * 256 + flags as u16) % 31, 0);
        assert_eq!(flags & 0x20 != 0, dictionary);
    }
    // zlib's default header 78 9C (level 6), 78 DA (level 9), 78 01 (levels 0 and 1).
    assert_eq!(ZlibFormat::header(15, 6, false), [0x78, 0x9C]);
    assert_eq!(ZlibFormat::header(15, 9, false), [0x78, 0xDA]);
    assert_eq!(ZlibFormat::header(15, 1, false), [0x78, 0x01]);
    let invalid = |reason| Err(CompressionError::InvalidData { reason });
    let mut decompressor = ZlibDecompressor::default();
    for (stream, error) in [
        (&[0x79, 0x9C][..], invalid("invalid compression method")),
        (&[0x88, 0x98][..], invalid("invalid compression method")),
        (&[0x78, 0x9D][..], invalid("invalid header check")),
    ] {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(stream, 10), error);
    }
    // A wrong Adler-32.
    let mut stream = ZlibCompressor::new(DeflateConfig::default()).unwrap().compress_to_vec(b"data").unwrap();
    *stream.last_mut().unwrap() ^= 1;
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&stream, 10), Err(CompressionError::ChecksumMismatch));
}

#[test]
fn zlib_compressors_write_the_streams_zlib_writes_for_empty_input() {
    // 78 9C, an empty fixed block 03 00, and the Adler-32 of nothing, 1.
    let stream = ZlibCompressor::new(DeflateConfig::default()).unwrap().compress_to_vec(b"").unwrap();
    assert_eq!(stream, Vectors::bytes("codec/zlib/empty.zz"));
    let dictionary = Vectors::bytes("codec/deflate/dictionary.bin");
    let text = Vectors::bytes("codec/deflate/text.bin");
    let mut compressor = ZlibCompressor::with_dictionary(DeflateConfig::default(), &dictionary).unwrap();
    let stream = compressor.compress_to_vec(&text).unwrap();
    let mut decompressor =
        ZlibDecompressor::with_dictionary(DeflateDecompressorConfig::default(), &dictionary).unwrap();
    assert_eq!(decompressor.decompress_to_vec(&stream, text.len()).unwrap(), text);
    compressor.reset();
    assert_eq!(compressor.compress_to_vec(&text).unwrap(), stream);
}

#[test]
fn zlib_streams_round_trip() {
    for level in [0, 6, 9] {
        let mut compressor = ZlibCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap();
        Streaming::round_trip(&mut compressor, &mut ZlibDecompressor::default(), Ending::Marked, true);
    }
}
