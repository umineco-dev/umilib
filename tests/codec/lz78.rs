//! LZ78: the pairs of the LZ78 format, the dictionary and its limits.

use umilib::codec::lz78::{
    LZ78Compressor, LZ78Config, LZ78Decompressor, LZ78DecompressorConfig, LZ78Dictionary, LZ78Format,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::compression::{Ending, Streaming};

/// The bits of `stream` least significant first, as a string.
fn bits(stream: &[u8]) -> String {
    stream.iter().flat_map(|byte| (0..8).map(move |bit| if byte >> bit & 1 == 1 { '1' } else { '0' })).collect()
}

/// `value` as `width` bits, least significant first.
fn field(value: u32, width: u32) -> String {
    (0..width).map(|bit| if value >> bit & 1 == 1 { '1' } else { '0' }).collect()
}

#[test]
fn lz78_streams_follow_their_format() {
    // "ababa": (0, a) -> 1, (0, b) -> 2, (1, b) -> 3, then "a" is pending: the marker 4, the phrase 1 and 1.
    let stream = LZ78Compressor::new(LZ78Config { dictionary_bits: 4 }).unwrap().compress_to_vec(b"ababa").unwrap();
    assert_eq!(stream[0], 4);
    let expected = [
        field(0, 1),
        field(b'a' as u32, 8),
        field(0, 2),
        field(b'b' as u32, 8),
        field(1, 2),
        field(b'b' as u32, 8),
        field(4, 3),
        field(1, 3),
        field(1, 1),
    ]
    .concat();
    let actual = bits(&stream[1..]);
    assert_eq!(&actual[..expected.len()], expected);
    assert!(actual[expected.len()..].chars().all(|bit| bit == '0') && actual.len() - expected.len() < 8);
    assert_eq!(LZ78Format::width(0), 1);
    assert_eq!(LZ78Format::width(3), 3);
}

#[test]
fn lz78_dictionaries_empty_when_full() {
    let mut dictionary = LZ78Dictionary::new(4, true);
    assert_eq!(dictionary.add(0, b'a'), 1);
    assert_eq!(dictionary.add(1, b'b'), 2);
    assert_eq!(dictionary.child(1, b'b'), Some(2));
    assert_eq!(dictionary.child(2, b'b'), None);
    let mut out = [0u8; 2];
    dictionary.write(2, &mut out);
    assert_eq!(&out, b"ab");
    dictionary.add(2, b'c');
    dictionary.add(0, b'd');
    assert!(dictionary.is_empty());
    assert_eq!(dictionary.child(0, b'a'), None);
    // A small dictionary fills and empties many times within one stream.
    let data: Vec<u8> = (0..20000u32).map(|index| (index * index % 251) as u8).collect();
    let stream = LZ78Compressor::new(LZ78Config { dictionary_bits: 3 }).unwrap().compress_to_vec(&data).unwrap();
    assert_eq!(LZ78Decompressor::default().decompress_to_vec(&stream, data.len()).unwrap(), data);
}

#[test]
fn lz78_decompressors_check_their_streams() {
    let mut decompressor = LZ78Decompressor::new(LZ78DecompressorConfig { maximum_dictionary_bits: 12 });
    for (stream, error) in [
        (&[0u8][..], CompressionError::InvalidData { reason: "invalid dictionary size" }),
        (&[25u8][..], CompressionError::InvalidData { reason: "invalid dictionary size" }),
        (&[13u8][..], CompressionError::LimitExceeded { limit: 1 << 12 }),
        // With no phrase the field has 1 bit: 1 is the marker, then phrase 0 and the bit 1, then a nonzero padding bit.
        (&[8u8, 0b1101][..], CompressionError::InvalidData { reason: "nonzero padding" }),
        (&[8u8][..], CompressionError::UnexpectedEnd),
    ] {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(stream, 100), Err(error));
    }
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[8u8, 0b101], 100).unwrap(), b"");
    // With one phrase the field has 2 bits; 3 is beyond the marker 2.
    decompressor.reset();
    let stream = [8u8, 0b1000_0010, 0b0000_0111];
    assert_eq!(
        decompressor.decompress_to_vec(&stream, 100),
        Err(CompressionError::InvalidData { reason: "phrase beyond the dictionary" })
    );
}

#[test]
fn lz78_streams_round_trip() {
    for dictionary_bits in [1, 9, 16] {
        let mut compressor = LZ78Compressor::new(LZ78Config { dictionary_bits }).unwrap();
        Streaming::round_trip(&mut compressor, &mut LZ78Decompressor::default(), Ending::Marked, true);
    }
    assert_eq!(LZ78Compressor::new(LZ78Config { dictionary_bits: 0 }), Err(CompressionError::InvalidParameter));
    assert_eq!(LZ78Compressor::new(LZ78Config { dictionary_bits: 25 }), Err(CompressionError::InvalidParameter));
}
