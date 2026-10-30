use umilib::codec::base::base58::Base58;
use umilib::codec::base::{BaseError, Encoding};

use crate::Vectors;

#[test]
fn bitcoin_core_vectors() {
    let text = Vectors::read("codec/base/base58_encode_decode.json");
    let mut count = 0;
    for line in text.lines().map(str::trim).filter(|line| line.starts_with("[\"")) {
        let fields: Vec<&str> = line
            .trim_end_matches(',')
            .trim_matches(|character| character == '[' || character == ']')
            .split("\", \"")
            .collect();
        let (hex, encoded) = (fields[0].trim_matches('"'), fields[1].trim_matches('"'));
        let bytes = Vectors::hex(hex);
        assert_eq!(Base58::BITCOIN.encode(&bytes), encoded, "{hex}");
        assert_eq!(Base58::BITCOIN.decode(encoded.as_bytes()).unwrap(), bytes, "{encoded}");
        count += 1;
    }
    assert!(count >= 10, "only {count} vectors found");
}

#[test]
fn leading_zero_bytes_are_leading_first_characters() {
    assert_eq!(Base58::BITCOIN.encode(&[0, 0, 1]), "112");
    assert_eq!(Base58::RIPPLE.encode(&[0, 0, 1]), "rrp");
    assert_eq!(Base58::FLICKR.encode(&[0, 57]), "1Z");
    assert_eq!(Base58::BITCOIN.decode(b"111").unwrap(), [0, 0, 0]);
    // 58 is "21": one times 58 plus zero.
    assert_eq!(Base58::BITCOIN.encode(&[58]), "21");
}

#[test]
fn invalid_text_and_long_input_are_rejected() {
    for character in *b"0OIl+" {
        assert_eq!(
            Base58::BITCOIN.decode(&[b'2', character]),
            Err(BaseError::InvalidCharacter { position: 1, character })
        );
    }
    let limited = Base58::BITCOIN.with_maximum_length(4);
    assert_eq!(limited.encode_to_slice(&[1; 5], &mut [0; 16]), Err(BaseError::InputTooLong { length: 5, maximum: 4 }));
    assert_eq!(limited.decode(b"22222"), Err(BaseError::InputTooLong { length: 5, maximum: 4 }));
    let mut small = [0u8; 1];
    assert!(matches!(
        Base58::BITCOIN.encode_to_slice(&[0xFF, 0xFF], &mut small),
        Err(BaseError::OutputTooSmall { .. })
    ));
}

#[test]
fn random_inputs_round_trip() {
    let mut state = 0x1234_5678u32;
    for length in 0..64 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect();
        for encoding in [Base58::BITCOIN, Base58::FLICKR, Base58::RIPPLE] {
            let text = encoding.encode(&bytes);
            assert!(text.len() <= encoding.maximum_encoded_length(length).unwrap());
            assert_eq!(encoding.decode(text.as_bytes()).unwrap(), bytes);
        }
    }
}
