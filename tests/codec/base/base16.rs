use umilib::codec::base::base16::Base16;
use umilib::codec::base::{BaseError, Encoding};

use crate::RFC4648;

#[test]
fn rfc4648_section_10_vectors() {
    let vectors = RFC4648::vectors("BASE16");
    assert_eq!(vectors.len(), 7);
    for (input, output) in vectors {
        assert_eq!(Base16::UPPER.encode(input.as_bytes()), output);
        assert_eq!(Base16::UPPER.decode(output.as_bytes()).unwrap(), input.as_bytes());
        assert_eq!(Base16::LOWER.encode(input.as_bytes()), output.to_lowercase());
        assert_eq!(Base16::LOWER.decode(output.as_bytes()).unwrap(), input.as_bytes());
    }
}

#[test]
fn every_byte_round_trips_and_both_cases_decode() {
    let all: Vec<u8> = (0..=255).collect();
    let upper = Base16::UPPER.encode(&all);
    assert!(upper.starts_with("000102") && upper.ends_with("FDFEFF"));
    assert_eq!(Base16::UPPER.decode(upper.to_lowercase().as_bytes()).unwrap(), all);
    assert_eq!(Base16::LOWER.decode(upper.as_bytes()).unwrap(), all);
}

#[test]
fn invalid_text_is_rejected() {
    assert_eq!(Base16::UPPER.decode(b"6"), Err(BaseError::InvalidLength { length: 1 }));
    assert_eq!(Base16::UPPER.decode(b"6G"), Err(BaseError::InvalidCharacter { position: 1, character: b'G' }));
    assert_eq!(Base16::UPPER.decode(b"66="), Err(BaseError::InvalidPadding { position: 2 }));
    assert_eq!(Base16::UPPER.decode(b" 6"), Err(BaseError::InvalidCharacter { position: 0, character: b' ' }));
    // The length is checked before the characters.
    assert_eq!(Base16::UPPER.decode(b" 66"), Err(BaseError::InvalidLength { length: 3 }));
}
