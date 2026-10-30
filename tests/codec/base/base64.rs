use umilib::codec::base::base64::Base64;
use umilib::codec::base::{BaseError, Encoding, Padding};

use crate::RFC4648;

#[test]
fn rfc4648_section_10_vectors() {
    let vectors = RFC4648::vectors("BASE64");
    assert_eq!(vectors.len(), 7);
    for (input, output) in vectors {
        assert_eq!(Base64::STANDARD.encode(input.as_bytes()), output);
        assert_eq!(Base64::STANDARD.decode(output.as_bytes()).unwrap(), input.as_bytes());
        let unpadded = output.trim_end_matches('=');
        assert_eq!(Base64::STANDARD_NO_PADDING.encode(input.as_bytes()), unpadded);
        assert_eq!(Base64::URL_SAFE_NO_PADDING.decode(unpadded.as_bytes()).unwrap(), input.as_bytes());
    }
}

#[test]
fn alphabets_differ_only_in_the_last_two_characters() {
    // 0xFB 0xFF 0xBF encodes to the values 62, 63, 62, 63.
    let input = [0xFB, 0xFF, 0xBF];
    assert_eq!(Base64::STANDARD.encode(&input), "+/+/");
    assert_eq!(Base64::URL_SAFE.encode(&input), "-_-_");
    assert_eq!(Base64::STANDARD.decode(b"-_-_"), Err(BaseError::InvalidCharacter { position: 0, character: b'-' }));
    assert_eq!(Base64::URL_SAFE.decode(b"+/+/"), Err(BaseError::InvalidCharacter { position: 0, character: b'+' }));
    let all: Vec<u8> = (0..=255).collect();
    for encoding in [Base64::STANDARD, Base64::STANDARD_NO_PADDING, Base64::URL_SAFE, Base64::URL_SAFE_NO_PADDING] {
        for length in 0..all.len() {
            let text = encoding.encode(&all[..length]);
            assert_eq!(text.len(), encoding.maximum_encoded_length(length).unwrap());
            assert_eq!(encoding.decode(text.as_bytes()).unwrap(), &all[..length]);
        }
    }
}

#[test]
fn non_canonical_and_malformed_text_is_rejected() {
    // "Zg==" is "f"; "Zh==" sets the unused low bits of its last character.
    assert_eq!(Base64::STANDARD.decode(b"Zh=="), Err(BaseError::NonCanonical { position: 1 }));
    assert_eq!(Base64::STANDARD.decode(b"Zm9="), Err(BaseError::NonCanonical { position: 2 }));
    assert_eq!(Base64::STANDARD.decode(b"Zg="), Err(BaseError::InvalidLength { length: 3 }));
    assert_eq!(Base64::STANDARD.decode(b"Zg"), Err(BaseError::InvalidLength { length: 2 }));
    // One character cannot hold a byte, whatever the padding.
    assert_eq!(Base64::STANDARD.decode(b"Z==="), Err(BaseError::InvalidLength { length: 4 }));
    assert_eq!(Base64::STANDARD.decode(b"===="), Err(BaseError::InvalidPadding { position: 0 }));
    assert_eq!(Base64::STANDARD.decode(b"Zg==Zg=="), Err(BaseError::InvalidCharacter { position: 2, character: b'=' }));
    assert_eq!(Base64::STANDARD.decode(b"Zm9v\n"), Err(BaseError::InvalidLength { length: 5 }));
    assert_eq!(Base64::STANDARD.decode(b"Zm9\n"), Err(BaseError::InvalidCharacter { position: 3, character: b'\n' }));
    assert_eq!(Base64::STANDARD_NO_PADDING.decode(b"Z"), Err(BaseError::InvalidLength { length: 1 }));
    assert_eq!(Base64::STANDARD_NO_PADDING.decode(b"Zg=="), Err(BaseError::InvalidPadding { position: 2 }));
    let indifferent = Base64::new(Base64::STANDARD_ALPHABET, Padding::Indifferent);
    assert_eq!(indifferent.decode(b"Zg").unwrap(), b"f");
    assert_eq!(indifferent.decode(b"Zg==").unwrap(), b"f");
    assert_eq!(indifferent.decode(b"Zg="), Err(BaseError::InvalidPadding { position: 2 }));
}

#[test]
fn slices_must_be_large_enough() {
    let mut small = [0u8; 3];
    assert_eq!(
        Base64::STANDARD.encode_to_slice(b"fo", &mut small),
        Err(BaseError::OutputTooSmall { needed: 4, available: 3 })
    );
    let mut exact = [0u8; 4];
    assert_eq!(Base64::STANDARD.encode_to_slice(b"fo", &mut exact), Ok(4));
    assert_eq!(&exact, b"Zm8=");
    let mut one = [0u8; 1];
    assert_eq!(
        Base64::STANDARD.decode_to_slice(b"Zm8=", &mut one),
        Err(BaseError::OutputTooSmall { needed: 2, available: 1 })
    );
    assert_eq!(Base64::STANDARD.maximum_decoded_length(4), 3);
}
