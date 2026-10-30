use umilib::codec::base::base32::Base32;
use umilib::codec::base::{BaseError, Encoding, Padding};

use crate::RFC4648;

#[test]
fn rfc4648_section_10_vectors() {
    for (name, encoding) in [("BASE32", Base32::STANDARD), ("BASE32-HEX", Base32::HEX)] {
        let vectors = RFC4648::vectors(name);
        assert_eq!(vectors.len(), 7);
        for (input, output) in vectors {
            assert_eq!(encoding.encode(input.as_bytes()), output, "{name}");
            assert_eq!(encoding.decode(output.as_bytes()).unwrap(), input.as_bytes(), "{name}");
        }
    }
}

#[test]
fn unpadded_encodings_drop_the_padding() {
    for (input, output) in RFC4648::vectors("BASE32") {
        let unpadded = output.trim_end_matches('=');
        assert_eq!(Base32::STANDARD_NO_PADDING.encode(input.as_bytes()), unpadded);
        assert_eq!(Base32::STANDARD_NO_PADDING.decode(unpadded.as_bytes()).unwrap(), input.as_bytes());
        let indifferent = Base32::new(Base32::STANDARD_ALPHABET, Padding::Indifferent);
        assert_eq!(indifferent.decode(output.as_bytes()).unwrap(), input.as_bytes());
        assert_eq!(indifferent.decode(unpadded.as_bytes()).unwrap(), input.as_bytes());
    }
}

#[test]
fn only_lengths_that_end_on_a_byte_are_valid() {
    // Data characters in a final group of 8 can be 2, 4, 5 or 7 (RFC 4648 section 6).
    for (characters, valid) in [(1, false), (2, true), (3, false), (4, true), (5, true), (6, false), (7, true)] {
        let text = "A".repeat(characters);
        assert_eq!(Base32::STANDARD_NO_PADDING.decode(text.as_bytes()).is_ok(), valid, "{characters}");
    }
}

#[test]
fn invalid_text_is_rejected() {
    assert_eq!(Base32::STANDARD.decode(b"MY"), Err(BaseError::InvalidLength { length: 2 }));
    assert_eq!(Base32::STANDARD.decode(b"MY=====A"), Err(BaseError::InvalidCharacter { position: 2, character: b'=' }));
    assert_eq!(
        Base32::STANDARD.decode(b"MY======MY======"),
        Err(BaseError::InvalidCharacter { position: 2, character: b'=' })
    );
    assert_eq!(Base32::STANDARD.decode(b"M======="), Err(BaseError::InvalidLength { length: 8 }));
    assert_eq!(Base32::STANDARD.decode(b"MZ======"), Err(BaseError::NonCanonical { position: 1 }));
    assert_eq!(Base32::STANDARD.decode(b"my======"), Err(BaseError::InvalidCharacter { position: 0, character: b'm' }));
    assert_eq!(Base32::STANDARD_NO_PADDING.decode(b"MY======"), Err(BaseError::InvalidPadding { position: 2 }));
    assert_eq!(Base32::new(Base32::STANDARD_ALPHABET_ANY_CASE, Padding::Required).decode(b"my======").unwrap(), b"f");
    assert_eq!(Base32::new(Base32::HEX_ALPHABET_ANY_CASE, Padding::Required).decode(b"co======").unwrap(), b"f");
    assert_eq!(Base32::HEX.decode(b"W0======"), Err(BaseError::InvalidCharacter { position: 0, character: b'W' }));
}
