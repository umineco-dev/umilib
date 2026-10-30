use umilib::codec::base::base85::Base85;
use umilib::codec::base::{BaseError, Encoding};

#[test]
fn z85_specification_example() {
    // ZeroMQ RFC 32: the frame 86 4F D2 6F B5 59 F7 5B is "HelloWorld".
    let frame = [0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B];
    assert_eq!(Base85::Z85.encode(&frame), "HelloWorld");
    assert_eq!(Base85::Z85.decode(b"HelloWorld").unwrap(), frame);
    assert_eq!(Base85::Z85.encode_to_slice(&frame[..3], &mut [0; 16]), Err(BaseError::InvalidLength { length: 3 }));
    assert_eq!(Base85::Z85.decode(b"Hello"), Ok(vec![0x86, 0x4F, 0xD2, 0x6F]));
    assert_eq!(Base85::Z85.decode(b"Hell"), Err(BaseError::InvalidLength { length: 4 }));
}

#[test]
fn ascii85_follows_adobe() {
    // "Man " is 0x4D616E20 = 9*85^4 + 73*85^3 + 78*85^2 + 61*85 + 85... written "9jqo^".
    assert_eq!(Base85::ASCII85.encode(b"Man "), "9jqo^");
    assert_eq!(Base85::ASCII85_ADOBE.encode(b"Man "), "<~9jqo^~>");
    // A group of four zero bytes is "z"; a partial group of n bytes is n + 1 characters.
    assert_eq!(Base85::ASCII85.encode(&[0, 0, 0, 0, 0]), "z!!");
    assert_eq!(Base85::ASCII85.decode(b"z!!").unwrap(), [0, 0, 0, 0, 0]);
    assert_eq!(Base85::ASCII85.decode(b"9j qo\n^").unwrap(), b"Man ");
    assert_eq!(Base85::ASCII85_ADOBE.decode(b"<~9jqo^~>").unwrap(), b"Man ");
    assert_eq!(Base85::ASCII85_ADOBE.decode(b"9jqo^"), Err(BaseError::InvalidPadding { position: 0 }));
    assert_eq!(Base85::ASCII85.decode(b"9jzqo"), Err(BaseError::InvalidCharacter { position: 2, character: b'z' }));
    assert_eq!(Base85::ASCII85.decode(b"9"), Err(BaseError::InvalidLength { length: 1 }));
    // "s8W-!" is the largest value, 2^32 - 1; "s8W-\"" exceeds it.
    assert_eq!(Base85::ASCII85.decode(b"s8W-!").unwrap(), [0xFF; 4]);
    assert_eq!(Base85::ASCII85.decode(b"s8W-\""), Err(BaseError::Overflow { position: 0 }));
    assert_eq!(Base85::ASCII85.decode(b"uuuuu"), Err(BaseError::Overflow { position: 0 }));
}

#[test]
fn partial_groups_are_canonical() {
    // One byte 0x41 ("A") is "5l"; "5m" decodes to the same byte but is not canonical.
    assert_eq!(Base85::ASCII85.encode(b"A"), "5l");
    assert_eq!(Base85::ASCII85.decode(b"5l").unwrap(), b"A");
    assert_eq!(Base85::ASCII85.decode(b"5m"), Err(BaseError::NonCanonical { position: 1 }));
}

#[test]
fn every_length_round_trips() {
    let data: Vec<u8> = (0..=255u8).rev().collect();
    for encoding in [Base85::ASCII85, Base85::ASCII85_ADOBE, Base85::RFC1924] {
        for length in 0..64 {
            let text = encoding.encode(&data[..length]);
            assert!(text.len() <= encoding.maximum_encoded_length(length).unwrap());
            assert_eq!(encoding.decode(text.as_bytes()).unwrap(), &data[..length]);
        }
    }
    for length in (0..64).step_by(4) {
        let text = Base85::Z85.encode(&data[..length]);
        assert_eq!(Base85::Z85.decode(text.as_bytes()).unwrap(), &data[..length]);
    }
}
