#[cfg(umilib_feature = "codec-base-base16")]
mod base16;
#[cfg(umilib_feature = "codec-base-base32")]
mod base32;
#[cfg(umilib_feature = "codec-base-base58")]
mod base58;
#[cfg(umilib_feature = "codec-base-base64")]
mod base64;
#[cfg(umilib_feature = "codec-base-base85")]
mod base85;

use umilib::codec::base::{Alphabet, AlphabetRange};

#[test]
fn alphabet_masks_select_exactly_their_range() {
    for value in 0..=255u8 {
        for start in [0u8, 1, 33, 200, 255] {
            for count in [1u8, 10, 26, 55] {
                let inside = (value as u16) >= start as u16 && (value as u16) < start as u16 + count as u16;
                assert_eq!(
                    Alphabet::mask_in(value, start, count),
                    if inside { 0xFF } else { 0 },
                    "{value} {start} {count}"
                );
            }
        }
    }
}

#[test]
fn alphabets_round_trip_every_value() {
    const ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'x', 3, 0),
        AlphabetRange::new(b'0', 2, 3),
        AlphabetRange::decode_only(b'X', 3, 0),
    ]);
    let alphabet = ALPHABET;
    assert_eq!(alphabet.size(), 5);
    for value in 0..5 {
        assert_eq!(alphabet.decode(alphabet.encode(value)), Some(value));
    }
    assert_eq!(alphabet.decode(b'Y'), Some(1));
    assert_eq!(alphabet.decode(b'a'), None);
}

#[cfg(umilib_feature = "codec-base-base64")]
#[test]
fn bit_encodings_need_a_padding_character_outside_the_alphabet() {
    use umilib::codec::base::base64::Base64;
    use umilib::codec::base::{BitEncoding, Padding};
    let valid = BitEncoding {
        alphabet: Base64::STANDARD_ALPHABET,
        bits: 6,
        padding: Padding::Required,
        padding_character: b'=',
    };
    assert!(valid.is_valid());
    assert!(Base64::STANDARD.encoding.is_valid() && Base64::URL_SAFE_NO_PADDING.encoding.is_valid());
    // With 'A' as padding, "AAAA" could be data or padding.
    assert!(!BitEncoding { padding_character: b'A', ..valid }.is_valid());
    assert!(!BitEncoding { bits: 5, ..valid }.is_valid());
    assert!(!BitEncoding { bits: 0, ..valid }.is_valid());
    assert!(!BitEncoding { bits: 8, ..valid }.is_valid());
}
