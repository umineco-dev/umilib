use alloc::string::String;
use alloc::vec::Vec;

use super::ASN1Error;

/// Validation and conversion of the restricted character string types (X.680 section 41).
pub struct ASN1String;

impl ASN1String {
    /// Whether `bytes` are PrintableString characters: letters, digits, space and `'()+,-./:=?`.
    pub fn is_printable(bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&byte))
    }

    /// Whether `bytes` are IA5String (ASCII) characters.
    pub fn is_ia5(bytes: &[u8]) -> bool {
        bytes.is_ascii()
    }

    /// Whether `bytes` are VisibleString characters (printable ASCII and space).
    pub fn is_visible(bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| (0x20..=0x7E).contains(&byte))
    }

    /// Whether `bytes` are NumericString characters: digits and space.
    pub fn is_numeric(bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| byte.is_ascii_digit() || byte == b' ')
    }

    /// The text of a UTF8String, which must be valid UTF-8.
    pub fn decode_utf8(bytes: &[u8]) -> Result<&str, ASN1Error> {
        core::str::from_utf8(bytes).map_err(|_| ASN1Error::InvalidContent { position: 0 })
    }

    /// The text of a BMPString: big-endian UCS-2, without surrogates.
    pub fn decode_bmp(bytes: &[u8]) -> Result<String, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if !bytes.len().is_multiple_of(2) {
            return Err(invalid);
        }
        bytes
            .chunks(2)
            .map(|pair| char::from_u32(u16::from_be_bytes([pair[0], pair[1]]) as u32).ok_or(invalid))
            .collect()
    }

    /// The text of a UniversalString: big-endian UCS-4.
    pub fn decode_universal(bytes: &[u8]) -> Result<String, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if !bytes.len().is_multiple_of(4) {
            return Err(invalid);
        }
        bytes
            .chunks(4)
            .map(|group| char::from_u32(u32::from_be_bytes([group[0], group[1], group[2], group[3]])).ok_or(invalid))
            .collect()
    }

    /// The contents of a BMPString holding `text`; fails for characters above U+FFFF.
    pub fn encode_bmp(text: &str) -> Result<Vec<u8>, ASN1Error> {
        let mut bytes = Vec::with_capacity(text.len() * 2);
        for character in text.chars() {
            let value = u16::try_from(character as u32).map_err(|_| ASN1Error::OutOfRange)?;
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        Ok(bytes)
    }

    /// The contents of a UniversalString holding `text`.
    pub fn encode_universal(text: &str) -> Vec<u8> {
        text.chars().flat_map(|character| (character as u32).to_be_bytes()).collect()
    }
}
