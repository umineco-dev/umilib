use alloc::string::String;
use alloc::vec::Vec;

use super::URIError;

/// Percent-encoding (RFC 3986 §2.1) and the character classes of §2.
pub struct URIPercent;

impl URIPercent {
    /// The digits of encoded octets, in upper case as §2.1 says producers SHOULD use.
    pub const HEXADECIMAL: &'static [u8; 16] = b"0123456789ABCDEF";

    /// Whether `byte` is unreserved (§2.3): ALPHA, DIGIT, `-`, `.`, `_`, `~`.
    pub fn is_unreserved(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }

    /// Whether `byte` is a sub-delimiter (§2.2): `!$&'()*+,;=`.
    pub fn is_sub_delim(byte: u8) -> bool {
        matches!(byte, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
    }

    /// Whether `byte` is a general delimiter (§2.2): `:/?#[]@`.
    pub fn is_gen_delim(byte: u8) -> bool {
        matches!(byte, b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@')
    }

    /// Whether `byte` is a `pchar` other than a percent-encoding (§3.3): unreserved, a
    /// sub-delimiter, `:` or `@`.
    pub fn is_pchar(byte: u8) -> bool {
        URIPercent::is_unreserved(byte) || URIPercent::is_sub_delim(byte) || matches!(byte, b':' | b'@')
    }

    /// `data` with every octet `keep` does not take percent-encoded.
    pub fn encode(data: &[u8], keep: impl Fn(u8) -> bool) -> String {
        let mut out = String::with_capacity(data.len());
        for &byte in data {
            if keep(byte) {
                out.push(char::from(byte));
            } else {
                out.push('%');
                out.push(char::from(URIPercent::HEXADECIMAL[usize::from(byte >> 4)]));
                out.push(char::from(URIPercent::HEXADECIMAL[usize::from(byte & 0xF)]));
            }
        }
        out
    }

    /// `data` with every octet but the unreserved percent-encoded: a component that may hold
    /// any octets and keeps no delimiter of its own (§2.4).
    pub fn encode_component(data: &[u8]) -> String {
        URIPercent::encode(data, URIPercent::is_unreserved)
    }

    /// The value of the hexadecimal digit `byte`.
    pub fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    /// The octets of `text`, its percent-encodings decoded; fails for a `%` not followed by two
    /// hexadecimal digits.
    pub fn decode(text: &[u8]) -> Result<Vec<u8>, URIError> {
        let mut out = Vec::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            if text[index] == b'%' {
                let high = text.get(index + 1).copied().and_then(URIPercent::digit);
                let low = text.get(index + 2).copied().and_then(URIPercent::digit);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(URIError::Percent { position: index });
                };
                out.push(high << 4 | low);
                index += 3;
            } else {
                out.push(text[index]);
                index += 1;
            }
        }
        Ok(out)
    }

    /// The UTF-8 text of `text`, its percent-encodings decoded.
    pub fn decode_text(text: &[u8]) -> Result<String, URIError> {
        String::from_utf8(URIPercent::decode(text)?).map_err(|_| URIError::UTF8)
    }

    /// Checks that every `%` of `text` begins a percent-encoding.
    pub fn check(text: &[u8]) -> Result<(), URIError> {
        let mut index = 0;
        while index < text.len() {
            if text[index] == b'%' {
                let valid = text.get(index + 1).copied().and_then(URIPercent::digit).is_some()
                    && text.get(index + 2).copied().and_then(URIPercent::digit).is_some();
                if !valid {
                    return Err(URIError::Percent { position: index });
                }
                index += 3;
            } else {
                index += 1;
            }
        }
        Ok(())
    }
}
