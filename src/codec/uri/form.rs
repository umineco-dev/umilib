use alloc::string::String;
use alloc::vec::Vec;

use super::{URIError, URIPercent};

/// The form encoding `application/x-www-form-urlencoded` (WHATWG URL
/// Standard §5; RFC 6749 Appendix B): name and value pairs joined by `&`, a
/// name and its value by `=`, a space as `+`, other octets but the
/// alphanumerics and `*-._` percent-encoded.
pub struct URIForm;

impl URIForm {
    /// Whether the serializer keeps `byte` as it is (WHATWG URL §5.2: the
    /// `application/x-www-form-urlencoded` percent-encode set's complement).
    pub fn is_kept(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_')
    }

    /// The pairs of `input` (WHATWG URL §5.1): sequences split at `&`, empty ones skipped, each
    /// at its first `=` (a name without `=` has an empty value), `+` read as a space, and
    /// percent-encodings decoded, a `%` not followed by two hexadecimal digits kept as it is.
    /// Octets that are not UTF-8 fail with UTF8 instead of becoming U+FFFD as the standard
    /// writes: two different values that read the same would let one stand for the other.
    pub fn parse(input: &[u8]) -> Result<Vec<(String, String)>, URIError> {
        let mut pairs = Vec::new();
        for sequence in input.split(|byte| *byte == b'&') {
            if sequence.is_empty() {
                continue;
            }
            let (name, value) = match sequence.iter().position(|byte| *byte == b'=') {
                Some(index) => (&sequence[..index], &sequence[index + 1..]),
                None => (sequence, &[][..]),
            };
            pairs.push((URIForm::decode(name)?, URIForm::decode(value)?));
        }
        Ok(pairs)
    }

    /// The text of one name or value: `+` a space, percent-encodings decoded leniently.
    pub fn decode(text: &[u8]) -> Result<String, URIError> {
        let mut out = Vec::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            let byte = text[index];
            let high = text.get(index + 1).copied().and_then(URIPercent::digit);
            let low = text.get(index + 2).copied().and_then(URIPercent::digit);
            match (byte, high, low) {
                (b'%', Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    index += 3;
                }
                (b'+', _, _) => {
                    out.push(b' ');
                    index += 1;
                }
                _ => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| URIError::UTF8)
    }

    /// One name or value written (WHATWG URL §5.2): a space as `+`, the octets of its UTF-8
    /// but the alphanumerics and `*-._` percent-encoded.
    pub fn encode_text(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for &byte in text.as_bytes() {
            match byte {
                b' ' => out.push('+'),
                byte if URIForm::is_kept(byte) => out.push(char::from(byte)),
                byte => {
                    out.push('%');
                    out.push(char::from(URIPercent::HEXADECIMAL[usize::from(byte >> 4)]));
                    out.push(char::from(URIPercent::HEXADECIMAL[usize::from(byte & 0xF)]));
                }
            }
        }
        out
    }

    /// `pairs` written: `name=value`, joined by `&`.
    pub fn encode<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> String {
        let mut out = String::new();
        for (index, (name, value)) in pairs.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            out.push_str(&URIForm::encode_text(name.as_ref()));
            out.push('=');
            out.push_str(&URIForm::encode_text(value.as_ref()));
        }
        out
    }
}
