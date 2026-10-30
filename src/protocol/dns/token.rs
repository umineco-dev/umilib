use alloc::string::String;
use alloc::vec::Vec;

use crate::calendar::Date;
use crate::codec::base::Encoding;
use crate::codec::base::base16::Base16;
use crate::codec::base::base32::Base32;
use crate::codec::base::base64::Base64;

use super::DNSError;

/// A field of the presentation format (RFC 1035 §5.1): its text as written,
/// escapes kept, and whether it was a quoted string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSToken {
    pub text: Vec<u8>,
    pub quoted: bool,
}

impl DNSToken {
    pub fn new(text: &str) -> DNSToken {
        DNSToken { text: text.as_bytes().to_vec(), quoted: false }
    }

    /// The fields of one line of `text` (no parentheses or comments): words
    /// split by whitespace, and quoted strings.
    pub fn split(text: &str) -> Result<Vec<DNSToken>, DNSError> {
        let mut tokens = Vec::new();
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b' ' | b'\t' | b'\r' | b'\n' => index += 1,
                b'"' => {
                    let mut token = DNSToken { text: Vec::new(), quoted: true };
                    index += 1;
                    loop {
                        match bytes.get(index) {
                            None => return Err(DNSError::Syntax("a quoted string without its end")),
                            Some(b'"') => break,
                            Some(b'\\') => {
                                token.text.push(b'\\');
                                token.text.push(*bytes.get(index + 1).ok_or(DNSError::Syntax("an escape at the end"))?);
                                index += 2;
                            }
                            Some(byte) => {
                                token.text.push(*byte);
                                index += 1;
                            }
                        }
                    }
                    index += 1;
                    tokens.push(token);
                }
                _ => {
                    let mut token = DNSToken::default();
                    while let Some(&byte) = bytes.get(index) {
                        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'"') {
                            break;
                        }
                        token.text.push(byte);
                        if byte == b'\\'
                            && let Some(&next) = bytes.get(index + 1)
                        {
                            token.text.push(next);
                            index += 1;
                        }
                        index += 1;
                    }
                    tokens.push(token);
                }
            }
        }
        Ok(tokens)
    }

    pub fn as_str(&self) -> Result<&str, DNSError> {
        core::str::from_utf8(&self.text).map_err(|_| DNSError::Syntax("a field not of text"))
    }

    pub fn number<T: core::str::FromStr>(&self) -> Result<T, DNSError> {
        if self.quoted {
            return Err(DNSError::Syntax("a quoted string where a number is expected"));
        }
        self.as_str()?.parse().map_err(|_| DNSError::Syntax("not a number of its range"))
    }

    /// The bytes of the field, escapes `\X` and `\DDD` replaced (RFC 1035 §5.1).
    pub fn unescaped(&self) -> Result<Vec<u8>, DNSError> {
        let mut out = Vec::with_capacity(self.text.len());
        let mut index = 0;
        while index < self.text.len() {
            if self.text[index] != b'\\' {
                out.push(self.text[index]);
                index += 1;
                continue;
            }
            match self.text.get(index + 1..index + 4) {
                Some(digits) if digits.iter().all(u8::is_ascii_digit) => {
                    let value = digits.iter().fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
                    out.push(u8::try_from(value).map_err(|_| DNSError::Syntax("an escape above 255"))?);
                    index += 4;
                }
                _ => {
                    out.push(*self.text.get(index + 1).ok_or(DNSError::Syntax("an escape at the end"))?);
                    index += 2;
                }
            }
        }
        Ok(out)
    }

    /// `bytes` as a quoted string, `"` and `\` escaped and bytes outside
    /// printable ASCII as `\DDD`.
    pub fn quote(bytes: &[u8]) -> String {
        let mut out = String::from("\"");
        for &byte in bytes {
            match byte {
                b'"' | b'\\' => {
                    out.push('\\');
                    out.push(byte as char);
                }
                0x20..=0x7E => out.push(byte as char),
                _ => out.push_str(&alloc::format!("\\{byte:03}")),
            }
        }
        out.push('"');
        out
    }

    pub fn hex(text: &[u8]) -> Result<Vec<u8>, DNSError> {
        Base16::UPPER.decode(text).map_err(|_| DNSError::Syntax("not hexadecimal"))
    }

    pub fn base64(text: &[u8]) -> Result<Vec<u8>, DNSError> {
        Base64::STANDARD.decode(text).map_err(|_| DNSError::Syntax("not base64"))
    }

    /// Base32 of the extended hex alphabet, without padding, of any case (RFC 4648 §7, RFC 5155 §3.3).
    pub fn base32hex(text: &[u8]) -> Result<Vec<u8>, DNSError> {
        Base32::new(Base32::HEX_ALPHABET_ANY_CASE, crate::codec::base::Padding::Forbidden)
            .decode(text)
            .map_err(|_| DNSError::Syntax("not base32hex"))
    }

    /// A TTL: seconds, or a number of weeks, days, hours, minutes and
    /// seconds with their units ("1w2d3h4m5s", the form of BIND).
    pub fn ttl(text: &str) -> Result<u32, DNSError> {
        let syntax = DNSError::Syntax("not a TTL");
        if let Ok(seconds) = text.parse::<u32>() {
            return Ok(seconds);
        }
        let mut total: u64 = 0;
        let mut value: u64 = 0;
        let mut digits = false;
        for byte in text.bytes() {
            if byte.is_ascii_digit() {
                value =
                    value.checked_mul(10).and_then(|value| value.checked_add(u64::from(byte - b'0'))).ok_or(syntax)?;
                digits = true;
                continue;
            }
            let unit = match byte.to_ascii_lowercase() {
                b'w' => 604_800,
                b'd' => 86_400,
                b'h' => 3_600,
                b'm' => 60,
                b's' => 1,
                _ => return Err(syntax),
            };
            if !digits {
                return Err(syntax);
            }
            total = value.checked_mul(unit).and_then(|seconds| total.checked_add(seconds)).ok_or(syntax)?;
            (value, digits) = (0, false);
        }
        if digits {
            return Err(syntax);
        }
        u32::try_from(total).map_err(|_| syntax)
    }

    /// An RRSIG time: YYYYMMDDHHmmSS in UTC, or seconds (RFC 4034 §3.2),
    /// modulo 2^32 (§3.1.5).
    pub fn time(text: &str) -> Result<u32, DNSError> {
        let syntax = DNSError::Syntax("not a time");
        if text.len() != 14 {
            return text.parse().map_err(|_| syntax);
        }
        let field = |range: core::ops::Range<usize>| {
            let digits = text.get(range).filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))?;
            digits.parse::<i64>().ok()
        };
        let (year, month, day) = (field(0..4).ok_or(syntax)?, field(4..6).ok_or(syntax)?, field(6..8).ok_or(syntax)?);
        let (hour, minute, second) =
            (field(8..10).ok_or(syntax)?, field(10..12).ok_or(syntax)?, field(12..14).ok_or(syntax)?);
        // The month and the day have two digits, which fit u8.
        let date = Date::new(year, month as u8, day as u8);
        let date = date.filter(|_| hour <= 23 && minute <= 59 && second <= 59).ok_or(syntax)?;
        let seconds = date.days() * 86_400 + hour * 3_600 + minute * 60 + second;
        Ok(seconds.rem_euclid(1 << 32) as u32)
    }

    /// The RRSIG time `seconds` as YYYYMMDDHHmmSS (RFC 4034 §3.2), taken in
    /// the 136 years from 1970 (the serial arithmetic of §3.1.5 decides the rest).
    pub fn format_time(seconds: u32) -> String {
        let seconds = i64::from(seconds);
        let (days, rest) = (seconds / 86_400, seconds % 86_400);
        let date = Date::from_days(days).expect("the days of u32 seconds are of dates");
        alloc::format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            date.year(),
            date.month(),
            date.day(),
            rest / 3_600,
            rest / 60 % 60,
            rest % 60
        )
    }
}
