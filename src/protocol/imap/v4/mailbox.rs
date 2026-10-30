use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::IMAPError;

/// A mailbox name (RFC 9051 §5.1): text of Unicode; `INBOX` in any case is
/// INBOX, kept in upper case. On the wire it is UTF-8 under IMAP4rev2, and
/// modified UTF-7 under IMAP4rev1 (RFC 3501 §5.1.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IMAPMailbox {
    pub name: String,
}

impl IMAPMailbox {
    /// The characters of modified BASE64 (RFC 3501 §5.1.3): `,` for `/`.
    pub const BASE64: &'static [u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    pub fn new(name: &str) -> IMAPMailbox {
        match name.eq_ignore_ascii_case("INBOX") {
            true => IMAPMailbox { name: String::from("INBOX") },
            false => IMAPMailbox { name: String::from(name) },
        }
    }

    pub fn inbox() -> IMAPMailbox {
        IMAPMailbox::new("INBOX")
    }

    pub fn is_inbox(&self) -> bool {
        self.name == "INBOX"
    }

    /// The mailbox of the octets of an astring: of UTF-8 if `utf8`, of modified UTF-7 otherwise.
    pub fn from_wire(name: &[u8], utf8: bool) -> Result<IMAPMailbox, IMAPError> {
        let invalid = IMAPError::Syntax { position: 0, reason: "not a mailbox name" };
        let text = match utf8 {
            true => String::from_utf8(name.to_vec()).map_err(|_| invalid)?,
            false => IMAPMailbox::decode_modified_utf7(name)?,
        };
        Ok(IMAPMailbox::new(&text))
    }

    /// The octets of the name on the wire: UTF-8 if `utf8`, modified UTF-7 otherwise.
    pub fn to_wire(&self, utf8: bool) -> Vec<u8> {
        match utf8 {
            true => self.name.as_bytes().to_vec(),
            false => IMAPMailbox::encode_modified_utf7(&self.name).into_bytes(),
        }
    }

    /// `text` in modified UTF-7 (RFC 3501 §5.1.3): printable US-ASCII as it is but `&` as
    /// `&-`, other characters as `&`, the modified BASE64 of their UTF-16, and `-`.
    pub fn encode_modified_utf7(text: &str) -> String {
        let mut encoded = String::with_capacity(text.len());
        let mut pending: Vec<u16> = Vec::new();
        let flush = |encoded: &mut String, pending: &mut Vec<u16>| {
            if pending.is_empty() {
                return;
            }
            let bytes: Vec<u8> = pending.iter().flat_map(|unit| unit.to_be_bytes()).collect();
            encoded.push('&');
            let mut bits = 0u32;
            let mut count = 0;
            for byte in bytes {
                bits = (bits << 8) | u32::from(byte);
                count += 8;
                while count >= 6 {
                    count -= 6;
                    encoded.push(char::from(IMAPMailbox::BASE64[((bits >> count) & 0x3f) as usize]));
                }
                bits &= (1 << count) - 1;
            }
            if count > 0 {
                encoded.push(char::from(IMAPMailbox::BASE64[((bits << (6 - count)) & 0x3f) as usize]));
            }
            encoded.push('-');
            pending.clear();
        };
        for character in text.chars() {
            match character {
                '&' => {
                    flush(&mut encoded, &mut pending);
                    encoded.push_str("&-");
                }
                ' '..='~' => {
                    flush(&mut encoded, &mut pending);
                    encoded.push(character);
                }
                _ => pending.extend_from_slice(character.encode_utf16(&mut [0; 2])),
            }
        }
        flush(&mut encoded, &mut pending);
        encoded
    }

    /// The text of modified UTF-7. A name not of its rules (an `&` not closed, a run of
    /// BASE64 of no whole UTF-16, a printable character encoded, bits left set) fails.
    pub fn decode_modified_utf7(name: &[u8]) -> Result<String, IMAPError> {
        let invalid = |position| IMAPError::Syntax { position, reason: "not modified UTF-7" };
        let mut text = String::with_capacity(name.len());
        let mut index = 0;
        while index < name.len() {
            let byte = name[index];
            if !(0x20..=0x7e).contains(&byte) {
                return Err(invalid(index));
            }
            if byte != b'&' {
                text.push(char::from(byte));
                index += 1;
                continue;
            }
            let start = index;
            let end = start + 1 + name[start + 1..].iter().position(|byte| *byte == b'-').ok_or(invalid(start))?;
            if end == start + 1 {
                text.push('&');
                index = end + 1;
                continue;
            }
            let mut bits = 0u32;
            let mut count = 0;
            let mut units: Vec<u16> = Vec::new();
            let mut pending = 0u32;
            let mut have = 0;
            for byte in &name[start + 1..end] {
                let value = IMAPMailbox::BASE64.iter().position(|code| code == byte).ok_or(invalid(start))? as u32;
                bits = (bits << 6) | value;
                count += 6;
                if count >= 8 {
                    count -= 8;
                    pending = (pending << 8) | ((bits >> count) & 0xff);
                    bits &= (1 << count) - 1;
                    have += 1;
                    if have == 2 {
                        units.push(pending as u16);
                        pending = 0;
                        have = 0;
                    }
                }
            }
            if have != 0 || bits & ((1 << count) - 1) != 0 {
                return Err(invalid(start));
            }
            let decoded = char::decode_utf16(units).collect::<Result<String, _>>().map_err(|_| invalid(start))?;
            if decoded.is_empty() || decoded.chars().any(|character| (' '..='~').contains(&character)) {
                return Err(invalid(start));
            }
            text.push_str(&decoded);
            index = end + 1;
        }
        Ok(text)
    }
}

impl fmt::Display for IMAPMailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.name)
    }
}
