use alloc::string::String;
use alloc::vec::Vec;

use super::MailError;

/// A character set of MIME text (RFC 2045 §5.1, RFC 2046 §4.1.2) that
/// this crate converts to and from Unicode. Others are left to the caller,
/// as RFC 2047 §6.2 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MIMECharset {
    USASCII = 0,
    UTF8 = 1,
    ISO88591 = 2,
    Windows1252 = 3,
}

impl MIMECharset {
    /// The characters 0x80 to 0x9F of Windows-1252; U+FFFD where it has none.
    pub const WINDOWS_1252_HIGH: [char; 32] = [
        '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{02C6}',
        '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}', '\u{017D}', '\u{FFFD}', '\u{FFFD}', '\u{2018}',
        '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}',
        '\u{203A}', '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
    ];

    /// The character set of its number (its discriminant).
    pub fn from_u8(value: u8) -> Option<MIMECharset> {
        [MIMECharset::USASCII, MIMECharset::UTF8, MIMECharset::ISO88591, MIMECharset::Windows1252]
            .into_iter()
            .find(|charset| *charset as u8 == value)
    }

    /// The character set of a name, in any case; the names of the IANA
    /// registry and their aliases.
    pub fn from_name(name: &str) -> Option<MIMECharset> {
        let name = name.trim();
        let is = |names: &[&str]| names.iter().any(|known| known.eq_ignore_ascii_case(name));
        if is(&[
            "us-ascii",
            "ascii",
            "ANSI_X3.4-1968",
            "iso-ir-6",
            "ANSI_X3.4-1986",
            "ISO_646.irv:1991",
            "ISO646-US",
            "us",
            "IBM367",
            "cp367",
            "csASCII",
        ]) {
            Some(MIMECharset::USASCII)
        } else if is(&["utf-8", "csUTF8"]) {
            Some(MIMECharset::UTF8)
        } else if is(&[
            "iso-8859-1",
            "ISO_8859-1:1987",
            "iso-ir-100",
            "ISO_8859-1",
            "latin1",
            "l1",
            "IBM819",
            "CP819",
            "csISOLatin1",
        ]) {
            Some(MIMECharset::ISO88591)
        } else if is(&["windows-1252", "cswindows1252"]) {
            Some(MIMECharset::Windows1252)
        } else {
            None
        }
    }

    /// The text of `bytes` of the character set named `name`: of one this
    /// type converts, or of one of ISO 8859 or Windows-1250 to 1258 when
    /// every byte is US-ASCII, as each of those is US-ASCII in its lower
    /// half. Fails for others, which are left to the caller.
    pub fn decode_named(name: &str, bytes: &[u8]) -> Result<String, MailError> {
        if let Some(charset) = MIMECharset::from_name(name) {
            return charset.decode(bytes);
        }
        let name = name.trim().to_ascii_lowercase();
        let number = |prefix: &str| name.strip_prefix(prefix).and_then(|number| number.parse::<u16>().ok());
        let superset = number("iso-8859-").is_some_and(|number| (1..=16).contains(&number))
            || number("iso_8859-").is_some_and(|number| (1..=16).contains(&number))
            || number("windows-").is_some_and(|number| (1250..=1258).contains(&number));
        match superset && bytes.is_ascii() {
            true => MIMECharset::USASCII.decode(bytes),
            false => Err(MailError::Charset),
        }
    }

    /// The preferred MIME name of the character set (IANA registry).
    pub fn preferred_name(&self) -> &'static str {
        match self {
            MIMECharset::USASCII => "US-ASCII",
            MIMECharset::UTF8 => "UTF-8",
            MIMECharset::ISO88591 => "ISO-8859-1",
            MIMECharset::Windows1252 => "windows-1252",
        }
    }

    /// `bytes` of the character set as text; fails for bytes it does not have.
    pub fn decode(&self, bytes: &[u8]) -> Result<String, MailError> {
        let invalid = |position| MailError::Syntax { position, reason: "a byte not of the character set" };
        match self {
            MIMECharset::USASCII => match bytes.iter().position(|byte| *byte >= 0x80) {
                Some(position) => Err(invalid(position)),
                None => Ok(bytes.iter().map(|byte| char::from(*byte)).collect()),
            },
            MIMECharset::UTF8 => {
                String::from_utf8(bytes.to_vec()).map_err(|error| invalid(error.utf8_error().valid_up_to()))
            }
            MIMECharset::ISO88591 => Ok(bytes.iter().map(|byte| char::from(*byte)).collect()),
            MIMECharset::Windows1252 => {
                let mut text = String::with_capacity(bytes.len());
                for (position, byte) in bytes.iter().enumerate() {
                    let character = match byte {
                        0x80..=0x9F => MIMECharset::WINDOWS_1252_HIGH[usize::from(byte - 0x80)],
                        _ => char::from(*byte),
                    };
                    if character == '\u{FFFD}' {
                        return Err(invalid(position));
                    }
                    text.push(character);
                }
                Ok(text)
            }
        }
    }

    /// `text` in the character set; fails for characters it does not have.
    pub fn encode(&self, text: &str) -> Result<Vec<u8>, MailError> {
        let mut bytes = Vec::with_capacity(text.len());
        for (position, character) in text.char_indices() {
            let byte = match self {
                MIMECharset::UTF8 => {
                    bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
                    continue;
                }
                MIMECharset::USASCII => u8::try_from(character).ok().filter(u8::is_ascii),
                MIMECharset::ISO88591 => u8::try_from(character).ok(),
                MIMECharset::Windows1252 => {
                    match MIMECharset::WINDOWS_1252_HIGH.iter().position(|high| *high == character) {
                        Some(_) if character == '\u{FFFD}' => None,
                        Some(index) => Some(0x80 + index as u8),
                        None => u8::try_from(character).ok().filter(|byte| !(0x80..=0x9F).contains(byte)),
                    }
                }
            };
            match byte {
                Some(byte) => bytes.push(byte),
                None => return Err(MailError::Syntax { position, reason: "a character not of the character set" }),
            }
        }
        Ok(bytes)
    }
}
