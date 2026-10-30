use alloc::string::String;
use alloc::vec::Vec;

use super::{MIMECharset, MailError};
use crate::codec::base::Encoding;
use crate::codec::base::base64::Base64;

/// The encoding of the text of an encoded word (RFC 2047 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MIMEWordEncoding {
    /// Base64 (§4.1).
    B = 0,
    /// The Q encoding, like Quoted-Printable (§4.2).
    Q = 1,
}

impl MIMEWordEncoding {
    /// The encoding of its number (its discriminant).
    pub fn from_u8(value: u8) -> Option<MIMEWordEncoding> {
        match value {
            0 => Some(MIMEWordEncoding::B),
            1 => Some(MIMEWordEncoding::Q),
            _ => None,
        }
    }
}

/// An encoded word (RFC 2047 §2): text of a character set in a header,
/// `=?charset?encoding?encoded-text?=`, with the language of RFC 2231 §5.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEEncodedWord {
    pub charset: String,
    pub language: Option<String>,
    pub encoding: MIMEWordEncoding,
    /// The bytes of the text, decoded from the encoding, in the character set.
    pub data: Vec<u8>,
}

impl MIMEEncodedWord {
    /// The longest encoded word (§2).
    pub const MAXIMUM_LENGTH: usize = 75;

    /// Whether `byte` is a character of a token of RFC 2047 §2: US-ASCII but
    /// space, controls and especials.
    pub fn is_token(byte: u8) -> bool {
        (33..=126).contains(&byte) && !b"()<>@,;:\"/[]?.=".contains(&byte)
    }

    /// The encoded word that is all of `word`.
    pub fn parse(word: &[u8]) -> Result<MIMEEncodedWord, MailError> {
        let invalid = |position, reason| MailError::Syntax { position, reason };
        if word.len() > MIMEEncodedWord::MAXIMUM_LENGTH {
            return Err(MailError::TooLong { length: word.len(), maximum: MIMEEncodedWord::MAXIMUM_LENGTH });
        }
        let inner = word
            .strip_prefix(b"=?")
            .and_then(|inner| inner.strip_suffix(b"?="))
            .ok_or(invalid(0, "not an encoded word"))?;
        let mut parts = inner.splitn(3, |byte| *byte == b'?');
        let (Some(charset), Some(encoding), Some(text)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(invalid(0, "an encoded word not of three parts"));
        };
        let (charset, language) = match charset.iter().position(|byte| *byte == b'*') {
            Some(star) => (&charset[..star], Some(&charset[star + 1..])),
            None => (charset, None),
        };
        let is_token = |bytes: &[u8]| !bytes.is_empty() && bytes.iter().all(|byte| MIMEEncodedWord::is_token(*byte));
        if !is_token(charset) || language.is_some_and(|language| !is_token(language)) {
            return Err(invalid(2, "not a character set of an encoded word"));
        }
        if text.is_empty() || text.iter().any(|byte| !(33..=126).contains(byte) || *byte == b'?') {
            return Err(invalid(0, "not the text of an encoded word"));
        }
        let encoding = match encoding {
            b"B" | b"b" => MIMEWordEncoding::B,
            b"Q" | b"q" => MIMEWordEncoding::Q,
            _ => return Err(invalid(0, "not an encoding of an encoded word")),
        };
        let data = match encoding {
            MIMEWordEncoding::B => Base64::STANDARD.decode(text)?,
            MIMEWordEncoding::Q => MIMEEncodedWord::decode_q(text)?,
        };
        let text_of = |bytes: &[u8]| String::from(core::str::from_utf8(bytes).unwrap_or_default());
        Ok(MIMEEncodedWord { charset: text_of(charset), language: language.map(text_of), encoding, data })
    }

    /// The bytes of Q-encoded text (§4.2): `_` a space, `=` and two
    /// hexadecimal digits a byte, any other character itself.
    pub fn decode_q(text: &[u8]) -> Result<Vec<u8>, MailError> {
        let mut data = Vec::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            match text[index] {
                b'_' => data.push(b' '),
                b'=' => {
                    let digit =
                        |offset: usize| text.get(index + offset).and_then(|digit| (*digit as char).to_digit(16));
                    let (Some(high), Some(low)) = (digit(1), digit(2)) else {
                        return Err(MailError::Syntax { position: index, reason: "an = not of a byte" });
                    };
                    data.push((high * 16 + low) as u8);
                    index += 2;
                }
                byte => data.push(byte),
            }
            index += 1;
        }
        Ok(data)
    }

    /// The text of the word, if its character set is one [`MIMECharset::decode_named`] converts.
    pub fn text(&self) -> Result<String, MailError> {
        MIMECharset::decode_named(&self.charset, &self.data)
    }

    /// The word as it is written. The Q encoding writes only the characters
    /// that every place of an encoded word takes (§5 (3)).
    pub fn encode(&self) -> String {
        let mut word = String::from("=?");
        word.push_str(&self.charset);
        if let Some(language) = &self.language {
            word.push('*');
            word.push_str(language);
        }
        match self.encoding {
            MIMEWordEncoding::B => {
                word.push_str("?B?");
                word.push_str(&Base64::STANDARD.encode(&self.data));
            }
            MIMEWordEncoding::Q => {
                word.push_str("?Q?");
                for byte in &self.data {
                    MIMEEncodedWord::push_q(&mut word, *byte);
                }
            }
        }
        word.push_str("?=");
        word
    }

    /// Writes `byte` Q-encoded.
    pub fn push_q(word: &mut String, byte: u8) {
        match byte {
            b' ' => word.push('_'),
            b'!' | b'*' | b'+' | b'-' | b'/' => word.push(char::from(byte)),
            byte if byte.is_ascii_alphanumeric() => word.push(char::from(byte)),
            byte => {
                const HEXADECIMAL: &[u8; 16] = b"0123456789ABCDEF";
                word.push('=');
                word.push(char::from(HEXADECIMAL[usize::from(byte >> 4)]));
                word.push(char::from(HEXADECIMAL[usize::from(byte & 0xF)]));
            }
        }
    }

    /// The text of unstructured header text (or of a phrase, unquoted): its
    /// line breaks removed (unfolded, RFC 5322 §2.2.3), its encoded words
    /// decoded, and the white space between two encoded words removed
    /// (§6.2). An encoded word is a word between white space (§5 (1));
    /// one that cannot be decoded, or of a character set not converted, is
    /// left as it is (§6.2, §6.3). The rest must be UTF-8 (RFC 6532 §3.2).
    pub fn decode_text(text: &[u8]) -> Result<String, MailError> {
        let mut decoded = String::with_capacity(text.len());
        let mut pending_space: &[u8] = &[];
        let mut after_word = false;
        let mut index = 0;
        while index < text.len() {
            let start = index;
            let space = matches!(text[index], b' ' | b'\t' | b'\r' | b'\n');
            while index < text.len() && matches!(text[index], b' ' | b'\t' | b'\r' | b'\n') == space {
                index += 1;
            }
            let run = &text[start..index];
            if space {
                pending_space = run;
                continue;
            }
            let word = MIMEEncodedWord::parse(run).and_then(|word| word.text());
            let is_word = word.is_ok();
            if !(is_word && after_word) {
                for byte in pending_space {
                    if !matches!(byte, b'\r' | b'\n') {
                        decoded.push(char::from(*byte));
                    }
                }
            }
            pending_space = &[];
            match word {
                Ok(word) => decoded.push_str(&word),
                Err(_) => decoded.push_str(core::str::from_utf8(run).map_err(|error| MailError::Syntax {
                    position: start + error.valid_up_to(),
                    reason: "not UTF-8",
                })?),
            }
            after_word = is_word;
        }
        for byte in pending_space {
            if !matches!(byte, b'\r' | b'\n') {
                decoded.push(char::from(*byte));
            }
        }
        Ok(decoded)
    }

    /// `text` for a header that takes only US-ASCII: as it is if it is
    /// printable US-ASCII and spaces with no `=?` in it, else encoded words
    /// of UTF-8 separated by spaces, each at most 75 characters and of whole
    /// characters (§5), in the encoding that is shorter.
    pub fn encode_text(text: &str) -> String {
        let plain = text.bytes().all(|byte| byte == b' ' || (33..=126).contains(&byte));
        if plain && !text.contains("=?") {
            return String::from(text);
        }
        let q_length = |bytes: &[u8]| -> usize {
            bytes.iter().map(|byte| if byte.is_ascii_alphanumeric() || b" !*+-/".contains(byte) { 1 } else { 3 }).sum()
        };
        let b_length = |bytes: &[u8]| bytes.len().div_ceil(3) * 4;
        let encoding = match q_length(text.as_bytes()) <= b_length(text.as_bytes()) {
            true => MIMEWordEncoding::Q,
            false => MIMEWordEncoding::B,
        };
        let length = |bytes: &[u8]| match encoding {
            MIMEWordEncoding::Q => q_length(bytes),
            MIMEWordEncoding::B => b_length(bytes),
        };
        // =?UTF-8?Q?...?=
        let room = MIMEEncodedWord::MAXIMUM_LENGTH - 12;
        let mut encoded = String::new();
        let mut start = 0;
        while start < text.len() {
            let mut end = start;
            for (offset, character) in text[start..].char_indices() {
                let next = start + offset + character.len_utf8();
                if length(&text.as_bytes()[start..next]) > room {
                    break;
                }
                end = next;
            }
            if !encoded.is_empty() {
                encoded.push(' ');
            }
            let word = MIMEEncodedWord {
                charset: String::from("UTF-8"),
                language: None,
                encoding,
                data: text.as_bytes()[start..end].to_vec(),
            };
            encoded.push_str(&word.encode());
            start = end;
        }
        encoded
    }
}
