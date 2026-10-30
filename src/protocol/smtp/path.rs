use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::SMTPError;
use crate::protocol::ip::IPv6Address;

/// A mailbox of SMTP (RFC 5321 §4.1.2): a local part and a domain or an
/// address literal. The local part is unquoted: written quoted where it is
/// not a dot-string. With SMTPUTF8 (RFC 6531 §3.3) both may be UTF-8.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPMailbox {
    pub local: String,
    pub domain: String,
}

/// A reverse-path or forward-path (RFC 5321 §4.1.2): the null path `<>` of
/// MAIL, a mailbox, or `<Postmaster>` of RCPT (§4.1.1.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SMTPPath {
    Null,
    Mailbox(SMTPMailbox),
    Postmaster,
}

/// The xtext of RFC 3461 §4: printable US-ASCII but `+` and `=`, other
/// octets as `+` and two upper-case hexadecimal digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SMTPXText;

impl SMTPMailbox {
    pub fn new(local: &str, domain: &str) -> SMTPMailbox {
        SMTPMailbox { local: String::from(local), domain: String::from(domain) }
    }

    /// Whether `byte` is atext (RFC 5322 §3.2.3), or of UTF-8 with `utf8` (RFC 6531 §3.3).
    pub fn is_atext(byte: u8, utf8: bool) -> bool {
        byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte) || (utf8 && byte >= 0x80)
    }

    /// Whether `text` is a domain of §4.1.2: labels of letters, digits and
    /// hyphens, not beginning or ending with a hyphen; or U-labels of UTF-8
    /// too with `utf8` (RFC 6531 §3.3).
    pub fn is_domain_of(text: &[u8], utf8: bool) -> bool {
        !text.is_empty()
            && text.split(|byte| *byte == b'.').all(|label| {
                let letter_digit = |byte: &u8| byte.is_ascii_alphanumeric() || (utf8 && *byte >= 0x80);
                !label.is_empty()
                    && label.first().is_some_and(letter_digit)
                    && label.last().is_some_and(letter_digit)
                    && label.iter().all(|byte| letter_digit(byte) || *byte == b'-')
            })
    }

    /// [`SMTPMailbox::is_domain_of`] of US-ASCII.
    pub fn is_domain(text: &[u8]) -> bool {
        SMTPMailbox::is_domain_of(text, false)
    }

    /// Whether `text` is an address literal of §4.1.3, with its brackets: an
    /// IPv4 address, `IPv6:` and an IPv6 address, or a standardized tag and its content.
    pub fn is_address_literal(text: &[u8]) -> bool {
        let Some(inner) = text.strip_prefix(b"[").and_then(|inner| inner.strip_suffix(b"]")) else {
            return false;
        };
        let Ok(inner) = core::str::from_utf8(inner) else {
            return false;
        };
        if let Some(address) = inner.strip_prefix("IPv6:") {
            return address.parse::<IPv6Address>().is_ok();
        }
        if let Some((tag, content)) = inner.split_once(':') {
            let tag_valid = SMTPMailbox::is_domain(tag.as_bytes()) && !tag.contains('.');
            return tag_valid && !content.is_empty() && content.bytes().all(|byte| matches!(byte, 33..=90 | 94..=126));
        }
        // Snum: 1 to 3 digits of a value of 0 to 255, leading zeros taken.
        let parts: Vec<&str> = inner.split('.').collect();
        parts.len() == 4
            && parts.iter().all(|part| {
                (1..=3).contains(&part.len())
                    && part.bytes().all(|byte| byte.is_ascii_digit())
                    && part.parse::<u16>().is_ok_and(|value| value <= 255)
            })
    }

    /// Whether `local` is a dot-string (§4.1.2): atoms joined by single dots.
    pub fn is_dot_string(local: &[u8], utf8: bool) -> bool {
        !local.is_empty()
            && local
                .split(|byte| *byte == b'.')
                .all(|atom| !atom.is_empty() && atom.iter().all(|byte| SMTPMailbox::is_atext(*byte, utf8)))
    }

    /// The mailbox of `text`: local part, `@`, domain or address literal.
    pub fn parse(text: &[u8], utf8: bool) -> Result<SMTPMailbox, SMTPError> {
        let invalid = |reason| Err(SMTPError::Syntax { reason });
        let (local, rest) = if text.first() == Some(&b'"') {
            let mut local = Vec::new();
            let mut index = 1;
            loop {
                match text.get(index) {
                    None => return invalid("a quoted local part not closed"),
                    Some(b'"') => break,
                    Some(b'\\') => match text.get(index + 1) {
                        Some(byte @ 32..=126) => {
                            local.push(*byte);
                            index += 2;
                        }
                        Some(byte) if utf8 && *byte >= 0x80 => {
                            local.push(*byte);
                            index += 2;
                        }
                        _ => return invalid("a quoted pair of no character"),
                    },
                    Some(byte @ (32..=33 | 35..=91 | 93..=126)) => {
                        local.push(*byte);
                        index += 1;
                    }
                    Some(byte) if utf8 && *byte >= 0x80 => {
                        local.push(*byte);
                        index += 1;
                    }
                    Some(_) => return invalid("a character a quoted local part does not take"),
                }
            }
            (local, &text[index + 1..])
        } else {
            let at = text
                .iter()
                .rposition(|byte| *byte == b'@')
                .ok_or(SMTPError::Syntax { reason: "a mailbox without @" })?;
            if !SMTPMailbox::is_dot_string(&text[..at], utf8) {
                return invalid("a local part that is not a dot-string");
            }
            (text[..at].to_vec(), &text[at..])
        };
        let domain = rest.strip_prefix(b"@").ok_or(SMTPError::Syntax { reason: "a mailbox without @" })?;
        if !SMTPMailbox::is_domain_of(domain, utf8) && !SMTPMailbox::is_address_literal(domain) {
            return invalid("not a domain or an address literal");
        }
        let text_of = |bytes: Vec<u8>| String::from_utf8(bytes).map_err(|_| SMTPError::Syntax { reason: "not UTF-8" });
        Ok(SMTPMailbox { local: text_of(local)?, domain: text_of(domain.to_vec())? })
    }

    /// Whether the mailbox has a character not of US-ASCII, which needs SMTPUTF8 (RFC 6531 §3.2).
    pub fn is_utf8(&self) -> bool {
        !self.local.is_ascii() || !self.domain.is_ascii()
    }

    /// The local part as it is written: as it is if it is a dot-string, quoted with the least
    /// quoting otherwise (§4.1.2: the sending system SHOULD transmit the minimum quoting).
    pub fn local_text(&self) -> String {
        if SMTPMailbox::is_dot_string(self.local.as_bytes(), true) {
            return self.local.clone();
        }
        let mut quoted = String::with_capacity(self.local.len() + 2);
        quoted.push('"');
        for character in self.local.chars() {
            if character == '"' || character == '\\' {
                quoted.push('\\');
            }
            quoted.push(character);
        }
        quoted.push('"');
        quoted
    }
}

impl fmt::Display for SMTPMailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.local_text(), self.domain)
    }
}

impl SMTPPath {
    /// The path of `text`, with its angle brackets; a source route (A-d-l)
    /// before the mailbox is taken and ignored (§4.1.2: MUST be accepted,
    /// SHOULD be ignored). `<Postmaster>` is taken where `postmaster`.
    pub fn parse(text: &[u8], utf8: bool, postmaster: bool) -> Result<SMTPPath, SMTPError> {
        let inner = text
            .strip_prefix(b"<")
            .and_then(|inner| inner.strip_suffix(b">"))
            .ok_or(SMTPError::Syntax { reason: "a path not in angle brackets" })?;
        if inner.is_empty() {
            return Ok(SMTPPath::Null);
        }
        if postmaster && inner.eq_ignore_ascii_case(b"postmaster") {
            return Ok(SMTPPath::Postmaster);
        }
        let mut mailbox = inner;
        if inner.first() == Some(&b'@') {
            let colon = inner
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(SMTPError::Syntax { reason: "a source route without :" })?;
            for domain in inner[..colon].split(|byte| *byte == b',') {
                let domain =
                    domain.strip_prefix(b"@").ok_or(SMTPError::Syntax { reason: "a source route of no domain" })?;
                if !SMTPMailbox::is_domain_of(domain, utf8) && !SMTPMailbox::is_address_literal(domain) {
                    return Err(SMTPError::Syntax { reason: "a source route of no domain" });
                }
            }
            mailbox = &inner[colon + 1..];
        }
        SMTPMailbox::parse(mailbox, utf8).map(SMTPPath::Mailbox)
    }

    pub fn mailbox(&self) -> Option<&SMTPMailbox> {
        match self {
            SMTPPath::Mailbox(mailbox) => Some(mailbox),
            _ => None,
        }
    }
}

impl fmt::Display for SMTPPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SMTPPath::Null => formatter.write_str("<>"),
            SMTPPath::Mailbox(mailbox) => write!(formatter, "<{mailbox}>"),
            SMTPPath::Postmaster => formatter.write_str("<Postmaster>"),
        }
    }
}

impl SMTPXText {
    /// `data` as xtext.
    pub fn encode(data: &[u8]) -> String {
        let mut text = String::with_capacity(data.len());
        for byte in data {
            match byte {
                b'+' | b'=' => text.push_str(&alloc::format!("+{byte:02X}")),
                33..=126 => text.push(char::from(*byte)),
                _ => text.push_str(&alloc::format!("+{byte:02X}")),
            }
        }
        text
    }

    /// The octets of xtext; `+` must be followed by two upper-case hexadecimal digits.
    pub fn decode(text: &[u8]) -> Result<Vec<u8>, SMTPError> {
        let mut data = Vec::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            match text[index] {
                b'+' => {
                    let digit = |offset: usize| {
                        text.get(index + offset)
                            .filter(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
                            .and_then(|digit| (*digit as char).to_digit(16))
                    };
                    let (Some(high), Some(low)) = (digit(1), digit(2)) else {
                        return Err(SMTPError::Syntax { reason: "a + not of two hexadecimal digits" });
                    };
                    data.push((high * 16 + low) as u8);
                    index += 3;
                }
                byte @ 33..=126 if byte != b'=' => {
                    data.push(byte);
                    index += 1;
                }
                _ => return Err(SMTPError::Syntax { reason: "a character xtext does not take" }),
            }
        }
        Ok(data)
    }
}
