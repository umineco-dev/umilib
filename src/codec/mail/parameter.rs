use alloc::string::String;
use alloc::vec::Vec;

use super::{MIMECharset, MailError, MailReader};

/// A parameter of a MIME field (RFC 2045 §5.1), its sections joined and
/// its octets decoded (RFC 2231 §3, §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEParameter {
    /// The name, in lower case: names compare without case (RFC 2045 §5.1).
    pub name: String,
    /// The octets of the value.
    pub value: Vec<u8>,
    /// The character set of the value, given as RFC 2231 §4 gives it.
    pub charset: Option<String>,
    /// The language of the value, given as RFC 2231 §4 gives it.
    pub language: Option<String>,
}

/// The parameters of a MIME field, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MIMEParameters {
    pub entries: Vec<MIMEParameter>,
}

/// A section of a parameter as it is written (RFC 2231 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEParameterSection {
    pub name: String,
    /// The number of the section; `None` for a value of one section.
    pub number: Option<u32>,
    /// Whether the value is extended: percent-encoded, with the character
    /// set and language first in the first section (RFC 2231 §4).
    pub extended: bool,
    pub value: Vec<u8>,
}

impl MIMEParameter {
    pub fn new(name: &str, value: &[u8]) -> MIMEParameter {
        MIMEParameter { name: name.to_ascii_lowercase(), value: value.to_vec(), charset: None, language: None }
    }

    /// The value as text: of its character set, if given and converted; of
    /// UTF-8 otherwise (RFC 6532 §3.2 takes it where MIME gives US-ASCII).
    pub fn text(&self) -> Result<String, MailError> {
        match &self.charset {
            Some(charset) if !charset.is_empty() => MIMECharset::decode_named(charset, &self.value),
            _ => MIMECharset::UTF8.decode(&self.value),
        }
    }
}

impl MIMEParameterSection {
    /// The longest number of a section read: more sections than this are
    /// taken as not of a value.
    pub const MAXIMUM_NUMBER: u32 = 999;

    /// Reads `; name=value`, where the name may end in a section number and
    /// an asterisk, and the value is a token or a quoted string.
    pub fn read(reader: &mut MailReader<'_>) -> Result<MIMEParameterSection, MailError> {
        reader.skip_cfws()?;
        let position = reader.position;
        let name = reader.token()?;
        let (name, extended) = match name.strip_suffix(b"*") {
            Some(name) => (name, true),
            None => (name, false),
        };
        let (name, number) = match name.iter().position(|byte| *byte == b'*') {
            Some(star) => {
                let digits = &name[star + 1..];
                let leading_zero = digits.len() > 1 && digits[0] == b'0';
                let number = core::str::from_utf8(digits).ok().and_then(|digits| digits.parse::<u32>().ok());
                let number = number.filter(|number| !leading_zero && *number <= MIMEParameterSection::MAXIMUM_NUMBER);
                let number = number.ok_or(MailError::Syntax { position, reason: "not a section number" })?;
                if !digits.iter().all(u8::is_ascii_digit) {
                    return Err(MailError::Syntax { position, reason: "not a section number" });
                }
                (&name[..star], Some(number))
            }
            None => (name, None),
        };
        if name.is_empty() || name.contains(&b'*') {
            return Err(MailError::Syntax { position, reason: "not a parameter name" });
        }
        reader.expect(b'=', "a parameter without =")?;
        reader.skip_cfws()?;
        let value = match reader.peek() {
            Some(b'"') => reader.quoted_string()?,
            _ => reader.token()?.to_vec(),
        };
        let name = core::str::from_utf8(name).unwrap_or_default().to_ascii_lowercase();
        Ok(MIMEParameterSection { name, number, extended, value })
    }

    /// The octets of percent-encoded text (RFC 2231 §7: `%` and two hexadecimal digits).
    pub fn percent_decode(text: &[u8]) -> Result<Vec<u8>, MailError> {
        let mut octets = Vec::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            if text[index] == b'%' {
                let digit = |offset: usize| text.get(index + offset).and_then(|digit| (*digit as char).to_digit(16));
                let (Some(high), Some(low)) = (digit(1), digit(2)) else {
                    return Err(MailError::Syntax { position: index, reason: "a % not of an octet" });
                };
                octets.push((high * 16 + low) as u8);
                index += 3;
            } else {
                octets.push(text[index]);
                index += 1;
            }
        }
        Ok(octets)
    }

    /// Whether `byte` is written as it is in an extended value: an
    /// attribute-char of RFC 2231 §7, a token character but `*`, `'` and `%`.
    pub fn is_attribute_char(byte: u8) -> bool {
        MailReader::is_token(byte) && !b"*'%".contains(&byte)
    }
}

impl MIMEParameters {
    pub fn new() -> MIMEParameters {
        MIMEParameters::default()
    }

    /// The parameter named `name`, in any case.
    pub fn get(&self, name: &str) -> Option<&MIMEParameter> {
        self.entries.iter().find(|parameter| parameter.name.eq_ignore_ascii_case(name))
    }

    /// The value of the parameter named `name`, if it is UTF-8 text (as
    /// the values of US-ASCII are).
    pub fn text(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|parameter| core::str::from_utf8(&parameter.value).ok())
    }

    /// Replaces the parameter named as `parameter` is, or adds it at the end.
    pub fn set(&mut self, parameter: MIMEParameter) {
        match self.entries.iter_mut().find(|entry| entry.name == parameter.name) {
            Some(entry) => *entry = parameter,
            None => self.entries.push(parameter),
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|parameter| !parameter.name.eq_ignore_ascii_case(name));
    }

    /// Reads the parameters that follow a value: `;` and a parameter, each,
    /// to the end of the text. A semicolon at the end is taken. A parameter
    /// given twice, or sections that do not go from 0 without a gap, are
    /// not taken (RFC 2231 §3), as the value would be in doubt.
    pub fn read(reader: &mut MailReader<'_>) -> Result<MIMEParameters, MailError> {
        let mut sections: Vec<MIMEParameterSection> = Vec::new();
        loop {
            reader.skip_cfws()?;
            if reader.is_end() {
                break;
            }
            reader.expect(b';', "parameters not separated by ;")?;
            reader.skip_cfws()?;
            if reader.is_end() {
                break;
            }
            sections.push(MIMEParameterSection::read(reader)?);
        }
        let position = reader.position;
        let duplicate = MailError::Syntax { position, reason: "a parameter given twice" };
        // The sections grouped by name once, in O(n log n): each group in order of number, the
        // groups in the order their names first came.
        let mut order: Vec<usize> = (0..sections.len()).collect();
        order.sort_by(|a, b| (&sections[*a].name, sections[*a].number).cmp(&(&sections[*b].name, sections[*b].number)));
        let mut groups: Vec<(usize, Vec<&MIMEParameterSection>)> = Vec::new();
        for index in order {
            match groups.last_mut() {
                Some((first, parts)) if parts[0].name == sections[index].name => {
                    *first = (*first).min(index);
                    parts.push(&sections[index]);
                }
                _ => groups.push((index, alloc::vec![&sections[index]])),
            }
        }
        groups.sort_by_key(|(first, _)| *first);
        let mut parameters = MIMEParameters::new();
        for (_, parts) in groups {
            let section = parts[0];
            let single = parts.iter().filter(|part| part.number.is_none()).count();
            if single > 1 || (single == 1 && parts.len() > 1) {
                return Err(duplicate);
            }
            for (index, part) in parts.iter().enumerate() {
                if part.number.is_some_and(|number| number as usize != index) {
                    return Err(MailError::Syntax { position, reason: "sections of a parameter with a gap or twice" });
                }
            }
            let mut parameter = MIMEParameter::new(&section.name, &[]);
            for (index, part) in parts.iter().enumerate() {
                if !part.extended {
                    parameter.value.extend_from_slice(&part.value);
                    continue;
                }
                let mut value = part.value.as_slice();
                if index == 0 {
                    let mut fields = value.splitn(3, |byte| *byte == b'\'');
                    let (Some(charset), Some(language), Some(rest)) = (fields.next(), fields.next(), fields.next())
                    else {
                        return Err(MailError::Syntax { position, reason: "an extended value without its quotes" });
                    };
                    let text_of = |bytes: &[u8]| {
                        core::str::from_utf8(bytes).ok().filter(|text| !text.is_empty()).map(String::from)
                    };
                    parameter.charset = text_of(charset);
                    parameter.language = text_of(language);
                    value = rest;
                }
                parameter.value.extend_from_slice(&MIMEParameterSection::percent_decode(value)?);
            }
            parameters.entries.push(parameter);
        }
        Ok(parameters)
    }

    /// Writes the parameters, each `; name=value`. A value of token
    /// characters is written as it is, one of other US-ASCII text quoted; a
    /// value with a character set or a language, or other octets, is
    /// extended (RFC 2231 §4), of UTF-8 if no character set is given and it is
    /// not ASCII, and in
    /// sections of at most `MailField::LINE` characters (§3).
    pub fn encode(&self, out: &mut String) {
        for parameter in &self.entries {
            let plain = parameter.charset.is_none()
                && parameter.language.is_none()
                && parameter.value.iter().all(|byte| matches!(byte, b' ' | b'\t') || (33..=126).contains(byte));
            if plain {
                out.push_str("; ");
                out.push_str(&parameter.name);
                out.push('=');
                let token =
                    !parameter.value.is_empty() && parameter.value.iter().all(|byte| MailReader::is_token(*byte));
                let value = core::str::from_utf8(&parameter.value).unwrap_or_default();
                if token {
                    out.push_str(value);
                } else {
                    out.push('"');
                    for character in value.chars() {
                        if character == '"' || character == '\\' {
                            out.push('\\');
                        }
                        out.push(character);
                    }
                    out.push('"');
                }
                continue;
            }
            let mut first = String::new();
            // A value of no character set is labelled UTF-8 only where it has octets beyond ASCII:
            // an ASCII value is written of none (`''`), as it was read.
            let unlabelled = if parameter.value.is_ascii() { "" } else { "UTF-8" };
            first.push_str(parameter.charset.as_deref().unwrap_or(unlabelled));
            first.push('\'');
            first.push_str(parameter.language.as_deref().unwrap_or(""));
            first.push('\'');
            let head = first.len();
            let mut sections = alloc::vec![first];
            // Sections of at most a line, or longer where a line each would number more than
            // MAXIMUM_NUMBER, which a reader does not take: each section but the last holds more
            // than `room` - 3 characters, so there are at most MAXIMUM_NUMBER + 1.
            let width_of = |byte: &u8| if MIMEParameterSection::is_attribute_char(*byte) { 1 } else { 3 };
            let total = head + parameter.value.iter().map(width_of).sum::<usize>();
            let sections_allowed = MIMEParameterSection::MAXIMUM_NUMBER as usize + 1;
            let room = super::MailField::LINE
                .saturating_sub(parameter.name.len() + 8)
                .max(total.div_ceil(sections_allowed) + 3);
            for byte in &parameter.value {
                const HEXADECIMAL: &[u8; 16] = b"0123456789ABCDEF";
                let attribute = MIMEParameterSection::is_attribute_char(*byte);
                let width = if attribute { 1 } else { 3 };
                let empty = if sections.len() == 1 { head } else { 0 };
                let last = sections.last_mut().expect("a section");
                if last.len() + width > room && last.len() > empty {
                    sections.push(String::new());
                }
                let last = sections.last_mut().expect("a section");
                if attribute {
                    last.push(char::from(*byte));
                } else {
                    last.push('%');
                    last.push(char::from(HEXADECIMAL[usize::from(byte >> 4)]));
                    last.push(char::from(HEXADECIMAL[usize::from(byte & 0xF)]));
                }
            }
            let count = sections.len();
            for (index, section) in sections.iter().enumerate() {
                out.push_str("; ");
                out.push_str(&parameter.name);
                if count > 1 {
                    out.push_str(&alloc::format!("*{index}"));
                }
                out.push_str("*=");
                out.push_str(section);
            }
        }
    }
}
