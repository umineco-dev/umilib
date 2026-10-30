use alloc::string::String;
use alloc::vec::Vec;

use super::{MIMEEncodedWord, MailAddress, MailConfig, MailDate, MailError, MailMailbox, MailMessageID};

/// A header field (RFC 5322 §2.2): its name and its value as it is in the
/// message, folded or not, without the space after the colon and the line
/// break that ends it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MailField {
    pub name: String,
    pub value: Vec<u8>,
}

impl MailField {
    /// The longest line a message may have, its line break not counted (RFC 5322 §2.1.1: MUST).
    pub const MAXIMUM_LINE: usize = 998;
    /// The longest line a message should have (RFC 5322 §2.1.1: SHOULD).
    pub const LINE: usize = 78;

    /// A field of `name` and the unfolded `value`, folded at its spaces so
    /// that lines are of at most 78 characters where its words allow (RFC
    /// 5322 §2.2.3: folding is the writer's); fails for a name that is not
    /// one, a value with a line break or a NUL (§2.2: a value is of
    /// printable characters and white space), or a word too long for a line
    /// of 998 characters (§2.1.1: MUST). A fold is made only before a word,
    /// so that no line is of white space alone (§3.2.2: MUST NOT).
    pub fn new(name: &str, value: &[u8]) -> Result<MailField, MailError> {
        if !MailField::is_name(name) {
            return Err(MailError::Syntax { position: 0, reason: "not a field name" });
        }
        if let Some(position) = value.iter().position(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(MailError::Syntax { position, reason: "a line break in a field value" });
        }
        let value = value.strip_prefix(b" ").unwrap_or(value);
        let mut folded = Vec::with_capacity(value.len() + value.len() / MailField::LINE * 3);
        let mut line = name.len() + 2;
        for (index, word) in value.split(|byte| *byte == b' ').enumerate() {
            if index > 0 {
                let fold = !word.is_empty() && line > 1 && line + 1 + word.len() > MailField::LINE;
                if fold {
                    folded.extend_from_slice(b"\r\n ");
                    line = 1;
                } else {
                    folded.push(b' ');
                    line += 1;
                }
            }
            folded.extend_from_slice(word);
            line += word.len();
            if line > MailField::MAXIMUM_LINE {
                return Err(MailError::TooLong { length: line, maximum: MailField::MAXIMUM_LINE });
            }
        }
        Ok(MailField { name: String::from(name), value: folded })
    }

    /// Whether `name` is a field name: printable US-ASCII but the colon (RFC 5322 §3.6.8).
    pub fn is_name(name: &str) -> bool {
        !name.is_empty() && name.bytes().all(|byte| (33..=126).contains(&byte) && byte != b':')
    }

    /// The value unfolded: each line break followed by white space removed (RFC 5322 §2.2.3).
    pub fn unfolded(&self) -> Vec<u8> {
        let mut unfolded = Vec::with_capacity(self.value.len());
        let mut index = 0;
        while index < self.value.len() {
            match self.value[index] {
                b'\r' if self.value.get(index + 1) == Some(&b'\n') => index += 2,
                b'\n' | b'\r' => index += 1,
                byte => {
                    unfolded.push(byte);
                    index += 1;
                }
            }
        }
        unfolded
    }

    /// Writes the field as it is, a line break after it.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&self.value);
        out.extend_from_slice(b"\r\n");
    }
}

/// The fields of a header section, in order (RFC 5322 §2.2, §3.6: their
/// order is kept, and names compare without case).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MailFields {
    pub entries: Vec<MailField>,
}

impl MailFields {
    pub fn new() -> MailFields {
        MailFields::default()
    }

    /// The value of the first field named `name`.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.iter().find(|field| field.name.eq_ignore_ascii_case(name)).map(|field| field.value.as_slice())
    }

    /// The first field named `name`.
    pub fn field(&self, name: &str) -> Option<&MailField> {
        self.entries.iter().find(|field| field.name.eq_ignore_ascii_case(name))
    }

    /// The fields named `name`, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a MailField> + 'a {
        self.entries.iter().filter(move |field| field.name.eq_ignore_ascii_case(name))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.field(name).is_some()
    }

    /// Adds a field at the end ([`MailField::new`]).
    pub fn push(&mut self, name: &str, value: &[u8]) -> Result<(), MailError> {
        self.entries.push(MailField::new(name, value)?);
        Ok(())
    }

    /// Replaces the fields named `name` by one, where the first was, or at the end.
    pub fn set(&mut self, name: &str, value: &[u8]) -> Result<(), MailError> {
        let field = MailField::new(name, value)?;
        let position = self.entries.iter().position(|field| field.name.eq_ignore_ascii_case(name));
        self.remove(name);
        let position = position.unwrap_or(self.entries.len());
        self.entries.insert(position, field);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|field| !field.name.eq_ignore_ascii_case(name));
    }

    /// The date-time of the first field named `name` (Date, Resent-Date; RFC 5322 §3.3).
    pub fn date(&self, name: &str) -> Result<Option<MailDate>, MailError> {
        self.get(name).map(MailDate::parse).transpose()
    }

    /// The addresses of the first field named `name` (To, Cc, Bcc, Reply-To; RFC 5322 §3.4).
    pub fn addresses(&self, name: &str) -> Result<Option<Vec<MailAddress>>, MailError> {
        self.get(name).map(|value| MailAddress::parse_list(value, true)).transpose()
    }

    /// The mailboxes of the first field named `name` (From, Resent-From; RFC 5322 §3.4).
    pub fn mailboxes(&self, name: &str) -> Result<Option<Vec<MailMailbox>>, MailError> {
        self.get(name).map(|value| MailMailbox::parse_list(value, true)).transpose()
    }

    /// The one address of the first field named `name` (Sender, which RFC
    /// 6854 §2.1 lets be a group).
    pub fn address(&self, name: &str) -> Result<Option<MailAddress>, MailError> {
        self.get(name).map(|value| MailAddress::parse(value, true)).transpose()
    }

    /// The one mailbox of the first field named `name` (Sender; RFC 5322 §3.6.2).
    pub fn mailbox(&self, name: &str) -> Result<Option<MailMailbox>, MailError> {
        self.get(name).map(|value| MailMailbox::parse(value, true)).transpose()
    }

    /// The message identifiers of the first field named `name` (Message-ID,
    /// In-Reply-To, References; RFC 5322 §3.6.4).
    pub fn message_ids(&self, name: &str) -> Result<Option<Vec<MailMessageID>>, MailError> {
        self.get(name).map(|value| MailMessageID::parse_list(value, true)).transpose()
    }

    /// The unstructured text of the first field named `name` (Subject,
    /// Comments; RFC 5322 §3.6.5), unfolded and its encoded words decoded
    /// (RFC 2047), white space at its ends removed.
    pub fn text(&self, name: &str) -> Result<Option<String>, MailError> {
        let text = self.get(name).map(MIMEEncodedWord::decode_text).transpose()?;
        Ok(text.map(|text| String::from(text.trim_matches([' ', '\t']))))
    }

    /// The fields of the header section that begins `text`, and where the
    /// body begins: after the empty line, or the end of the text if there is
    /// none (RFC 5322 §2.1). Lines end in CRLF, or in LF alone as files of
    /// messages often have them. A field may have white space before its
    /// colon (§4.5).
    pub fn decode(text: &[u8], config: &MailConfig) -> Result<(MailFields, usize), MailError> {
        let mut fields = MailFields::new();
        let mut position = 0;
        loop {
            match &text[position..] {
                [] => return Ok((fields, position)),
                [b'\r', b'\n', ..] => return Ok((fields, position + 2)),
                [b'\n', ..] => return Ok((fields, position + 1)),
                [b' ' | b'\t', ..] => {
                    return Err(MailError::Syntax { position, reason: "a folded line before any field" });
                }
                _ => {}
            }
            let start = position;
            let colon = text[start..]
                .iter()
                .position(|byte| matches!(byte, b':' | b'\r' | b'\n'))
                .map(|offset| start + offset)
                .filter(|colon| text[*colon] == b':')
                .ok_or(MailError::Syntax { position: start, reason: "a line that is not a field" })?;
            let name = core::str::from_utf8(&text[start..colon]).unwrap_or_default().trim_end_matches([' ', '\t']);
            if !MailField::is_name(name) {
                return Err(MailError::Syntax { position: start, reason: "not a field name" });
            }
            // The value: to the line break not followed by white space.
            let mut end = colon + 1;
            loop {
                let line_end = text[end..].iter().position(|byte| *byte == b'\n').map(|offset| end + offset);
                let Some(line_end) = line_end else {
                    end = text.len();
                    break;
                };
                if matches!(text.get(line_end + 1), Some(b' ' | b'\t')) {
                    end = line_end + 1;
                    continue;
                }
                end = line_end;
                break;
            }
            let value_end = if end > colon + 1 && text[end - 1] == b'\r' && end < text.len() { end - 1 } else { end };
            if value_end - start > config.maximum_field_length {
                return Err(MailError::TooLong { length: value_end - start, maximum: config.maximum_field_length });
            }
            if fields.entries.len() == config.maximum_fields {
                return Err(MailError::TooMany { maximum: config.maximum_fields });
            }
            let value = &text[colon + 1..value_end];
            let value = value.strip_prefix(b" ").unwrap_or(value);
            if !config.utf8
                && let Some(offset) = value.iter().position(|byte| *byte >= 0x80)
            {
                return Err(MailError::Syntax {
                    position: colon + 1 + offset,
                    reason: "a byte of no US-ASCII character",
                });
            }
            fields.entries.push(MailField { name: String::from(name), value: value.to_vec() });
            position = (end + 1).min(text.len());
        }
    }

    /// Writes the fields, each a line, and no empty line after them.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for field in &self.entries {
            field.encode(out);
        }
    }
}
