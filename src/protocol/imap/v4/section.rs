use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::{IMAPError, IMAPReader, IMAPWriter};
use crate::codec::mail::MIMEEntity;

/// The text of a section (RFC 9051 §9 `section-msgtext`, `section-text`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPSectionText {
    Header,
    /// The fields named, or with `not` all others; names in upper case, as they compare without case.
    HeaderFields {
        not: bool,
        fields: Vec<String>,
    },
    Text,
    /// The MIME header of a body part.
    MIME,
}

/// A section of FETCH BODY (RFC 9051 §6.4.5): a part, its numbers from
/// the top (empty for the whole message), and a text of it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPSection {
    pub part: Vec<u32>,
    pub text: Option<IMAPSectionText>,
}

impl IMAPSection {
    pub fn new(part: &[u32], text: Option<IMAPSectionText>) -> IMAPSection {
        IMAPSection { part: part.to_vec(), text }
    }

    /// Reads `[section-spec]`, its brackets included; `binary` for
    /// `section-binary`, of a part alone (RFC 3516).
    pub fn read(reader: &mut IMAPReader<'_>, binary: bool) -> Result<IMAPSection, IMAPError> {
        reader.expect(b'[', "not a section")?;
        let mut section = IMAPSection::default();
        if reader.eat(b']') {
            return Ok(section);
        }
        if reader.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            loop {
                section.part.push(reader.nz_number()?);
                if !(reader.peek() == Some(b'.')
                    && reader.data.get(reader.position + 1).is_some_and(u8::is_ascii_digit))
                {
                    break;
                }
                reader.position += 1;
            }
            if binary || reader.peek() == Some(b']') {
                reader.expect(b']', "a section not closed")?;
                return Ok(section);
            }
            reader.expect(b'.', "a section of no text")?;
        } else if binary {
            return Err(reader.error("a binary section of no part"));
        }
        let not = reader.eat_prefix("HEADER.FIELDS.NOT");
        let text = if not || reader.eat_prefix("HEADER.FIELDS") {
            reader.sp()?;
            let fields = reader.list(|reader| Ok(reader.astring_text()?.to_ascii_uppercase()))?;
            if fields.is_empty() {
                return Err(reader.error("a list of no field names"));
            }
            IMAPSectionText::HeaderFields { not, fields }
        } else if reader.eat_prefix("HEADER") {
            IMAPSectionText::Header
        } else if reader.eat_prefix("TEXT") {
            IMAPSectionText::Text
        } else if !section.part.is_empty() && reader.eat_prefix("MIME") {
            IMAPSectionText::MIME
        } else {
            return Err(reader.error("not the text of a section"));
        };
        section.text = Some(text);
        reader.expect(b']', "a section not closed")?;
        Ok(section)
    }

    /// Writes the section, its brackets included.
    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(b"[");
        let part: Vec<String> = self.part.iter().map(|number| alloc::format!("{number}")).collect();
        writer.raw(part.join(".").as_bytes());
        if let Some(text) = &self.text {
            if !self.part.is_empty() {
                writer.raw(b".");
            }
            match text {
                IMAPSectionText::Header => writer.raw(b"HEADER"),
                IMAPSectionText::Text => writer.raw(b"TEXT"),
                IMAPSectionText::MIME => writer.raw(b"MIME"),
                IMAPSectionText::HeaderFields { not, fields } => {
                    writer.raw(if *not { b"HEADER.FIELDS.NOT " } else { b"HEADER.FIELDS " });
                    writer.list(fields, |writer, field| {
                        writer.astring(field.as_bytes());
                    })
                }
            };
        }
        writer.raw(b"]");
    }

    /// The entity a part's numbers name in a message (§6.4.5): a
    /// multipart's parts are numbered from 1; the parts of a part that is an
    /// encapsulated message are those of that message; a message or a part
    /// that is not a multipart has a part 1, itself (its body).
    pub fn locate<'e>(entity: &'e MIMEEntity, part: &[u32]) -> Option<&'e MIMEEntity> {
        let mut current = entity;
        for (step, number) in part.iter().enumerate() {
            let index = usize::try_from(*number).ok()?.checked_sub(1)?;
            let container = match (step, current.message.as_deref()) {
                (1.., Some(message)) => message,
                _ => current,
            };
            current = match container.parts.is_empty() {
                false => container.parts.get(index)?,
                true if index == 0 => container,
                true => return None,
            };
        }
        Some(current)
    }

    /// The octets of the section of `text`, read as `entity` (RFC 9051 §6.4.5): HEADER the
    /// header with its empty line, HEADER.FIELDS its lines of the fields named (or, NOT, of
    /// the others) and an empty line, TEXT the body of the message, MIME the header of a part,
    /// no text the body of the part (the whole message for no part). `None` for a section
    /// the message does not have.
    pub fn extract(&self, entity: &MIMEEntity, text: &[u8]) -> Option<Vec<u8>> {
        let target = IMAPSection::locate(entity, &self.part)?;
        // HEADER and TEXT of a part name those of the message it encapsulates.
        let message = match self.part.is_empty() {
            true => Some(entity),
            false => target.message.as_deref(),
        };
        match &self.text {
            None if self.part.is_empty() => Some(text.to_vec()),
            None => text.get(target.body.clone()).map(<[u8]>::to_vec),
            Some(IMAPSectionText::MIME) => text.get(target.header.clone()).map(<[u8]>::to_vec),
            Some(IMAPSectionText::Header) => text.get(message?.header.clone()).map(<[u8]>::to_vec),
            Some(IMAPSectionText::Text) => text.get(message?.body.clone()).map(<[u8]>::to_vec),
            Some(IMAPSectionText::HeaderFields { not, fields }) => {
                let header = text.get(message?.header.clone())?;
                Some(IMAPSection::header_fields(header, fields, *not))
            }
        }
    }

    /// The lines of the fields of `header` named in `fields` (or, `not`, of the others), as
    /// they are, and an empty line.
    pub fn header_fields(header: &[u8], fields: &[String], not: bool) -> Vec<u8> {
        let mut selected = Vec::new();
        let mut index = 0;
        while index < header.len() {
            // A field: its first line and the lines that continue it.
            let start = index;
            loop {
                let end = header[index..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(header.len(), |offset| index + offset + 1);
                index = end;
                if !matches!(header.get(index), Some(b' ' | b'\t')) {
                    break;
                }
            }
            let field = &header[start..index];
            let Some(colon) = field.iter().position(|byte| *byte == b':') else { continue };
            let name = core::str::from_utf8(&field[..colon]).unwrap_or_default().trim_end_matches([' ', '\t']);
            let named = fields.iter().any(|wanted| wanted.eq_ignore_ascii_case(name));
            if named != not {
                selected.extend_from_slice(field);
            }
        }
        selected.extend_from_slice(b"\r\n");
        selected
    }
}

impl fmt::Display for IMAPSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut writer = IMAPWriter::new(super::IMAPLiteralMode::Server, true);
        self.write(&mut writer);
        formatter.write_str(&String::from_utf8_lossy(&writer.out))
    }
}
