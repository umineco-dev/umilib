use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{IMAPEnvelope, IMAPError, IMAPReader, IMAPWriter};
use crate::codec::mail::{MIMEEntity, MIMEParameters};

/// A parameter of a body (RFC 9051 §9 `body-fld-param`): a name and a value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPBodyParameter {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// The disposition of a body (§9 `body-fld-dsp`): its type and parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPBodyDisposition {
    pub kind: Vec<u8>,
    pub parameters: Vec<IMAPBodyParameter>,
}

/// The fields of a body part of a non-multipart (RFC 9051 §9 `body-fields`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPBodyFields {
    pub kind: Vec<u8>,
    pub subtype: Vec<u8>,
    pub parameters: Vec<IMAPBodyParameter>,
    pub id: Option<Vec<u8>>,
    pub description: Option<Vec<u8>>,
    pub encoding: Vec<u8>,
    pub octets: u32,
}

/// The extension data of a body (§9 `body-ext-1part`, `body-ext-mpart`), of BODYSTRUCTURE only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPBodyExtension {
    /// The MD5 of a non-multipart (`body-fld-md5`); for a multipart, its parameters instead.
    pub md5: Option<Vec<u8>>,
    pub parameters: Vec<IMAPBodyParameter>,
    pub disposition: Option<IMAPBodyDisposition>,
    pub language: Vec<Vec<u8>>,
    pub location: Option<Vec<u8>>,
}

/// The body structure of a message or a part (RFC 9051 §7.5.2 BODY, BODYSTRUCTURE).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPBody {
    /// A part of a type other than MESSAGE/RFC822, MESSAGE/GLOBAL and TEXT.
    Basic {
        fields: IMAPBodyFields,
        extension: Option<IMAPBodyExtension>,
    },
    /// A TEXT part and its size in lines.
    Text {
        fields: IMAPBodyFields,
        lines: u64,
        extension: Option<IMAPBodyExtension>,
    },
    /// An encapsulated message: its envelope, its body, its size in lines.
    Message {
        fields: IMAPBodyFields,
        envelope: Box<IMAPEnvelope>,
        body: Box<IMAPBody>,
        lines: u64,
        extension: Option<IMAPBodyExtension>,
    },
    Multipart {
        parts: Vec<IMAPBody>,
        subtype: Vec<u8>,
        extension: Option<IMAPBodyExtension>,
    },
}

impl IMAPBody {
    /// The structure of `entity`, read from `text` (§7.5.2), with the
    /// extension data if `extensible` (BODYSTRUCTURE) and without it
    /// (BODY). Types are in upper case; a parameter given with a character
    /// set or a language (RFC 2231) is `name*` and `charset'language'`
    /// and its octets percent-encoded; lines are the LFs of the body.
    pub fn from_entity(entity: &MIMEEntity, text: &[u8], extensible: bool) -> IMAPBody {
        let content = &entity.content_type;
        let upper = |text: &str| text.to_ascii_uppercase().into_bytes();
        let extension = |parameters: Option<&MIMEParameters>| {
            extensible.then(|| IMAPBodyExtension {
                md5: parameters.is_none().then(|| IMAPBody::field(entity, "Content-MD5")).flatten(),
                parameters: parameters.map(IMAPBody::parameters).unwrap_or_default(),
                disposition: entity.disposition().map(|disposition| IMAPBodyDisposition {
                    kind: upper(&disposition.kind),
                    parameters: IMAPBody::parameters(&disposition.parameters),
                }),
                language: IMAPBody::field(entity, "Content-Language")
                    .map(|value| {
                        value
                            .split(|byte| *byte == b',')
                            .map(|tag| tag.trim_ascii().to_vec())
                            .filter(|tag| !tag.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                location: IMAPBody::field(entity, "Content-Location"),
            })
        };
        if content.is_multipart() && !entity.parts.is_empty() {
            let parts = entity.parts.iter().map(|part| IMAPBody::from_entity(part, text, extensible)).collect();
            return IMAPBody::Multipart {
                parts,
                subtype: upper(&content.subtype),
                extension: extension(Some(&content.parameters)),
            };
        }
        let body = text.get(entity.body.clone()).unwrap_or_default();
        let fields = IMAPBodyFields {
            kind: upper(&content.kind),
            subtype: upper(&content.subtype),
            parameters: IMAPBody::parameters(&content.parameters),
            id: IMAPBody::field(entity, "Content-ID"),
            description: IMAPBody::field(entity, "Content-Description"),
            encoding: upper(entity.encoding.name()),
            octets: u32::try_from(body.len()).unwrap_or(u32::MAX),
        };
        let lines = body.iter().filter(|byte| **byte == b'\n').count() as u64;
        match (&entity.message, content.kind.as_str()) {
            (Some(message), _) => IMAPBody::Message {
                fields,
                envelope: Box::new(IMAPEnvelope::from_fields(&message.fields)),
                body: Box::new(IMAPBody::from_entity(message, text, extensible)),
                lines,
                extension: extension(None),
            },
            (None, "text") => IMAPBody::Text { fields, lines, extension: extension(None) },
            (None, _) => IMAPBody::Basic { fields, extension: extension(None) },
        }
    }

    /// The unfolded value of a field of the entity, white space at its ends removed.
    pub fn field(entity: &MIMEEntity, name: &str) -> Option<Vec<u8>> {
        entity.fields.field(name).map(|field| field.unfolded().trim_ascii().to_vec())
    }

    /// The pairs of `parameters`, a value of a character set or a language as RFC 2231 writes it.
    pub fn parameters(parameters: &MIMEParameters) -> Vec<IMAPBodyParameter> {
        parameters
            .entries
            .iter()
            .map(|parameter| match (&parameter.charset, &parameter.language) {
                (None, None) => {
                    IMAPBodyParameter { name: parameter.name.clone().into_bytes(), value: parameter.value.clone() }
                }
                (charset, language) => {
                    let mut value =
                        alloc::format!("{}'{}'", charset.as_deref().unwrap_or(""), language.as_deref().unwrap_or(""))
                            .into_bytes();
                    for byte in &parameter.value {
                        match byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(byte) {
                            true => value.push(*byte),
                            false => value.extend_from_slice(alloc::format!("%{byte:02X}").as_bytes()),
                        }
                    }
                    IMAPBodyParameter { name: alloc::format!("{}*", parameter.name).into_bytes(), value }
                }
            })
            .collect()
    }

    /// Reads `body` (§9): of BODY or of BODYSTRUCTURE, its extension data taken if it has any.
    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPBody, IMAPError> {
        reader.expect(b'(', "not a body")?;
        reader.depth += 1;
        if reader.depth > reader.maximum_depth {
            return Err(reader.error("bodies nested too deep"));
        }
        let body = if reader.peek() == Some(b'(') {
            let mut parts = Vec::new();
            while reader.peek() == Some(b'(') {
                parts.push(IMAPBody::read(reader)?);
                // Servers are known to put spaces between parts; the grammar has none.
                if reader.data.get(reader.position + 1) == Some(&b'(') {
                    reader.eat(b' ');
                }
            }
            reader.sp()?;
            let subtype = reader.string()?;
            let extension = match reader.eat(b' ') {
                true => {
                    let parameters = IMAPBody::read_parameters(reader)?;
                    Some(IMAPBody::read_extension(
                        reader,
                        IMAPBodyExtension { parameters, ..IMAPBodyExtension::default() },
                    )?)
                }
                false => None,
            };
            IMAPBody::Multipart { parts, subtype, extension }
        } else {
            let kind = reader.string()?;
            reader.sp()?;
            let subtype = reader.string()?;
            reader.sp()?;
            let parameters = IMAPBody::read_parameters(reader)?;
            reader.sp()?;
            let id = reader.nstring()?;
            reader.sp()?;
            let description = reader.nstring()?;
            reader.sp()?;
            let encoding = reader.string()?;
            reader.sp()?;
            let octets = reader.number()?;
            let fields = IMAPBodyFields { kind, subtype, parameters, id, description, encoding, octets };
            let message = fields.kind.eq_ignore_ascii_case(b"MESSAGE")
                && (fields.subtype.eq_ignore_ascii_case(b"RFC822") || fields.subtype.eq_ignore_ascii_case(b"GLOBAL"));
            let mut body = if message {
                reader.sp()?;
                let envelope = Box::new(IMAPEnvelope::read(reader)?);
                reader.sp()?;
                let inner = Box::new(IMAPBody::read(reader)?);
                reader.sp()?;
                let lines = reader.number64()?;
                IMAPBody::Message { fields, envelope, body: inner, lines, extension: None }
            } else if fields.kind.eq_ignore_ascii_case(b"TEXT") {
                reader.sp()?;
                let lines = reader.number64()?;
                IMAPBody::Text { fields, lines, extension: None }
            } else {
                IMAPBody::Basic { fields, extension: None }
            };
            if reader.eat(b' ') {
                let md5 = reader.nstring()?;
                let extension =
                    IMAPBody::read_extension(reader, IMAPBodyExtension { md5, ..IMAPBodyExtension::default() })?;
                match &mut body {
                    IMAPBody::Basic { extension: slot, .. }
                    | IMAPBody::Text { extension: slot, .. }
                    | IMAPBody::Message { extension: slot, .. } => *slot = Some(extension),
                    IMAPBody::Multipart { .. } => {}
                }
            }
            body
        };
        reader.expect(b')', "a body not closed")?;
        reader.depth -= 1;
        Ok(body)
    }

    /// Reads `body-fld-param`: pairs of strings, or NIL.
    pub fn read_parameters(reader: &mut IMAPReader<'_>) -> Result<Vec<IMAPBodyParameter>, IMAPError> {
        if reader.eat_keyword("NIL") {
            return Ok(Vec::new());
        }
        let strings = reader.list(|reader| reader.string())?;
        if strings.is_empty() || strings.len() % 2 != 0 {
            return Err(reader.error("parameters not in pairs"));
        }
        Ok(strings.chunks(2).map(|pair| IMAPBodyParameter { name: pair[0].clone(), value: pair[1].clone() }).collect())
    }

    /// Reads the disposition, language, location and the extensions after them, each if it is
    /// there; the extensions of future revisions are read and dropped (§9: clients MUST accept them).
    pub fn read_extension(
        reader: &mut IMAPReader<'_>,
        mut extension: IMAPBodyExtension,
    ) -> Result<IMAPBodyExtension, IMAPError> {
        if !reader.eat(b' ') {
            return Ok(extension);
        }
        extension.disposition = match reader.eat_keyword("NIL") {
            true => None,
            false => {
                reader.expect(b'(', "not a disposition")?;
                let kind = reader.string()?;
                reader.sp()?;
                let parameters = IMAPBody::read_parameters(reader)?;
                reader.expect(b')', "a disposition not closed")?;
                Some(IMAPBodyDisposition { kind, parameters })
            }
        };
        if !reader.eat(b' ') {
            return Ok(extension);
        }
        extension.language = match reader.peek() {
            Some(b'(') => reader.list(|reader| reader.string())?,
            _ => reader.nstring()?.into_iter().collect(),
        };
        if !reader.eat(b' ') {
            return Ok(extension);
        }
        extension.location = reader.nstring()?;
        while reader.eat(b' ') {
            IMAPBody::skip_extension(reader)?;
        }
        Ok(extension)
    }

    /// Reads a `body-extension` and drops it.
    pub fn skip_extension(reader: &mut IMAPReader<'_>) -> Result<(), IMAPError> {
        match reader.peek() {
            Some(b'(') => reader.list(IMAPBody::skip_extension).map(|_| ()),
            Some(byte) if byte.is_ascii_digit() => reader.number64().map(|_| ()),
            _ => reader.nstring().map(|_| ()),
        }
    }

    pub fn write_parameters(parameters: &[IMAPBodyParameter], writer: &mut IMAPWriter) {
        if parameters.is_empty() {
            writer.raw(b"NIL");
            return;
        }
        writer.raw(b"(");
        for (index, parameter) in parameters.iter().enumerate() {
            if index > 0 {
                writer.sp();
            }
            writer.string(&parameter.name).sp();
            writer.string(&parameter.value);
        }
        writer.raw(b")");
    }

    /// Writes the extension data after its first field (the MD5, or a multipart's parameters).
    pub fn write_extension(extension: &IMAPBodyExtension, writer: &mut IMAPWriter) {
        writer.sp();
        match &extension.disposition {
            None => writer.raw(b"NIL"),
            Some(disposition) => {
                writer.raw(b"(").string(&disposition.kind).sp();
                IMAPBody::write_parameters(&disposition.parameters, writer);
                writer.raw(b")")
            }
        };
        writer.sp();
        match extension.language.as_slice() {
            [] => writer.raw(b"NIL"),
            [language] => writer.string(language),
            languages => writer.list(languages, |writer, language| {
                writer.string(language);
            }),
        };
        writer.sp();
        writer.nstring(extension.location.as_deref());
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(b"(");
        match self {
            IMAPBody::Multipart { parts, subtype, extension } => {
                for part in parts {
                    part.write(writer);
                }
                writer.sp().string(subtype);
                if let Some(extension) = extension {
                    writer.sp();
                    IMAPBody::write_parameters(&extension.parameters, writer);
                    IMAPBody::write_extension(extension, writer);
                }
            }
            IMAPBody::Basic { fields, extension }
            | IMAPBody::Text { fields, extension, .. }
            | IMAPBody::Message { fields, extension, .. } => {
                writer.string(&fields.kind).sp().string(&fields.subtype).sp();
                IMAPBody::write_parameters(&fields.parameters, writer);
                writer.sp().nstring(fields.id.as_deref()).sp().nstring(fields.description.as_deref()).sp();
                writer.string(&fields.encoding).sp().number(u64::from(fields.octets));
                match self {
                    IMAPBody::Text { lines, .. } => {
                        writer.sp().number(*lines);
                    }
                    IMAPBody::Message { envelope, body, lines, .. } => {
                        writer.sp();
                        envelope.write(writer);
                        writer.sp();
                        body.write(writer);
                        writer.sp().number(*lines);
                    }
                    _ => {}
                }
                if let Some(extension) = extension {
                    writer.sp().nstring(extension.md5.as_deref());
                    IMAPBody::write_extension(extension, writer);
                }
            }
        }
        writer.raw(b")");
    }
}
