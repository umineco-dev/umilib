use alloc::string::String;
use alloc::vec::Vec;

use super::{IMAPBody, IMAPDateTime, IMAPEnvelope, IMAPError, IMAPReader, IMAPResponse, IMAPSection, IMAPWriter};

/// A data item of FETCH (RFC 9051 §6.4.5), and those of IMAP4rev1 (RFC 3501 §6.4.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPFetchAttribute {
    Envelope,
    Flags,
    InternalDate,
    RFC822Size,
    /// BODY: the structure without extension data.
    Body,
    BodyStructure,
    UID,
    /// `BODY[section]<partial>`, or `BODY.PEEK`, which does not set `\Seen`; the partial is an
    /// offset and a count of octets.
    BodySection {
        peek: bool,
        section: IMAPSection,
        partial: Option<(u64, u64)>,
    },
    /// `BINARY[part]<partial>` (RFC 3516): the part decoded from its transfer encoding.
    Binary {
        peek: bool,
        part: Vec<u32>,
        partial: Option<(u64, u64)>,
    },
    BinarySize {
        part: Vec<u32>,
    },
    /// RFC822, RFC822.HEADER and RFC822.TEXT of IMAP4rev1.
    RFC822,
    RFC822Header,
    RFC822Text,
}

/// A data item of a FETCH response (RFC 9051 §7.5.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPFetchItem {
    Flags(Vec<String>),
    Envelope(IMAPEnvelope),
    InternalDate(IMAPDateTime),
    RFC822Size(u64),
    Body(IMAPBody),
    BodyStructure(IMAPBody),
    UID(u32),
    /// The section and, for a partial one, the octet it begins at.
    BodySection {
        section: IMAPSection,
        origin: Option<u64>,
        data: Option<Vec<u8>>,
    },
    Binary {
        part: Vec<u32>,
        origin: Option<u64>,
        data: Option<Vec<u8>>,
    },
    BinarySize {
        part: Vec<u32>,
        size: u64,
    },
    RFC822(Option<Vec<u8>>),
    RFC822Header(Option<Vec<u8>>),
    RFC822Text(Option<Vec<u8>>),
    /// An item of an extension: its name in upper case, and its value as it is written.
    Other {
        name: String,
        value: Vec<u8>,
    },
}

impl IMAPFetchAttribute {
    /// The attributes of the macros ALL, FAST and FULL (§6.4.5).
    pub fn all() -> Vec<IMAPFetchAttribute> {
        alloc::vec![
            IMAPFetchAttribute::Flags,
            IMAPFetchAttribute::InternalDate,
            IMAPFetchAttribute::RFC822Size,
            IMAPFetchAttribute::Envelope
        ]
    }

    pub fn fast() -> Vec<IMAPFetchAttribute> {
        alloc::vec![IMAPFetchAttribute::Flags, IMAPFetchAttribute::InternalDate, IMAPFetchAttribute::RFC822Size]
    }

    pub fn full() -> Vec<IMAPFetchAttribute> {
        let mut attributes = IMAPFetchAttribute::all();
        attributes.push(IMAPFetchAttribute::Body);
        attributes
    }

    /// Whether the attribute marks the message \Seen (§6.4.5): BODY[...], BINARY[...] and RFC822 and RFC822.TEXT.
    pub fn sets_seen(&self) -> bool {
        matches!(
            self,
            IMAPFetchAttribute::BodySection { peek: false, .. }
                | IMAPFetchAttribute::Binary { peek: false, .. }
                | IMAPFetchAttribute::RFC822
                | IMAPFetchAttribute::RFC822Text
        )
    }

    /// Reads `<offset.count>` if it is next.
    pub fn read_partial(reader: &mut IMAPReader<'_>) -> Result<Option<(u64, u64)>, IMAPError> {
        if !reader.eat(b'<') {
            return Ok(None);
        }
        let offset = reader.number64()?;
        reader.expect(b'.', "a partial of no count")?;
        let count = reader.number64()?;
        if count == 0 {
            return Err(reader.error("a partial of no octets"));
        }
        reader.expect(b'>', "a partial not closed")?;
        Ok(Some((offset, count)))
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPFetchAttribute, IMAPError> {
        let start = reader.position;
        let name = reader.take_while(
            |byte| IMAPReader::is_atom_char(byte) && byte != b'[' && byte != b'<',
            "not a fetch attribute",
        )?;
        let name = String::from_utf8_lossy(name).to_ascii_uppercase();
        Ok(match name.as_str() {
            "ENVELOPE" => IMAPFetchAttribute::Envelope,
            "FLAGS" => IMAPFetchAttribute::Flags,
            "INTERNALDATE" => IMAPFetchAttribute::InternalDate,
            "RFC822.SIZE" => IMAPFetchAttribute::RFC822Size,
            "BODYSTRUCTURE" => IMAPFetchAttribute::BodyStructure,
            "UID" => IMAPFetchAttribute::UID,
            "RFC822" => IMAPFetchAttribute::RFC822,
            "RFC822.HEADER" => IMAPFetchAttribute::RFC822Header,
            "RFC822.TEXT" => IMAPFetchAttribute::RFC822Text,
            "BODY" if reader.peek() != Some(b'[') => IMAPFetchAttribute::Body,
            "BODY" | "BODY.PEEK" => {
                let section = IMAPSection::read(reader, false)?;
                let partial = IMAPFetchAttribute::read_partial(reader)?;
                IMAPFetchAttribute::BodySection { peek: name == "BODY.PEEK", section, partial }
            }
            "BINARY" | "BINARY.PEEK" => {
                let part = IMAPSection::read(reader, true)?.part;
                let partial = IMAPFetchAttribute::read_partial(reader)?;
                IMAPFetchAttribute::Binary { peek: name == "BINARY.PEEK", part, partial }
            }
            "BINARY.SIZE" => IMAPFetchAttribute::BinarySize { part: IMAPSection::read(reader, true)?.part },
            _ => return Err(IMAPError::Syntax { position: start, reason: "not a fetch attribute" }),
        })
    }

    /// Reads the attributes of FETCH: a macro, an attribute, or a list of attributes.
    pub fn read_list(reader: &mut IMAPReader<'_>) -> Result<Vec<IMAPFetchAttribute>, IMAPError> {
        if reader.eat_keyword("ALL") {
            return Ok(IMAPFetchAttribute::all());
        }
        if reader.eat_keyword("FAST") {
            return Ok(IMAPFetchAttribute::fast());
        }
        if reader.eat_keyword("FULL") {
            return Ok(IMAPFetchAttribute::full());
        }
        match reader.peek() {
            Some(b'(') => reader.list(IMAPFetchAttribute::read),
            _ => Ok(alloc::vec![IMAPFetchAttribute::read(reader)?]),
        }
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        let part = |writer: &mut IMAPWriter, part: &[u32]| IMAPSection::new(part, None).write(writer);
        let partial = |writer: &mut IMAPWriter, partial: &Option<(u64, u64)>| {
            if let Some((offset, count)) = partial {
                writer.raw(alloc::format!("<{offset}.{count}>").as_bytes());
            }
        };
        match self {
            IMAPFetchAttribute::Envelope => writer.raw(b"ENVELOPE"),
            IMAPFetchAttribute::Flags => writer.raw(b"FLAGS"),
            IMAPFetchAttribute::InternalDate => writer.raw(b"INTERNALDATE"),
            IMAPFetchAttribute::RFC822Size => writer.raw(b"RFC822.SIZE"),
            IMAPFetchAttribute::Body => writer.raw(b"BODY"),
            IMAPFetchAttribute::BodyStructure => writer.raw(b"BODYSTRUCTURE"),
            IMAPFetchAttribute::UID => writer.raw(b"UID"),
            IMAPFetchAttribute::RFC822 => writer.raw(b"RFC822"),
            IMAPFetchAttribute::RFC822Header => writer.raw(b"RFC822.HEADER"),
            IMAPFetchAttribute::RFC822Text => writer.raw(b"RFC822.TEXT"),
            IMAPFetchAttribute::BodySection { peek, section, partial: range } => {
                writer.raw(if *peek { b"BODY.PEEK" } else { b"BODY" });
                section.write(writer);
                partial(writer, range);
                writer
            }
            IMAPFetchAttribute::Binary { peek, part: number, partial: range } => {
                writer.raw(if *peek { b"BINARY.PEEK" } else { b"BINARY" });
                part(writer, number);
                partial(writer, range);
                writer
            }
            IMAPFetchAttribute::BinarySize { part: number } => {
                writer.raw(b"BINARY.SIZE");
                part(writer, number);
                writer
            }
        };
    }
}

impl IMAPFetchItem {
    /// Reads `<origin>` if it is next.
    pub fn read_origin(reader: &mut IMAPReader<'_>) -> Result<Option<u64>, IMAPError> {
        if !reader.eat(b'<') {
            return Ok(None);
        }
        let origin = reader.number64()?;
        reader.expect(b'>', "an origin not closed")?;
        Ok(Some(origin))
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPFetchItem, IMAPError> {
        let start = reader.position;
        let name = reader
            .take_while(|byte| IMAPReader::is_atom_char(byte) && byte != b'[' && byte != b'<', "not a fetch item")?;
        let name = String::from_utf8_lossy(name).to_ascii_uppercase();
        let item = match name.as_str() {
            "FLAGS" => {
                reader.sp()?;
                IMAPFetchItem::Flags(reader.list(|reader| reader.flag(false))?)
            }
            "ENVELOPE" => {
                reader.sp()?;
                IMAPFetchItem::Envelope(IMAPEnvelope::read(reader)?)
            }
            "INTERNALDATE" => {
                reader.sp()?;
                IMAPFetchItem::InternalDate(IMAPDateTime::read(reader)?)
            }
            "RFC822.SIZE" => {
                reader.sp()?;
                IMAPFetchItem::RFC822Size(reader.number64()?)
            }
            "UID" => {
                reader.sp()?;
                IMAPFetchItem::UID(reader.nz_number()?)
            }
            "BODYSTRUCTURE" => {
                reader.sp()?;
                IMAPFetchItem::BodyStructure(IMAPBody::read(reader)?)
            }
            "BODY" if reader.peek() != Some(b'[') => {
                reader.sp()?;
                IMAPFetchItem::Body(IMAPBody::read(reader)?)
            }
            "BODY" => {
                let section = IMAPSection::read(reader, false)?;
                let origin = IMAPFetchItem::read_origin(reader)?;
                reader.sp()?;
                IMAPFetchItem::BodySection { section, origin, data: reader.nstring()? }
            }
            "BINARY" => {
                let part = IMAPSection::read(reader, true)?.part;
                let origin = IMAPFetchItem::read_origin(reader)?;
                reader.sp()?;
                let data = match reader.peek() {
                    Some(b'~') => Some(reader.literal(true)?),
                    _ => reader.nstring()?,
                };
                IMAPFetchItem::Binary { part, origin, data }
            }
            "BINARY.SIZE" => {
                let part = IMAPSection::read(reader, true)?.part;
                reader.sp()?;
                IMAPFetchItem::BinarySize { part, size: reader.number64()? }
            }
            "RFC822" | "RFC822.HEADER" | "RFC822.TEXT" => {
                reader.sp()?;
                let data = reader.nstring()?;
                match name.as_str() {
                    "RFC822" => IMAPFetchItem::RFC822(data),
                    "RFC822.HEADER" => IMAPFetchItem::RFC822Header(data),
                    _ => IMAPFetchItem::RFC822Text(data),
                }
            }
            // RFC 9051 §7: a client MUST be ready for any response; an item of an extension
            // (MODSEQ, X-GM-LABELS) is kept as its value is written.
            _ if !name.is_empty() && reader.peek() == Some(b' ') => {
                reader.sp()?;
                let value = reader.position;
                IMAPResponse::skip_value(reader)?;
                IMAPFetchItem::Other { name, value: reader.data[value..reader.position].to_vec() }
            }
            _ => return Err(IMAPError::Syntax { position: start, reason: "not a fetch item" }),
        };
        Ok(item)
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        let origin = |writer: &mut IMAPWriter, origin: &Option<u64>| {
            if let Some(origin) = origin {
                writer.raw(alloc::format!("<{origin}>").as_bytes());
            }
        };
        match self {
            IMAPFetchItem::Flags(flags) => {
                writer.raw(b"FLAGS ").list(flags, |writer, flag| {
                    writer.raw(flag.as_bytes());
                });
            }
            IMAPFetchItem::Envelope(envelope) => {
                writer.raw(b"ENVELOPE ");
                envelope.write(writer);
            }
            IMAPFetchItem::InternalDate(date) => {
                writer.raw(alloc::format!("INTERNALDATE {date}").as_bytes());
            }
            IMAPFetchItem::RFC822Size(size) => {
                writer.raw(b"RFC822.SIZE ").number(*size);
            }
            IMAPFetchItem::UID(uid) => {
                writer.raw(b"UID ").number(u64::from(*uid));
            }
            IMAPFetchItem::Body(body) => {
                writer.raw(b"BODY ");
                body.write(writer);
            }
            IMAPFetchItem::BodyStructure(body) => {
                writer.raw(b"BODYSTRUCTURE ");
                body.write(writer);
            }
            IMAPFetchItem::BodySection { section, origin: start, data } => {
                writer.raw(b"BODY");
                section.write(writer);
                origin(writer, start);
                writer.sp();
                match data {
                    // Message data is sent as a literal: it may have any octet but NUL.
                    Some(data) => writer.literal(data),
                    None => writer.raw(b"NIL"),
                };
            }
            IMAPFetchItem::Binary { part, origin: start, data } => {
                writer.raw(b"BINARY");
                IMAPSection::new(part, None).write(writer);
                origin(writer, start);
                writer.sp();
                match data {
                    // literal8 (RFC 3516 §4.2) where the data has a NUL.
                    Some(data) if data.contains(&0) => {
                        writer.raw(b"~");
                        writer.literal(data)
                    }
                    Some(data) => writer.literal(data),
                    None => writer.raw(b"NIL"),
                };
            }
            IMAPFetchItem::BinarySize { part, size } => {
                writer.raw(b"BINARY.SIZE");
                IMAPSection::new(part, None).write(writer);
                writer.sp().number(*size);
            }
            IMAPFetchItem::Other { name, value } => {
                writer.raw(name.as_bytes()).sp().raw(value);
            }
            IMAPFetchItem::RFC822(data) | IMAPFetchItem::RFC822Header(data) | IMAPFetchItem::RFC822Text(data) => {
                let name: &[u8] = match self {
                    IMAPFetchItem::RFC822(_) => b"RFC822 ",
                    IMAPFetchItem::RFC822Header(_) => b"RFC822.HEADER ",
                    _ => b"RFC822.TEXT ",
                };
                writer.raw(name);
                match data {
                    Some(data) => writer.literal(data),
                    None => writer.raw(b"NIL"),
                };
            }
        }
    }
}
