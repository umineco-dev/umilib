use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Range;

use super::{MIMEContentType, MIMEDisposition, MIMETransferEncoding, MailConfig, MailError, MailFields};

/// A MIME entity (RFC 2045 §2.4) read from a message: its fields, its
/// type and encoding, and where its header section and body are in the
/// text read, so that its parts can be given as they are (IMAP's
/// `BODY[section]`, RFC 9051 §6.4.5). A multipart has its parts (RFC 2046
/// §5.1), an encapsulated message its message (§5.2.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEEntity {
    /// The header section, with the empty line that ends it if there is one.
    pub header: Range<usize>,
    pub body: Range<usize>,
    pub fields: MailFields,
    /// The type of the Content-Type field, or the default if it has none or
    /// one that cannot be read (RFC 2045 §5.2, RFC 2046 §5.1.5).
    pub content_type: MIMEContentType,
    /// The encoding of the Content-Transfer-Encoding field; 7bit if it has
    /// none (RFC 2045 §6.1), another one if it cannot be read.
    pub encoding: MIMETransferEncoding,
    pub parts: Vec<MIMEEntity>,
    pub message: Option<Box<MIMEEntity>>,
}

/// The parts of the body of a multipart (RFC 2046 §5.1.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MIMEMultipart {
    pub preamble: Range<usize>,
    /// Each part: from after the line break of its delimiter to before the
    /// line break of the next, which belongs to the delimiter.
    pub parts: Vec<Range<usize>>,
    /// After the close delimiter; empty if there is none.
    pub epilogue: Range<usize>,
    /// Whether the close delimiter was found; the last part runs to the end of the body if not.
    pub closed: bool,
}

impl MIMEEntity {
    /// The entity of the message `text`, its parts and the messages in it.
    pub fn decode(text: &[u8], config: &MailConfig) -> Result<MIMEEntity, MailError> {
        if text.len() > config.maximum_length {
            return Err(MailError::TooLong { length: text.len(), maximum: config.maximum_length });
        }
        let mut count = 0;
        MIMEEntity::read(text, 0..text.len(), false, 0, config, &mut count)
    }

    /// Reads the entity of `text[range]`, of a multipart/digest if `digest`,
    /// at nesting `depth`; `count` is of the entities read so far. A header
    /// section that cannot be read is taken as none: the whole entity is
    /// its body, so that a part out of the grammar is still a part.
    pub fn read(
        text: &[u8],
        range: Range<usize>,
        digest: bool,
        depth: usize,
        config: &MailConfig,
        count: &mut usize,
    ) -> Result<MIMEEntity, MailError> {
        *count += 1;
        if *count > config.maximum_parts {
            return Err(MailError::TooMany { maximum: config.maximum_parts });
        }
        let (fields, offset) = match MailFields::decode(&text[range.clone()], config) {
            Ok(decoded) => decoded,
            Err(MailError::Syntax { .. }) => (MailFields::new(), 0),
            Err(error) => return Err(error),
        };
        let header = range.start..range.start + offset;
        let body = range.start + offset..range.end;
        let content_type = match fields.get("Content-Type") {
            Some(value) => MIMEContentType::parse(value).unwrap_or_else(|_| MIMEContentType::default_text()),
            None if digest => MIMEContentType::default_digest(),
            None => MIMEContentType::default_text(),
        };
        let encoding = match fields.get("Content-Transfer-Encoding") {
            Some(value) => MIMETransferEncoding::parse(value).unwrap_or_else(|_| {
                MIMETransferEncoding::Other(alloc::string::String::from_utf8_lossy(value).into_owned())
            }),
            None => MIMETransferEncoding::SevenBit,
        };
        let mut entity =
            MIMEEntity { header, body: body.clone(), fields, content_type, encoding, parts: Vec::new(), message: None };
        // Only an identity encoding is taken for a multipart or a message (RFC 2045 §6.4, RFC 2046 §5.2.1).
        let nested =
            entity.encoding.is_identity() && (entity.content_type.is_multipart() || entity.content_type.is_message());
        if nested && depth + 1 > config.maximum_depth {
            return Err(MailError::TooMany { maximum: config.maximum_depth });
        }
        if nested && entity.content_type.is_multipart() {
            if let Some(boundary) = entity.content_type.boundary() {
                let digest = entity.content_type.subtype == "digest";
                let multipart = MIMEMultipart::split(text, body, boundary);
                for part in multipart.parts {
                    entity.parts.push(MIMEEntity::read(text, part, digest, depth + 1, config, count)?);
                }
            }
        } else if nested {
            entity.message = Some(Box::new(MIMEEntity::read(text, body, false, depth + 1, config, count)?));
        }
        Ok(entity)
    }

    /// The data of the body: the body decoded from its transfer encoding.
    pub fn data(&self, text: &[u8]) -> Result<Vec<u8>, MailError> {
        self.encoding.decode(&text[self.body.clone()])
    }

    /// The disposition of the Content-Disposition field, if it has one that can be read.
    pub fn disposition(&self) -> Option<MIMEDisposition> {
        self.fields.get("Content-Disposition").and_then(|value| MIMEDisposition::parse(value).ok())
    }
}

impl MIMEMultipart {
    /// The parts of `text[body]` delimited by `boundary`: a line that begins
    /// with `--` and the boundary (a delimiter), with `--` after it the close
    /// delimiter; the line break before either belongs to it (RFC 2046
    /// §5.1.1). Lines end in CRLF, or LF alone.
    pub fn split(text: &[u8], body: Range<usize>, boundary: &[u8]) -> MIMEMultipart {
        let mut multipart = MIMEMultipart { preamble: body.start..body.start, ..MIMEMultipart::default() };
        let mut open: Option<usize> = None;
        let mut line = body.start;
        while line < body.end {
            let next = text[line..body.end]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(body.end, |offset| line + offset + 1);
            if let Some(close) = MIMEMultipart::delimiter(&text[line..next], boundary) {
                let mut end = line;
                if end > body.start && text[end - 1] == b'\n' {
                    end -= 1;
                    if end > body.start && text[end - 1] == b'\r' {
                        end -= 1;
                    }
                }
                match open {
                    Some(start) => multipart.parts.push(start..end.max(start)),
                    None => multipart.preamble = body.start..end,
                }
                if close {
                    multipart.closed = true;
                    multipart.epilogue = next..body.end;
                    return multipart;
                }
                open = Some(next);
            }
            line = next;
        }
        if let Some(start) = open {
            multipart.parts.push(start..body.end);
        }
        multipart
    }

    /// Whether `line` is a delimiter of `boundary`: `Some(true)` the close delimiter. A line is
    /// one when it begins with `--` and the boundary, whatever follows (RFC 2046 §5.1.1: the
    /// delimiter MUST NOT appear in a part "as the prefix of any line", and it is sufficient
    /// that the boundary appear in its entirety after the CRLF). Taking only a line of the
    /// boundary and white space would read `--bX` inside a part where other readers see a
    /// delimiter, the difference a filter is bypassed by.
    pub fn delimiter(line: &[u8], boundary: &[u8]) -> Option<bool> {
        let rest = line.strip_prefix(b"--")?.strip_prefix(boundary)?;
        Some(rest.starts_with(b"--"))
    }

    /// Writes a multipart body: each part (an entity, its header section
    /// and body) after a delimiter of `boundary`, then the close delimiter.
    /// Fails if a part has a line that begins with a delimiter of the
    /// boundary (RFC 2046 §5.1.1: the boundary must not occur in the parts).
    pub fn encode(boundary: &[u8], parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), MailError> {
        for part in parts {
            if part
                .split_inclusive(|byte| *byte == b'\n')
                .any(|line| MIMEMultipart::delimiter(line, boundary).is_some())
            {
                return Err(MailError::Syntax { position: 0, reason: "a boundary in a part" });
            }
            out.extend_from_slice(b"--");
            out.extend_from_slice(boundary);
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(part);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary);
        out.extend_from_slice(b"--\r\n");
        Ok(())
    }
}
