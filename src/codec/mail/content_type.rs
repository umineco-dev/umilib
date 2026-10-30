use alloc::string::String;
use core::fmt;

use super::{MIMEParameter, MIMEParameters, MailError, MailReader};

/// A Content-Type (RFC 2045 §5): a media type and subtype, in lower case
/// as they compare without case, and parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEContentType {
    pub kind: String,
    pub subtype: String,
    pub parameters: MIMEParameters,
}

impl MIMEContentType {
    pub fn new(kind: &str, subtype: &str) -> MIMEContentType {
        MIMEContentType {
            kind: kind.to_ascii_lowercase(),
            subtype: subtype.to_ascii_lowercase(),
            parameters: MIMEParameters::new(),
        }
    }

    /// `text/plain; charset=us-ascii`, the type of an entity without one or
    /// with one that cannot be read (RFC 2045 §5.2).
    pub fn default_text() -> MIMEContentType {
        let mut content_type = MIMEContentType::new("text", "plain");
        content_type.parameters.set(MIMEParameter::new("charset", b"us-ascii"));
        content_type
    }

    /// `message/rfc822`, the type of a part of multipart/digest without one (RFC 2046 §5.1.5).
    pub fn default_digest() -> MIMEContentType {
        MIMEContentType::new("message", "rfc822")
    }

    /// The type of a field value: `type/subtype`, then parameters, CFWS
    /// between them (RFC 2045 §5.1).
    pub fn parse(value: &[u8]) -> Result<MIMEContentType, MailError> {
        let mut reader = MailReader::new(value, true);
        let kind = reader.token()?;
        reader.expect(b'/', "a media type without /")?;
        let subtype = reader.token()?;
        let parameters = MIMEParameters::read(&mut reader)?;
        let text_of = |bytes: &[u8]| core::str::from_utf8(bytes).unwrap_or_default().to_ascii_lowercase();
        Ok(MIMEContentType { kind: text_of(kind), subtype: text_of(subtype), parameters })
    }

    /// Whether the type is `kind/subtype`, in any case.
    pub fn is(&self, kind: &str, subtype: &str) -> bool {
        self.kind.eq_ignore_ascii_case(kind) && self.subtype.eq_ignore_ascii_case(subtype)
    }

    pub fn is_multipart(&self) -> bool {
        self.kind == "multipart"
    }

    /// Whether the type is that of an encapsulated message: message/rfc822,
    /// or message/global (RFC 6532 §3.7).
    pub fn is_message(&self) -> bool {
        self.is("message", "rfc822") || self.is("message", "global")
    }

    /// The boundary of a multipart: 1 to 70 characters of RFC 2046 §5.1.1,
    /// the last not a space.
    pub fn boundary(&self) -> Option<&[u8]> {
        let boundary = self.parameters.get("boundary")?.value.as_slice();
        let bchar = |byte: &u8| byte.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(byte);
        let valid = (1..=70).contains(&boundary.len()) && boundary.iter().all(bchar) && !boundary.ends_with(b" ");
        valid.then_some(boundary)
    }

    /// The type as a field value is: `type/subtype; name=value`.
    pub fn format(&self) -> String {
        let mut text = alloc::format!("{}/{}", self.kind, self.subtype);
        self.parameters.encode(&mut text);
        text
    }
}

impl fmt::Display for MIMEContentType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.format())
    }
}
