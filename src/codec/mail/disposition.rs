use alloc::string::String;
use core::fmt;

use super::{MIMEParameters, MailError, MailReader};

/// A Content-Disposition (RFC 2183): `inline`, `attachment` or another
/// type, in lower case, and parameters (`filename`, the dates, `size`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MIMEDisposition {
    pub kind: String,
    pub parameters: MIMEParameters,
}

impl MIMEDisposition {
    pub fn new(kind: &str) -> MIMEDisposition {
        MIMEDisposition { kind: kind.to_ascii_lowercase(), parameters: MIMEParameters::new() }
    }

    /// The disposition of a field value (RFC 2183 §2).
    pub fn parse(value: &[u8]) -> Result<MIMEDisposition, MailError> {
        let mut reader = MailReader::new(value, true);
        let kind = reader.token()?;
        let parameters = MIMEParameters::read(&mut reader)?;
        Ok(MIMEDisposition { kind: core::str::from_utf8(kind).unwrap_or_default().to_ascii_lowercase(), parameters })
    }

    /// Whether the part is to be shown with the message (RFC 2183 §2.1);
    /// an unknown type is taken as `attachment` (§2.8).
    pub fn is_inline(&self) -> bool {
        self.kind == "inline"
    }

    /// The suggested file name: its last path component only, as RFC 2183
    /// §2.3 requires of a receiver (a name of a path, `..` or `.`, is none).
    pub fn filename(&self) -> Option<String> {
        let name = self.parameters.get("filename")?.text().ok()?;
        let name = name.rsplit(['/', '\\']).next().unwrap_or_default();
        let control = name.chars().any(char::is_control);
        (!name.is_empty() && name != "." && name != ".." && !control).then(|| String::from(name))
    }

    /// The disposition as a field value is.
    pub fn format(&self) -> String {
        let mut text = self.kind.clone();
        self.parameters.encode(&mut text);
        text
    }
}

impl fmt::Display for MIMEDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.format())
    }
}
