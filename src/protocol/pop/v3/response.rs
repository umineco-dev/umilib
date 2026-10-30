use alloc::string::String;
use alloc::vec::Vec;

use super::POP3Error;

/// A status line (RFC 1939 §3, RFC 2449 §3): `+OK` or `-ERR`, a response
/// code if it has one (`[LEVEL/LEVEL]`, RFC 2449 §8), and text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct POP3Response {
    pub ok: bool,
    /// The levels of the response code, as they are written.
    pub code: Vec<String>,
    pub text: Vec<u8>,
}

/// A capability of the CAPA list (RFC 2449 §5): a tag, in upper case as
/// tags compare without case, and parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct POP3Capability {
    pub tag: String,
    pub parameters: Vec<String>,
}

/// The capabilities a server announced.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct POP3Capabilities {
    pub entries: Vec<POP3Capability>,
}

impl POP3Response {
    pub fn ok(text: &str) -> POP3Response {
        POP3Response { ok: true, code: Vec::new(), text: text.as_bytes().to_vec() }
    }

    pub fn error(text: &str) -> POP3Response {
        POP3Response { ok: false, code: Vec::new(), text: text.as_bytes().to_vec() }
    }

    /// A negative response with the code of `levels` (RFC 2449 §8): `["IN-USE"]`, `["SYS", "TEMP"]`.
    pub fn error_with(levels: &[&str], text: &str) -> POP3Response {
        POP3Response {
            ok: false,
            code: levels.iter().map(|level| String::from(*level)).collect(),
            text: text.as_bytes().to_vec(),
        }
    }

    /// Whether `level` is a resp-level: characters of rchar, printable US-ASCII but `/` and `]`.
    pub fn is_level(level: &str) -> bool {
        !level.is_empty() && level.bytes().all(|byte| (0x21..=0x7f).contains(&byte) && byte != b'/' && byte != b']')
    }

    /// The response of a status line, its CRLF removed. `+OK` and `-ERR`
    /// are upper case (RFC 1939 §3: servers MUST send them so). A code is
    /// taken where it begins the text.
    pub fn parse(line: &[u8]) -> Result<POP3Response, POP3Error> {
        let (ok, rest) = if let Some(rest) = line.strip_prefix(b"+OK") {
            (true, rest)
        } else if let Some(rest) = line.strip_prefix(b"-ERR") {
            (false, rest)
        } else {
            return Err(POP3Error::Syntax { reason: "a response of no status" });
        };
        let text = match rest {
            [] => &[][..],
            [b' ', text @ ..] => text,
            _ => return Err(POP3Error::Syntax { reason: "no space after the status" }),
        };
        if text.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(POP3Error::Syntax { reason: "a CR, LF or NUL in a response" });
        }
        let mut code = Vec::new();
        let mut text = text;
        if text.first() == Some(&b'[')
            && let Some(end) = text.iter().position(|byte| *byte == b']')
            && let Ok(inner) = core::str::from_utf8(&text[1..end])
            && inner.split('/').all(POP3Response::is_level)
        {
            code = inner.split('/').map(String::from).collect();
            text = &text[end + 1..];
            text = text.strip_prefix(b" ").unwrap_or(text);
        }
        Ok(POP3Response { ok, code, text: text.to_vec() })
    }

    /// The timestamp of a greeting for APOP (RFC 1939 §7): the text from `<` to `>`, of an msg-id.
    pub fn timestamp(&self) -> Option<&[u8]> {
        let start = self.text.iter().position(|byte| *byte == b'<')?;
        let end = start + self.text[start..].iter().position(|byte| *byte == b'>')?;
        let timestamp = &self.text[start..=end];
        timestamp[1..timestamp.len() - 1].contains(&b'@').then_some(timestamp)
    }

    /// Whether the code is `levels`, compared without case.
    pub fn has_code(&self, levels: &[&str]) -> bool {
        self.code.len() == levels.len()
            && self.code.iter().zip(levels).all(|(level, expected)| level.eq_ignore_ascii_case(expected))
    }

    /// Writes the status line.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(if self.ok { b"+OK" } else { b"-ERR" });
        if !self.code.is_empty() || !self.text.is_empty() {
            out.push(b' ');
        }
        if !self.code.is_empty() {
            out.push(b'[');
            out.extend_from_slice(self.code.join("/").as_bytes());
            out.push(b']');
            if !self.text.is_empty() {
                out.push(b' ');
            }
        }
        out.extend_from_slice(&self.text);
        out.extend_from_slice(b"\r\n");
    }

    /// Fails for a response that cannot be written: a level that is not
    /// one, a line break or a NUL in the text.
    pub fn check(&self) -> Result<(), POP3Error> {
        if !self.code.iter().all(|level| POP3Response::is_level(level)) {
            return Err(POP3Error::Syntax { reason: "not a response code" });
        }
        if self.text.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(POP3Error::Syntax { reason: "a line break in a response" });
        }
        Ok(())
    }
}

impl POP3Capability {
    pub fn new(tag: &str, parameters: &[&str]) -> POP3Capability {
        POP3Capability {
            tag: tag.to_ascii_uppercase(),
            parameters: parameters.iter().map(|parameter| String::from(*parameter)).collect(),
        }
    }

    /// The capability of a line: a tag of cchar and parameters; `None` for a line that is not one.
    pub fn parse(line: &[u8]) -> Option<POP3Capability> {
        let text = core::str::from_utf8(line).ok()?;
        let mut words = text.split(' ');
        let tag = words.next()?;
        let tag_valid = !tag.is_empty() && tag.bytes().all(|byte| (0x21..=0x7f).contains(&byte) && byte != b'.');
        let parameters: Vec<String> = words.map(String::from).collect();
        let valid = parameters
            .iter()
            .all(|parameter| !parameter.is_empty() && parameter.bytes().all(|byte| byte.is_ascii_graphic()));
        (tag_valid && valid).then(|| POP3Capability { tag: tag.to_ascii_uppercase(), parameters })
    }

    pub fn line(&self) -> Vec<u8> {
        let mut line = self.tag.clone();
        for parameter in &self.parameters {
            line.push(' ');
            line.push_str(parameter);
        }
        line.into_bytes()
    }
}

impl POP3Capabilities {
    /// The capabilities of the lines of a CAPA list, its periods removed;
    /// lines that are not capabilities are ignored.
    pub fn parse(list: &[u8]) -> POP3Capabilities {
        let entries = list
            .split(|byte| *byte == b'\n')
            .filter_map(|line| POP3Capability::parse(line.strip_suffix(b"\r").unwrap_or(line)))
            .collect();
        POP3Capabilities { entries }
    }

    pub fn get(&self, tag: &str) -> Option<&POP3Capability> {
        self.entries.iter().find(|capability| capability.tag.eq_ignore_ascii_case(tag))
    }

    pub fn has(&self, tag: &str) -> bool {
        self.get(tag).is_some()
    }

    /// The mechanisms of SASL (RFC 2449 §6.3).
    pub fn sasl_mechanisms(&self) -> Vec<&str> {
        self.get("SASL")
            .map(|capability| capability.parameters.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The lines of the list, each with its CRLF, without the period that ends it.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for capability in &self.entries {
            out.extend_from_slice(&capability.line());
            out.extend_from_slice(b"\r\n");
        }
    }
}
