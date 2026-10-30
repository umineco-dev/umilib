use alloc::string::String;
use alloc::vec::Vec;

use super::FTPError;

/// A reply (RFC 959 §4.2): a code and its lines of text. Of a multi-line
/// reply, the first line is its text after `ddd-`, the last after `ddd `,
/// and the lines between are as they are.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FTPReply {
    pub code: u16,
    pub lines: Vec<Vec<u8>>,
}

/// The lines of a reply read so far (RFC 959 §4.2): the first line `ddd-`,
/// any lines, and the line of the same code and a space that ends it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FTPReplyReader {
    pub code: Option<u16>,
    pub lines: Vec<Vec<u8>>,
}

/// A feature of the reply to FEAT (RFC 2389 §3.2): a name, in upper case,
/// and its parameters as they are.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FTPFeature {
    pub name: String,
    pub parameters: String,
}

/// The features of a reply to FEAT.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FTPFeatures {
    pub entries: Vec<FTPFeature>,
}

impl FTPReply {
    pub fn new(code: u16, text: &str) -> FTPReply {
        FTPReply { code, lines: alloc::vec![text.as_bytes().to_vec()] }
    }

    /// Whether `code` is a reply code (RFC 959 §4.2.1): a first digit of 1 to 5, a second of 0 to 5.
    pub fn is_code(code: u16) -> bool {
        (100..=599).contains(&code) && (code / 10) % 10 <= 5
    }

    /// The first digit: 1 positive preliminary, 2 positive completion, 3 positive intermediate,
    /// 4 transient negative, 5 permanent negative (§4.2.1).
    pub fn severity(&self) -> u16 {
        self.code / 100
    }

    pub fn is_preliminary(&self) -> bool {
        self.severity() == 1
    }

    pub fn is_positive(&self) -> bool {
        self.severity() == 2
    }

    pub fn is_intermediate(&self) -> bool {
        self.severity() == 3
    }

    pub fn is_negative(&self) -> bool {
        self.severity() >= 4
    }

    /// The text of the lines, joined by line breaks.
    pub fn text(&self) -> String {
        let lines: Vec<String> = self.lines.iter().map(|line| String::from_utf8_lossy(line).into_owned()).collect();
        lines.join("\n")
    }

    /// Writes the reply. A line between the first and the last that begins with three digits is
    /// written after a space (§4.2: the server must pad it).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let code = alloc::format!("{:03}", self.code);
        let count = self.lines.len().max(1);
        for index in 0..count {
            let line = self.lines.get(index).map(Vec::as_slice).unwrap_or_default();
            if index == 0 || index + 1 == count {
                out.extend_from_slice(code.as_bytes());
                out.push(if index + 1 == count { b' ' } else { b'-' });
            } else if line.len() >= 3 && line[..3].iter().all(u8::is_ascii_digit) {
                out.push(b' ');
            }
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }

    pub fn check(&self) -> Result<(), FTPError> {
        if !FTPReply::is_code(self.code) {
            return Err(FTPError::Syntax { reason: "not a reply code" });
        }
        if self.lines.iter().flatten().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(FTPError::Syntax { reason: "a line break in the text of a reply" });
        }
        Ok(())
    }

    /// The pathname of a reply to PWD or MKD (RFC 959 Appendix II): the text between the first
    /// quote and the quote that ends it, a quote in it written twice.
    pub fn pathname(&self) -> Option<String> {
        let line = self.lines.first()?;
        let start = line.iter().position(|byte| *byte == b'"')? + 1;
        let mut name = Vec::new();
        let mut index = start;
        loop {
            match (line.get(index), line.get(index + 1)) {
                (Some(b'"'), Some(b'"')) => {
                    name.push(b'"');
                    index += 2;
                }
                (Some(b'"'), _) => break,
                (Some(byte), _) => {
                    name.push(*byte);
                    index += 1;
                }
                (None, _) => return None,
            }
        }
        String::from_utf8(name).ok()
    }

    /// The reply to PWD or MKD of `pathname` (RFC 959 Appendix II): `257 "name" text`.
    pub fn with_pathname(pathname: &str, text: &str) -> FTPReply {
        FTPReply::new(257, &alloc::format!("\"{}\" {text}", pathname.replace('"', "\"\"")))
    }
}

impl FTPReplyReader {
    pub fn new() -> FTPReplyReader {
        FTPReplyReader::default()
    }

    /// Takes a line, its CRLF removed; the reply when it is the last.
    pub fn push(&mut self, line: &[u8], maximum_lines: usize) -> Result<Option<FTPReply>, FTPError> {
        if line.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(FTPError::Syntax { reason: "a CR, LF or NUL in a reply line" });
        }
        let coded = line.get(..3).filter(|digits| digits.iter().all(u8::is_ascii_digit));
        let code = coded.map(|digits| digits.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0')));
        if let Some(first) = self.code {
            if self.lines.len() == maximum_lines {
                return Err(FTPError::TooLong { length: self.lines.len() + 1, maximum: maximum_lines });
            }
            let last = code == Some(first) && matches!(line.get(3), None | Some(b' '));
            if !last {
                self.lines.push(line.to_vec());
                return Ok(None);
            }
            self.lines.push(line.get(4..).unwrap_or_default().to_vec());
            self.code = None;
            return Ok(Some(FTPReply { code: first, lines: core::mem::take(&mut self.lines) }));
        }
        let code = code
            .filter(|code| FTPReply::is_code(*code))
            .ok_or(FTPError::Syntax { reason: "a reply line without a code" })?;
        match line.get(3) {
            None | Some(b' ') => {
                Ok(Some(FTPReply { code, lines: alloc::vec![line.get(4..).unwrap_or_default().to_vec()] }))
            }
            Some(b'-') => {
                self.code = Some(code);
                self.lines.push(line[4..].to_vec());
                Ok(None)
            }
            Some(_) => Err(FTPError::Syntax { reason: "a reply code without a space or a hyphen after it" }),
        }
    }
}

impl FTPFeature {
    pub fn new(name: &str, parameters: &str) -> FTPFeature {
        FTPFeature { name: name.to_ascii_uppercase(), parameters: String::from(parameters) }
    }

    /// The line of the feature, its leading space included (RFC 2389 §3.2).
    pub fn line(&self) -> Vec<u8> {
        let mut line = alloc::format!(" {}", self.name);
        if !self.parameters.is_empty() {
            line.push(' ');
            line.push_str(&self.parameters);
        }
        line.into_bytes()
    }
}

impl FTPFeatures {
    /// The features of a positive reply to FEAT (§3.2): its lines between the first and the last
    /// that begin with a space.
    pub fn from_reply(reply: &FTPReply) -> Result<FTPFeatures, FTPError> {
        if reply.code != 211 {
            return Err(FTPError::State { reason: "not a positive reply to FEAT" });
        }
        let lines = reply.lines.len();
        let entries = reply
            .lines
            .iter()
            .enumerate()
            .filter(|(index, _)| *index > 0 && *index + 1 < lines)
            .filter_map(|(_, line)| {
                let text = core::str::from_utf8(line.strip_prefix(b" ")?).ok()?;
                let (name, parameters) = text.split_once(' ').unwrap_or((text, ""));
                (!name.is_empty()).then(|| FTPFeature::new(name, parameters))
            })
            .collect();
        Ok(FTPFeatures { entries })
    }

    pub fn get(&self, name: &str) -> Option<&FTPFeature> {
        self.entries.iter().find(|feature| feature.name.eq_ignore_ascii_case(name))
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether AUTH is listed with `mechanism` among its parameters (RFC 4217 §6).
    pub fn has_auth(&self, mechanism: &str) -> bool {
        self.get("AUTH").is_some_and(|feature| {
            feature.parameters.split([' ', ';']).any(|name| name.eq_ignore_ascii_case(mechanism))
        })
    }

    /// The reply to FEAT of these features: 211, its lines, 211 End.
    pub fn reply(&self) -> FTPReply {
        let mut lines = alloc::vec![b"Extensions supported:".to_vec()];
        lines.extend(self.entries.iter().map(FTPFeature::line));
        lines.push(b"End".to_vec());
        FTPReply { code: 211, lines }
    }
}
