use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::SMTPError;

/// An enhanced status code (RFC 3463 §2, RFC 2034 §4): `class.subject.detail`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SMTPEnhancedStatus {
    /// 2 (success), 4 (persistent transient failure) or 5 (permanent failure).
    pub class: u8,
    pub subject: u16,
    pub detail: u16,
}

impl SMTPEnhancedStatus {
    pub const fn new(class: u8, subject: u16, detail: u16) -> SMTPEnhancedStatus {
        SMTPEnhancedStatus { class, subject, detail }
    }

    /// The status that begins `text` and the text after it and its space:
    /// a class of 2, 4 or 5, a subject and a detail of 1 to 3 digits each.
    pub fn parse(text: &[u8]) -> Option<(SMTPEnhancedStatus, &[u8])> {
        let end = text.iter().position(|byte| *byte == b' ').unwrap_or(text.len());
        let mut parts = text[..end].split(|byte| *byte == b'.');
        let (Some(class), Some(subject), Some(detail), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let number = |digits: &[u8]| {
            let valid = (1..=3).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit);
            valid.then(|| digits.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0')))
        };
        let class = match class {
            [digit @ (b'2' | b'4' | b'5')] => digit - b'0',
            _ => return None,
        };
        let status = SMTPEnhancedStatus { class, subject: number(subject)?, detail: number(detail)? };
        let rest = text.get(end + 1..).unwrap_or_default();
        Some((status, rest))
    }

    /// Whether the status is of the class of a reply code: 2.X.X of 2yz, and so on (RFC 2034 §4).
    pub fn agrees_with(&self, code: u16) -> bool {
        u16::from(self.class) == code / 100
    }
}

impl fmt::Display for SMTPEnhancedStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

/// A reply (RFC 5321 §4.2): a code and lines of text, the text of each
/// line after the code and its separator.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPReply {
    pub code: u16,
    pub lines: Vec<Vec<u8>>,
}

impl SMTPReply {
    /// A reply of one line.
    pub fn new(code: u16, text: &str) -> SMTPReply {
        SMTPReply { code, lines: alloc::vec![text.as_bytes().to_vec()] }
    }

    /// A reply of one line beginning with an enhanced status code (RFC 2034 §4).
    pub fn enhanced(code: u16, status: SMTPEnhancedStatus, text: &str) -> SMTPReply {
        SMTPReply::new(code, &alloc::format!("{status} {text}"))
    }

    /// Whether `code` is a reply code of §4.2: a first digit of 2 to 5, a
    /// second of 0 to 5, a third of 0 to 9.
    pub fn is_code(code: u16) -> bool {
        (200..=599).contains(&code) && (code / 10) % 10 <= 5
    }

    /// The first digit: 2 positive completion, 3 positive intermediate,
    /// 4 transient negative, 5 permanent negative (§4.2.1).
    pub fn severity(&self) -> u16 {
        self.code / 100
    }

    pub fn is_positive(&self) -> bool {
        self.severity() == 2
    }

    pub fn is_intermediate(&self) -> bool {
        self.severity() == 3
    }

    pub fn is_transient(&self) -> bool {
        self.severity() == 4
    }

    pub fn is_permanent(&self) -> bool {
        self.severity() == 5
    }

    /// The enhanced status code of the first line, if it begins with one of
    /// the reply's class (RFC 2034 §4).
    pub fn status(&self) -> Option<SMTPEnhancedStatus> {
        let (status, _) = SMTPEnhancedStatus::parse(self.lines.first()?)?;
        status.agrees_with(self.code).then_some(status)
    }

    /// The text of the lines, joined by line breaks; bytes that are not UTF-8 replaced.
    pub fn text(&self) -> String {
        let lines: Vec<String> = self.lines.iter().map(|line| String::from_utf8_lossy(line).into_owned()).collect();
        lines.join("\n")
    }

    /// Writes the reply: `code-text` lines, the last `code SP text` (§4.2).
    pub fn encode(&self, out: &mut Vec<u8>) {
        let empty: [Vec<u8>; 1] = [Vec::new()];
        let lines: &[Vec<u8>] = if self.lines.is_empty() { &empty } else { &self.lines };
        for (index, line) in lines.iter().enumerate() {
            let separator = if index + 1 == lines.len() { b' ' } else { b'-' };
            out.extend_from_slice(alloc::format!("{:03}", self.code).as_bytes());
            out.push(separator);
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }

    /// Fails for a reply that cannot be written: a code that is not one, a
    /// line with a CR, an LF or a NUL.
    pub fn check(&self) -> Result<(), SMTPError> {
        if !SMTPReply::is_code(self.code) {
            return Err(SMTPError::Syntax { reason: "not a reply code" });
        }
        if self.lines.iter().flatten().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(SMTPError::Syntax { reason: "a line break in the text of a reply" });
        }
        Ok(())
    }
}

/// The lines of a reply read so far (RFC 5321 §4.2): every line but the
/// last has a hyphen after its code, and every line the same code.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SMTPReplyReader {
    pub code: Option<u16>,
    pub lines: Vec<Vec<u8>>,
}

impl SMTPReplyReader {
    pub fn new() -> SMTPReplyReader {
        SMTPReplyReader::default()
    }

    /// Takes a line, its CRLF removed; the reply when it is the last line.
    /// A line of the code alone, or of the code and a space, is taken (§4.2:
    /// clients SHOULD be prepared for it).
    pub fn push(&mut self, line: &[u8], maximum_lines: usize) -> Result<Option<SMTPReply>, SMTPError> {
        let invalid = |reason| Err(SMTPError::Syntax { reason });
        let digits = match line.get(..3) {
            Some(digits) if digits.iter().all(u8::is_ascii_digit) => digits,
            _ => return invalid("a reply line without a code"),
        };
        let code = digits.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
        if !SMTPReply::is_code(code) {
            return invalid("not a reply code");
        }
        if self.code.is_some_and(|first| first != code) {
            return invalid("lines of a reply with different codes");
        }
        let (last, text) = match line.get(3) {
            None => (true, &[][..]),
            Some(b' ') => (true, &line[4..]),
            Some(b'-') => (false, &line[4..]),
            Some(_) => return invalid("a reply code without a space or a hyphen after it"),
        };
        if text.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return invalid("a CR, LF or NUL in a reply line");
        }
        if self.lines.len() == maximum_lines {
            return Err(SMTPError::TooLong { length: self.lines.len() + 1, maximum: maximum_lines });
        }
        self.code = Some(code);
        self.lines.push(text.to_vec());
        if !last {
            return Ok(None);
        }
        let reply = SMTPReply { code, lines: core::mem::take(&mut self.lines) };
        self.code = None;
        Ok(Some(reply))
    }
}
