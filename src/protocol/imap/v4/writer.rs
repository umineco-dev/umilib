use alloc::vec::Vec;

use super::IMAPReader;

/// How the strings a writer cannot quote are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IMAPLiteralMode {
    /// From a server: `{n}`, the data at once (RFC 9051 §4.3).
    Server,
    /// From a client: `{n}`, and the data only after the server's continuation request.
    Synchronizing,
    /// From a client to a server that takes non-synchronizing literals of at most `maximum`
    /// octets (LITERAL-: 4096; LITERAL+: any): `{n+}`, the data at once; a longer one synchronizing.
    NonSynchronizing { maximum: u64 },
}

/// A writer of the productions of RFC 9051 §9. A string is written as an
/// atom where the production takes one and it is one, quoted where it can
/// be, and as a literal otherwise; the points where a client must wait for
/// the server's continuation request are kept in `waits`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPWriter {
    pub out: Vec<u8>,
    pub mode: IMAPLiteralMode,
    /// Whether quoted strings may be of UTF-8 (IMAP4rev2, RFC 9051 §4.3; or UTF8=ACCEPT).
    pub utf8: bool,
    /// The positions of `out` after which a client waits for a continuation request: after
    /// the CRLF of each synchronizing literal's length.
    pub waits: Vec<usize>,
}

impl IMAPWriter {
    /// The longest string written quoted: a longer one is a literal.
    pub const MAXIMUM_QUOTED: usize = 1024;

    pub fn new(mode: IMAPLiteralMode, utf8: bool) -> IMAPWriter {
        IMAPWriter { out: Vec::new(), mode, utf8, waits: Vec::new() }
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut IMAPWriter {
        self.out.extend_from_slice(bytes);
        self
    }

    pub fn sp(&mut self) -> &mut IMAPWriter {
        self.raw(b" ")
    }

    pub fn number(&mut self, value: u64) -> &mut IMAPWriter {
        self.raw(alloc::format!("{value}").as_bytes())
    }

    /// Whether `text` can be written as a quoted string.
    pub fn can_quote(&self, text: &[u8]) -> bool {
        text.len() <= IMAPWriter::MAXIMUM_QUOTED
            && !text.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            && (text.is_ascii() || (self.utf8 && core::str::from_utf8(text).is_ok()))
    }

    pub fn quoted(&mut self, text: &[u8]) -> &mut IMAPWriter {
        self.out.push(b'"');
        for byte in text {
            if matches!(byte, b'"' | b'\\') {
                self.out.push(b'\\');
            }
            self.out.push(*byte);
        }
        self.out.push(b'"');
        self
    }

    /// A literal: `{n}` or `{n+}` as the mode says, CRLF, the data.
    pub fn literal(&mut self, data: &[u8]) -> &mut IMAPWriter {
        let length = data.len() as u64;
        match self.mode {
            IMAPLiteralMode::Server => {
                self.raw(alloc::format!("{{{length}}}\r\n").as_bytes());
            }
            IMAPLiteralMode::NonSynchronizing { maximum } if length <= maximum => {
                self.raw(alloc::format!("{{{length}+}}\r\n").as_bytes());
            }
            _ => {
                self.raw(alloc::format!("{{{length}}}\r\n").as_bytes());
                self.waits.push(self.out.len());
            }
        }
        self.raw(data)
    }

    /// A string: quoted if it can be, a literal otherwise.
    pub fn string(&mut self, text: &[u8]) -> &mut IMAPWriter {
        match self.can_quote(text) {
            true => self.quoted(text),
            false => self.literal(text),
        }
    }

    /// An astring: as it is if it is ASTRING-CHARs, a string otherwise.
    pub fn astring(&mut self, text: &[u8]) -> &mut IMAPWriter {
        match !text.is_empty() && text.iter().all(|byte| IMAPReader::is_astring_char(*byte)) {
            true => self.raw(text),
            false => self.string(text),
        }
    }

    /// An nstring: a string, or NIL.
    pub fn nstring(&mut self, text: Option<&[u8]>) -> &mut IMAPWriter {
        match text {
            Some(text) => self.string(text),
            None => self.raw(b"NIL"),
        }
    }

    /// A parenthesized list of `items`, each written by `item`.
    pub fn list<T>(&mut self, items: &[T], mut item: impl FnMut(&mut IMAPWriter, &T)) -> &mut IMAPWriter {
        self.out.push(b'(');
        for (index, value) in items.iter().enumerate() {
            if index > 0 {
                self.out.push(b' ');
            }
            item(self, value);
        }
        self.out.push(b')');
        self
    }
}
