use alloc::vec::Vec;

use super::{IMAPConfig, IMAPError};
use crate::bytes::LineBuffer;

/// What an [`IMAPLineReader`] read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IMAPLineEvent {
    /// A whole command or response: its lines and literals, its last CRLF removed.
    Line(Vec<u8>),
    /// A line ended with the length of a literal (RFC 9051 §4.3); its data is read next. A
    /// server answers a synchronizing one with a continuation request, or refuses it.
    Literal { length: u64, synchronizing: bool },
    /// A command whose literal was discarded ([`IMAPLineReader::discard_literal`]) ended.
    Discarded,
}

/// A reader of whole commands and responses: lines ended by CRLF, a line
/// ending in the length of a literal (`{n}`, `{n+}`, `~{n}`) continued by
/// the literal's octets and the line after them (RFC 9051 §4.3, RFC 7888 §3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IMAPLineReader {
    /// The command or response read so far.
    pub current: Vec<u8>,
    /// The octets of the current literal still to read.
    pub literal: u64,
    /// The rest of the command is read and dropped.
    pub discarding: bool,
    /// The rest of a line too long was skipped: whether it announced a literal, and so where
    /// the command ends, is not known.
    pub lost: bool,
}

impl IMAPLineReader {
    pub fn new() -> IMAPLineReader {
        IMAPLineReader::default()
    }

    /// The length of the literal `line` ends with, and whether it is synchronizing.
    pub fn literal_of(line: &[u8]) -> Option<(u64, bool)> {
        let inner = line.strip_suffix(b"}")?;
        let open = inner.iter().rposition(|byte| *byte == b'{')?;
        let (digits, synchronizing) = match inner[open + 1..].strip_suffix(b"+") {
            Some(digits) => (digits, false),
            None => (&inner[open + 1..], true),
        };
        let valid = !digits.is_empty() && digits.len() <= 19 && digits.iter().all(u8::is_ascii_digit);
        let length = valid.then(|| core::str::from_utf8(digits).ok()?.parse::<u64>().ok()).flatten()?;
        Some((length, synchronizing))
    }

    /// Reads from `input` what can be read: a whole command or response, or the announcement of
    /// a literal. A line longer than the configuration takes, or a command or literal larger,
    /// fails with TooLong, and what was read of the command is dropped.
    pub fn next(&mut self, input: &mut LineBuffer, config: &IMAPConfig) -> Result<Option<IMAPLineEvent>, IMAPError> {
        loop {
            if self.literal > 0 {
                let count = usize::try_from(self.literal).unwrap_or(usize::MAX).min(input.len());
                if count == 0 {
                    return Ok(None);
                }
                let data = input.take(count);
                if !self.discarding {
                    self.current.extend_from_slice(&data);
                }
                self.literal -= count as u64;
                continue;
            }
            let line = match input.line(config.maximum_line) {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(None),
                Err(_) => {
                    self.reset();
                    self.lost = true;
                    return Err(IMAPError::TooLong {
                        length: config.maximum_line as u64 + 1,
                        maximum: config.maximum_line as u64,
                    });
                }
            };
            if !self.discarding {
                self.current.extend_from_slice(&line);
            }
            if self.current.len() as u64 > config.maximum_command && !self.discarding {
                // The command is kept for its tag. A literal the line announces is still to come:
                // its octets are read and dropped, never taken as commands (RFC 7888 §4).
                let length = self.current.len() as u64;
                if let Some((literal, _)) = IMAPLineReader::literal_of(&line) {
                    self.current.extend_from_slice(b"\r\n");
                    self.literal = literal;
                }
                return Err(IMAPError::TooLong { length, maximum: config.maximum_command });
            }
            match IMAPLineReader::literal_of(&line) {
                Some((length, synchronizing)) => {
                    if !self.discarding {
                        self.current.extend_from_slice(b"\r\n");
                    }
                    self.literal = length;
                    if length > config.maximum_literal && !self.discarding {
                        return Err(IMAPError::TooLong { length, maximum: config.maximum_literal });
                    }
                    if !self.discarding {
                        return Ok(Some(IMAPLineEvent::Literal { length, synchronizing }));
                    }
                }
                None if self.discarding => {
                    self.reset();
                    return Ok(Some(IMAPLineEvent::Discarded));
                }
                None => return Ok(Some(IMAPLineEvent::Line(core::mem::take(&mut self.current)))),
            }
        }
    }

    /// Abandons the command being read: a synchronizing literal was refused, so the client
    /// sends neither it nor the rest of the command (RFC 9051 §7.5).
    pub fn refuse_literal(&mut self) {
        self.reset();
    }

    /// Reads the literal announced and the rest of the command, keeping none of it: for a
    /// non-synchronizing literal refused, whose octets come all the same (RFC 7888 §4).
    pub fn discard_literal(&mut self) {
        self.current.clear();
        self.discarding = true;
    }

    pub fn reset(&mut self) {
        self.current.clear();
        self.literal = 0;
        self.discarding = false;
        self.lost = false;
    }
}
