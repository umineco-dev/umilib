use alloc::vec::Vec;

use super::SMTPError;

/// The mail data of DATA (RFC 5321 §4.1.1.4, §4.5.2): lines ending in
/// CRLF, a line beginning with a period sent with one more, and the data
/// ended by a line of a period alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SMTPData;

/// Where an [`SMTPDataReader`] is in the data it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SMTPDataState {
    /// At the start of a line.
    LineStart,
    /// After a period at the start of a line.
    Dot,
    /// After a period and a CR at the start of a line.
    DotCR,
    /// Inside a line.
    Text,
    /// After a CR inside a line.
    TextCR,
    /// After the line of a period alone: the data has ended.
    End,
}

/// A reader of mail data as a server receives it: it removes the period
/// added to lines (§4.5.2), finds the end of the data, and marks what is
/// not of the data SMTP takes. Only CRLF ends a line: a CR or an LF alone
/// (§2.3.8) is no line break and makes the data invalid, so that the end
/// of the data is the same for every reader (the "SMTP smuggling" of
/// `<LF>.<LF>` and `<CR>.<CR>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SMTPDataReader {
    pub state: SMTPDataState,
    /// The octets of the current line, as they were sent, its CRLF counted and an added period not.
    pub line: usize,
    /// The octets of data read, after the added periods are removed.
    pub size: u64,
    /// Whether a CR or an LF alone was read.
    pub bare_line_break: bool,
    /// Whether a line was longer than the limit.
    pub long_line: bool,
    /// The most octets of data delivered; past them the data is read and not delivered.
    pub maximum_size: u64,
    /// The longest line, its CRLF counted.
    pub maximum_line: usize,
}

impl SMTPData {
    /// The line that ends the data.
    pub const END: &'static [u8] = b".\r\n";

    /// Writes `message` as mail data: each line beginning with a period
    /// with one more, a CRLF at the end if it has none, and the line of a
    /// period. Fails for a CR or an LF alone (§2.3.8) and for a line longer
    /// than `maximum_line` octets, its CRLF counted (§4.5.3.1.6).
    pub fn encode(message: &[u8], maximum_line: usize, out: &mut Vec<u8>) -> Result<(), SMTPError> {
        SMTPData::check(message, maximum_line)?;
        out.reserve(message.len() + message.len() / 64 + 5);
        let mut line_start = true;
        for byte in message {
            if line_start && *byte == b'.' {
                out.push(b'.');
            }
            out.push(*byte);
            line_start = *byte == b'\n';
        }
        if !message.is_empty() && !message.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(SMTPData::END);
        Ok(())
    }

    /// Fails for a CR or an LF that is not of a CRLF, and for a line longer
    /// than `maximum_line` octets, its CRLF counted.
    pub fn check(message: &[u8], maximum_line: usize) -> Result<(), SMTPError> {
        let mut line = 0;
        for (index, byte) in message.iter().enumerate() {
            match byte {
                b'\r' if message.get(index + 1) == Some(&b'\n') => {}
                b'\n' if index > 0 && message[index - 1] == b'\r' => line = 0,
                b'\r' | b'\n' => return Err(SMTPError::Content { reason: "a CR or an LF alone" }),
                _ => {
                    line += 1;
                    if line + 2 > maximum_line {
                        return Err(SMTPError::TooLong { length: line + 2, maximum: maximum_line });
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether every octet of `message` is of 7-bit data (RFC 6152 §1: no octet above 127).
    pub fn is_seven_bit(message: &[u8]) -> bool {
        message.is_ascii()
    }
}

impl SMTPDataReader {
    pub fn new(maximum_size: u64, maximum_line: usize) -> SMTPDataReader {
        SMTPDataReader {
            state: SMTPDataState::LineStart,
            line: 0,
            size: 0,
            bare_line_break: false,
            long_line: false,
            maximum_size,
            maximum_line,
        }
    }

    pub fn is_end(&self) -> bool {
        self.state == SMTPDataState::End
    }

    /// Whether the data was too large, a CR or an LF alone, or a line too long.
    pub fn error(&self) -> Option<SMTPError> {
        if self.size > self.maximum_size {
            Some(SMTPError::TooLarge { size: self.size, maximum: self.maximum_size })
        } else if self.bare_line_break {
            Some(SMTPError::Content { reason: "a CR or an LF alone" })
        } else if self.long_line {
            Some(SMTPError::TooLong { length: self.maximum_line + 1, maximum: self.maximum_line })
        } else {
            None
        }
    }

    /// Reads `input` to the end of the data, appending the data to `out`
    /// while it is within the maximum size; the octets read.
    pub fn read(&mut self, input: &[u8], out: &mut Vec<u8>) -> usize {
        for (index, byte) in input.iter().enumerate() {
            if self.state == SMTPDataState::End {
                return index;
            }
            // The period added for transparency is not of the line's length (§4.5.3.1.6).
            if !(self.state == SMTPDataState::LineStart && *byte == b'.') {
                self.line += 1;
            }
            if self.line > self.maximum_line {
                self.long_line = true;
            }
            match (self.state, byte) {
                (SMTPDataState::LineStart, b'.') => self.state = SMTPDataState::Dot,
                (SMTPDataState::Dot, b'\r') => self.state = SMTPDataState::DotCR,
                (SMTPDataState::DotCR, b'\n') => self.state = SMTPDataState::End,
                // A period removed from a line of more (§4.5.2), the line's next octet read as text.
                (SMTPDataState::Dot, _) => self.text(*byte, out),
                (SMTPDataState::DotCR, _) => {
                    self.bare_line_break = true;
                    self.push(b"\r", out);
                    self.text(*byte, out);
                }
                (SMTPDataState::TextCR, b'\n') => {
                    self.push(b"\r\n", out);
                    self.state = SMTPDataState::LineStart;
                    self.line = 0;
                }
                (SMTPDataState::TextCR, _) => {
                    self.bare_line_break = true;
                    self.push(b"\r", out);
                    self.text(*byte, out);
                }
                (_, _) => self.text(*byte, out),
            }
        }
        input.len()
    }

    /// Reads an octet inside a line.
    pub fn text(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            b'\r' => self.state = SMTPDataState::TextCR,
            b'\n' => {
                self.bare_line_break = true;
                self.push(b"\n", out);
                self.state = SMTPDataState::Text;
            }
            _ => {
                self.push(&[byte], out);
                self.state = SMTPDataState::Text;
            }
        }
    }

    /// Appends data to `out`, counting it, while it is within the maximum size.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.size = self.size.saturating_add(data.len() as u64);
        if self.size <= self.maximum_size {
            out.extend_from_slice(data);
        }
    }
}
