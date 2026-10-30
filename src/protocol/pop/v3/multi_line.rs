use alloc::vec::Vec;

/// Where a [`POP3MultiLineReader`] is in the lines it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum POP3MultiLineState {
    LineStart,
    /// After a period at the start of a line.
    Dot,
    /// After a period and a CR at the start of a line.
    DotCR,
    Text,
    /// After a CR inside a line.
    TextCR,
    /// After the line of a period alone: the response has ended.
    End,
}

/// A reader of the lines of a multi-line response (RFC 1939 §3): it
/// removes the period added to lines beginning with one and finds the
/// line of a period alone that ends them. Only CRLF ends a line; a CR or
/// an LF alone is data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct POP3MultiLineReader {
    pub state: POP3MultiLineState,
}

/// A writer of the lines of a multi-line response, in pieces: every line
/// break, a CR or an LF alone too, is sent as CRLF (RFC 1939 §3: lines end
/// in CRLF), a line beginning with a period gets another, and
/// [`POP3MultiLineWriter::finish`] ends the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct POP3MultiLineWriter {
    pub line_start: bool,
    /// A CR was written last, its LF not yet known.
    pub cr: bool,
}

impl Default for POP3MultiLineReader {
    fn default() -> POP3MultiLineReader {
        POP3MultiLineReader::new()
    }
}

impl POP3MultiLineReader {
    pub fn new() -> POP3MultiLineReader {
        POP3MultiLineReader { state: POP3MultiLineState::LineStart }
    }

    pub fn is_end(&self) -> bool {
        self.state == POP3MultiLineState::End
    }

    /// Reads `input` to the end of the response, appending its data to `out`; the octets read.
    pub fn read(&mut self, input: &[u8], out: &mut Vec<u8>) -> usize {
        for (index, byte) in input.iter().enumerate() {
            self.state = match (self.state, byte) {
                (POP3MultiLineState::End, _) => return index,
                (POP3MultiLineState::LineStart, b'.') => POP3MultiLineState::Dot,
                (POP3MultiLineState::Dot, b'\r') => POP3MultiLineState::DotCR,
                (POP3MultiLineState::DotCR, b'\n') => POP3MultiLineState::End,
                // A period removed from a line of more.
                (POP3MultiLineState::Dot, _) => POP3MultiLineReader::text(*byte, out),
                (POP3MultiLineState::TextCR, b'\n') => {
                    out.extend_from_slice(b"\r\n");
                    POP3MultiLineState::LineStart
                }
                (POP3MultiLineState::DotCR | POP3MultiLineState::TextCR, _) => {
                    out.push(b'\r');
                    POP3MultiLineReader::text(*byte, out)
                }
                (_, _) => POP3MultiLineReader::text(*byte, out),
            };
        }
        input.len()
    }

    /// Reads an octet inside a line.
    pub fn text(byte: u8, out: &mut Vec<u8>) -> POP3MultiLineState {
        if byte == b'\r' {
            return POP3MultiLineState::TextCR;
        }
        out.push(byte);
        POP3MultiLineState::Text
    }
}

impl Default for POP3MultiLineWriter {
    fn default() -> POP3MultiLineWriter {
        POP3MultiLineWriter::new()
    }
}

impl POP3MultiLineWriter {
    /// The line that ends a multi-line response.
    pub const END: &'static [u8] = b".\r\n";

    pub fn new() -> POP3MultiLineWriter {
        POP3MultiLineWriter { line_start: true, cr: false }
    }

    /// Writes `data` to `out`.
    pub fn write(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.reserve(data.len() + data.len() / 32 + 2);
        for byte in data {
            if self.cr {
                self.cr = false;
                out.extend_from_slice(b"\r\n");
                self.line_start = true;
                if *byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.cr = true,
                b'\n' => {
                    out.extend_from_slice(b"\r\n");
                    self.line_start = true;
                }
                _ => {
                    if self.line_start && *byte == b'.' {
                        out.push(b'.');
                    }
                    out.push(*byte);
                    self.line_start = false;
                }
            }
        }
    }

    /// Ends the response: a CRLF if the last line has none, and the line of a period.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.cr || !self.line_start {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(POP3MultiLineWriter::END);
        *self = POP3MultiLineWriter::new();
    }

    /// The octets of `data` as the writer sends them, line breaks as CRLF and a CRLF after a
    /// last line without one, the added periods and the end not counted: the size of a message
    /// LIST should give (RFC 6856 §2.1), the octets RETR delivers.
    pub fn canonical_length(data: &[u8]) -> u64 {
        let unterminated = data.last().is_some_and(|byte| !matches!(byte, b'\r' | b'\n'));
        let mut length = if unterminated { 2 } else { 0 };
        for (index, byte) in data.iter().enumerate() {
            length += match byte {
                b'\r' if data.get(index + 1) == Some(&b'\n') => 1,
                b'\r' => 2,
                b'\n' if index > 0 && data[index - 1] == b'\r' => 1,
                b'\n' => 2,
                _ => 1,
            };
        }
        length
    }
}
