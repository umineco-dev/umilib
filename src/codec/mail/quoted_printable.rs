use alloc::vec::Vec;

/// The Quoted-Printable content transfer encoding (RFC 2045 §6.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MIMEQuotedPrintable {
    /// Whether line breaks of the data are encoded (`=0D=0A`) rather than
    /// written as line breaks: for data that is not text (RFC 2045 §6.7 (4)).
    pub binary: bool,
}

impl MIMEQuotedPrintable {
    /// The longest encoded line, its line break not counted (RFC 2045 §6.7 (5)).
    pub const LINE: usize = 76;
    pub const HEXADECIMAL: &'static [u8; 16] = b"0123456789ABCDEF";

    pub fn new(binary: bool) -> MIMEQuotedPrintable {
        MIMEQuotedPrintable { binary }
    }

    /// Writes `data` encoded to `out`: lines of at most 76 characters,
    /// joined by soft line breaks, every line break of text data a CRLF.
    pub fn encode(&self, data: &[u8], out: &mut Vec<u8>) {
        let mut line = 0;
        let mut index = 0;
        while index < data.len() {
            let byte = data[index];
            let line_break = match (byte, data.get(index + 1)) {
                _ if self.binary => 0,
                (b'\r', Some(b'\n')) => 2,
                (b'\n', _) => 1,
                _ => 0,
            };
            if line_break > 0 {
                out.extend_from_slice(b"\r\n");
                line = 0;
                index += line_break;
                continue;
            }
            // White space is literal but before a line break or the end (§6.7 (3)).
            let at_end = match data.get(index + 1) {
                None => true,
                Some(b'\n') => !self.binary,
                Some(b'\r') => !self.binary && data.get(index + 2) == Some(&b'\n'),
                Some(_) => false,
            };
            let literal = match byte {
                b' ' | b'\t' => !at_end,
                33..=60 | 62..=126 => true,
                _ => false,
            };
            let width = if literal { 1 } else { 3 };
            // A soft line break, unless what is left of the line fits with what follows.
            let reserve = if at_end { 0 } else { 1 };
            if line + width + reserve > MIMEQuotedPrintable::LINE {
                out.extend_from_slice(b"=\r\n");
                line = 0;
            }
            if literal {
                out.push(byte);
            } else {
                out.extend_from_slice(&[
                    b'=',
                    MIMEQuotedPrintable::HEXADECIMAL[usize::from(byte >> 4)],
                    MIMEQuotedPrintable::HEXADECIMAL[usize::from(byte & 0xF)],
                ]);
            }
            line += width;
            index += 1;
        }
    }

    /// The data of `text`. Lines end in CRLF or LF; the white space at the
    /// end of a line is removed (§6.7 (3)); a line ending in `=` joins the
    /// next. An `=` not followed by two hexadecimal digits is taken as it is,
    /// as §6.7 note (1) suggests, and the digits are taken in either case
    /// (note (2)). Every hard line break is a CRLF in the data of text; in
    /// that of binary data, line breaks of the text are not data and are
    /// removed.
    pub fn decode(&self, text: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(text.len());
        let mut lines = text.split(|byte| *byte == b'\n').peekable();
        while let Some(line) = lines.next() {
            let last = lines.peek().is_none();
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let mut end = line.len();
            while end > 0 && matches!(line[end - 1], b' ' | b'\t') {
                end -= 1;
            }
            let line = &line[..end];
            let (line, soft) = match line.strip_suffix(b"=") {
                Some(line) => (line, true),
                None => (line, false),
            };
            let mut index = 0;
            while index < line.len() {
                let byte = line[index];
                let value = |offset: usize| line.get(index + offset).and_then(|digit| (*digit as char).to_digit(16));
                match (byte, value(1), value(2)) {
                    (b'=', Some(high), Some(low)) => {
                        data.push((high * 16 + low) as u8);
                        index += 3;
                    }
                    _ => {
                        data.push(byte);
                        index += 1;
                    }
                }
            }
            if !soft && !last && !self.binary {
                data.extend_from_slice(b"\r\n");
            }
        }
        data
    }
}
