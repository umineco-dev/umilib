use alloc::vec::Vec;

use super::BytesError;

/// Received octets not yet read, read as lines ended by CRLF (as the
/// line protocols of the Internet end them, e.g. RFC 5321 §2.3.8) or as
/// counted octets. A CR or an LF alone ends no line.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct LineBuffer {
    pub data: Vec<u8>,
    /// Where the unread octets begin.
    pub start: usize,
    /// Whether the rest of a line longer than the limit is being skipped.
    pub skipping: bool,
}

impl LineBuffer {
    pub fn new() -> LineBuffer {
        LineBuffer::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start * 2 >= self.data.len() {
            self.data.drain(..self.start);
            self.start = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    /// The octets not yet read.
    pub fn unread(&self) -> &[u8] {
        &self.data[self.start..]
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn consume(&mut self, count: usize) {
        self.start = (self.start + count).min(self.data.len());
    }

    /// Takes up to `count` octets.
    pub fn take(&mut self, count: usize) -> Vec<u8> {
        let count = count.min(self.len());
        let taken = self.data[self.start..self.start + count].to_vec();
        self.consume(count);
        taken
    }

    /// Discards every octet not yet read.
    pub fn clear(&mut self) {
        self.data.clear();
        self.start = 0;
        self.skipping = false;
    }

    /// The next line, its CRLF removed, if a whole line is here. A line of
    /// more than `maximum` octets, its CRLF counted, fails once with
    /// LineTooLong, and the rest of it is skipped.
    pub fn line(&mut self, maximum: usize) -> Result<Option<Vec<u8>>, BytesError> {
        loop {
            let unread = self.unread();
            let end = unread.windows(2).position(|pair| pair == b"\r\n");
            match end {
                Some(end) if self.skipping => {
                    self.consume(end + 2);
                    self.skipping = false;
                }
                Some(end) if end + 2 > maximum => {
                    self.consume(end + 2);
                    return Err(BytesError::LineTooLong { length: end + 2, maximum });
                }
                Some(end) => {
                    let line = unread[..end].to_vec();
                    self.consume(end + 2);
                    return Ok(Some(line));
                }
                // Keep a final CR, which may begin the CRLF.
                None if self.skipping => {
                    let keep = usize::from(unread.last() == Some(&b'\r'));
                    self.consume(unread.len() - keep);
                    return Ok(None);
                }
                None if unread.len() >= maximum => {
                    let length = unread.len();
                    let keep = usize::from(unread.last() == Some(&b'\r'));
                    self.consume(length - keep);
                    self.skipping = true;
                    return Err(BytesError::LineTooLong { length, maximum });
                }
                None => return Ok(None),
            }
        }
    }
}
