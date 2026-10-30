/// The content of a message counted against what its head says (RFC 9110
/// §8.6, §6.4.1, RFC 9113 §8.1.1, RFC 9114 §4.1.2): its Content-Length,
/// if any, and whether it may have content at all (`none`: a response to
/// HEAD, or of 204 or 304, whose Content-Length is that of another message).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HTTPContentLength {
    pub length: Option<u64>,
    pub none: bool,
    /// The bytes of content counted so far.
    pub counted: u64,
}

impl HTTPContentLength {
    pub const fn new(length: Option<u64>, none: bool) -> HTTPContentLength {
        HTTPContentLength { length, none, counted: 0 }
    }

    /// Checks `count` more bytes of content, the last ones if `end`.
    pub fn check(&self, count: u64, end: bool) -> Result<(), &'static str> {
        if self.none {
            return if count > 0 { Err("content in a message that has none") } else { Ok(()) };
        }
        let counted = self.counted.saturating_add(count);
        match self.length {
            Some(length) if counted > length => Err("content longer than Content-Length"),
            Some(length) if end && counted != length => Err("content shorter than Content-Length"),
            _ => Ok(()),
        }
    }

    /// Counts `count` more bytes.
    pub fn add(&mut self, count: u64) {
        self.counted = self.counted.saturating_add(count);
    }
}
