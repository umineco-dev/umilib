use core::fmt;

/// An error of HTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HTTPError {
    /// A message that breaks the rules of HTTP (RFC 9110, and of its
    /// version): a field, a target, a method, a status code, framing.
    Malformed(&'static str),
    /// A message larger than this end takes: its fields, its target, its
    /// content (answered with 431, 414 or 413 when this end is the server).
    TooLarge(&'static str),
    /// A content coding not supported, or content that does not decode (RFC 9110 §8.4).
    ContentCoding(&'static str),
    /// A rule of the version's protocol broken, with its error code: a
    /// connection error of HTTP/2 or HTTP/3 (RFC 9113 §5.4.1, RFC 9114 §8).
    Protocol { code: u64, reason: &'static str },
    /// What the call asks for is not possible now: a stream gone, a
    /// connection closing, a message already sent.
    State,
    /// A configuration that cannot work.
    Config,
}

impl fmt::Display for HTTPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HTTPError::Malformed(reason) => write!(formatter, "malformed HTTP message: {reason}"),
            HTTPError::TooLarge(reason) => write!(formatter, "HTTP message too large: {reason}"),
            HTTPError::ContentCoding(reason) => write!(formatter, "content coding: {reason}"),
            HTTPError::Protocol { code, reason } => write!(formatter, "HTTP protocol error {code:#x}: {reason}"),
            HTTPError::State => formatter.write_str("not possible in this state"),
            HTTPError::Config => formatter.write_str("invalid HTTP configuration"),
        }
    }
}

impl core::error::Error for HTTPError {}
