use super::{HTTPError, HTTPFields, HTTPRequest, HTTPResponse, HTTPVersion};

/// An exchange of a connection: HTTP/1.1's in their order from 0, HTTP/2's
/// stream identifiers (RFC 9113 §5.1.1), HTTP/3's QUIC stream identifiers
/// (RFC 9114 §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HTTPStreamID(pub u64);

/// Which end of a connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HTTPRole {
    Client,
    Server,
}

/// Why this end abandons a stream; each version has its code for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HTTPReset {
    /// The exchange is no longer wanted.
    Cancel,
    /// The request was not processed, so it may be retried (RFC 9113 §8.7, RFC 9114 §4.1.1).
    Refused,
    /// An error of this end.
    Internal,
    /// The rest of the request is not needed: a server that answered early (RFC 9113 §8.1).
    NoError,
}

/// What a connection tells its application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HTTPEvent {
    /// A server: the head of a request arrived; `end` if it has no content.
    Request { stream: HTTPStreamID, request: HTTPRequest, end: bool },
    /// A client: the head of a response arrived, interim (1xx) ones before
    /// the final one; `end` if it has no content.
    Response { stream: HTTPStreamID, response: HTTPResponse, end: bool },
    /// Content of `stream` can be read.
    Data { stream: HTTPStreamID },
    /// The trailer section of `stream`, which ends its message.
    Trailers { stream: HTTPStreamID, fields: HTTPFields },
    /// The message of `stream` arrived whole.
    End { stream: HTTPStreamID },
    /// The peer abandoned `stream`, with the version's error code.
    Reset { stream: HTTPStreamID, code: u64 },
    /// More content of `stream` can be written.
    Writable { stream: HTTPStreamID },
    /// The peer takes no new requests; those after `last` were not processed,
    /// and each of them that was under way was reported by a `Reset` before,
    /// with the version's code for a request refused unprocessed (HTTP/2
    /// REFUSED_STREAM, HTTP/3 H3_REQUEST_REJECTED), which may be retried.
    GoAway { last: HTTPStreamID },
    /// The connection ended; `error` says why, if not cleanly.
    Closed { error: Option<HTTPError> },
}

/// A connection of any version of HTTP, as its application sees it: it
/// sends and receives messages on streams, without I/O. How its bytes move
/// is the version's: HTTP/1.1 and HTTP/2 over a byte stream, HTTP/3 over QUIC.
pub trait HTTPConnection {
    fn version(&self) -> HTTPVersion;

    fn role(&self) -> HTTPRole;

    /// A client starts an exchange with `request`, which has no content if `end`.
    fn send_request(&mut self, request: &HTTPRequest, end: bool) -> Result<HTTPStreamID, HTTPError>;

    /// A server answers `stream`: interim (1xx) responses, then the final
    /// one, with no content if `end`.
    fn send_response(&mut self, stream: HTTPStreamID, response: &HTTPResponse, end: bool) -> Result<(), HTTPError>;

    /// Writes content of `stream`, the last of it if `end`; returns how
    /// much was taken, which flow control and buffers may make less than all.
    fn send_data(&mut self, stream: HTTPStreamID, data: &[u8], end: bool) -> Result<usize, HTTPError>;

    /// Ends the message of `stream` with a trailer section.
    fn send_trailers(&mut self, stream: HTTPStreamID, trailers: &HTTPFields) -> Result<(), HTTPError>;

    /// Reads content of `stream` into `out`; returns how much.
    fn read_data(&mut self, stream: HTTPStreamID, out: &mut [u8]) -> Result<usize, HTTPError>;

    /// Abandons `stream`.
    fn reset(&mut self, stream: HTTPStreamID, reason: HTTPReset) -> Result<(), HTTPError>;

    fn poll_event(&mut self) -> Option<HTTPEvent>;

    /// Takes no new exchanges: those under way finish, then the connection closes.
    fn shutdown(&mut self);

    fn is_closed(&self) -> bool;
}
