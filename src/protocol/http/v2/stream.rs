use alloc::collections::VecDeque;

use crate::protocol::http::{HTTPContentLength, HTTPFields, HTTPMethod, HTTPPriority};

/// The states of a stream this crate keeps (RFC 9113 §5.1): idle streams
/// are not kept, closed ones are forgotten, and reserved ones never exist
/// since push is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H2StreamState {
    Open,
    /// This end sent END_STREAM.
    HalfClosedLocal,
    /// The peer sent END_STREAM.
    HalfClosedRemote,
    Closed,
}

/// A stream of a connection: its state, its windows, the content received
/// for the application and the content it wrote, and what its messages are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H2Stream {
    pub id: u32,
    pub state: H2StreamState,
    /// The bytes this end may send (the peer's window), and the bytes the
    /// peer may send (this end's window) with those read since the last WINDOW_UPDATE.
    pub send_window: i64,
    pub receive_window: i64,
    pub consumed: u32,
    pub received: VecDeque<u8>,
    /// Content written by the application, not yet in DATA frames; whether
    /// the message ends after it, and with which trailers.
    pub outgoing: VecDeque<u8>,
    pub end_pending: bool,
    pub trailers: Option<HTTPFields>,
    /// Whether this end sent its (final) head, and whether the peer's (final) head arrived.
    pub sent_head: bool,
    pub received_head: bool,
    /// The method of the request, which tells whether a response has content (HEAD, CONNECT).
    pub method: HTTPMethod,
    /// The Content-Length of the peer's message, and the content counted so far (RFC 9113 §8.1.1).
    pub content_length: Option<u64>,
    pub content_received: u64,
    /// Whether the peer's message may not have content: a response to HEAD, or 204, 304.
    pub no_content: bool,
    pub priority: HTTPPriority,
    /// Whether the application waits for room to write.
    pub blocked: bool,
    /// This end's content, against its head (RFC 9113 §8.1.1).
    pub sent: HTTPContentLength,
    /// Whether the peer's content is dropped as it arrives: this end
    /// answered whole and needs no more of it (RFC 9113 §8.1).
    pub discard: bool,
}

impl H2Stream {
    pub fn new(id: u32, method: HTTPMethod, send_window: u32, receive_window: u32) -> H2Stream {
        H2Stream {
            id,
            state: H2StreamState::Open,
            send_window: i64::from(send_window),
            receive_window: i64::from(receive_window),
            consumed: 0,
            received: VecDeque::new(),
            outgoing: VecDeque::new(),
            end_pending: false,
            trailers: None,
            sent_head: false,
            received_head: false,
            method,
            content_length: None,
            content_received: 0,
            no_content: false,
            priority: HTTPPriority::default(),
            blocked: false,
            sent: HTTPContentLength::default(),
            discard: false,
        }
    }

    /// Whether this end may still send on the stream.
    pub fn can_send(&self) -> bool {
        matches!(self.state, H2StreamState::Open | H2StreamState::HalfClosedRemote)
    }

    /// Whether the peer may still send on the stream.
    pub fn can_receive(&self) -> bool {
        matches!(self.state, H2StreamState::Open | H2StreamState::HalfClosedLocal)
    }

    /// This end sent END_STREAM.
    pub fn close_local(&mut self) {
        self.state = match self.state {
            H2StreamState::Open => H2StreamState::HalfClosedLocal,
            _ => H2StreamState::Closed,
        };
    }

    /// The peer sent END_STREAM.
    pub fn close_remote(&mut self) {
        self.state = match self.state {
            H2StreamState::Open => H2StreamState::HalfClosedRemote,
            _ => H2StreamState::Closed,
        };
    }

    /// Whether the stream is over and read: it can be forgotten.
    pub fn is_done(&self) -> bool {
        self.state == H2StreamState::Closed && self.received.is_empty() && self.outgoing.is_empty()
    }

    /// Whether DATA or trailers wait to be sent.
    pub fn has_output(&self) -> bool {
        self.sent_head && (!self.outgoing.is_empty() || self.end_pending)
    }
}
