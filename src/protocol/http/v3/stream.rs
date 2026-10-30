use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::protocol::http::{HTTPContentLength, HTTPMethod};

/// What a request stream reads next (RFC 9114 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H3Reading {
    /// The header of a frame.
    Frame,
    /// The bytes left of a DATA frame's payload.
    Data(u64),
    /// The bytes left of a frame of an unknown type, skipped.
    Skip(u64),
}

/// A request stream (RFC 9114 §4.1): its frames being read, the content
/// for the application, what this end writes, and what its messages are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H3Stream {
    pub id: u64,
    pub reading: H3Reading,
    /// Bytes of the stream not yet taken as frames.
    pub incoming: Vec<u8>,
    /// A field section that waits for its dynamic table entries (RFC 9204 §2.2.1).
    pub blocked: Option<Vec<u8>>,
    pub received: VecDeque<u8>,
    /// Whether the peer's head arrived, whether its stream ended, and whether
    /// the application was told of the end.
    pub received_head: bool,
    pub received_fin: bool,
    pub ended: bool,
    /// Frames to write on the QUIC stream, and whether its FIN follows them.
    pub outgoing: Vec<u8>,
    pub fin_pending: bool,
    pub sent_head: bool,
    pub sent_end: bool,
    pub method: HTTPMethod,
    pub content_length: Option<u64>,
    pub content_received: u64,
    pub no_content: bool,
    /// Whether a trailer section arrived: nothing more may.
    pub trailers: bool,
    /// Whether the application waits for room to write.
    pub waiting: bool,
    /// This end's content, against its head (RFC 9114 §4.1.2).
    pub sent: HTTPContentLength,
    /// Whether what still arrives is dropped unread: this end answered a
    /// request it did not take (431), or needs no more of it.
    pub discard: bool,
}

impl H3Stream {
    pub fn new(id: u64, method: HTTPMethod) -> H3Stream {
        H3Stream {
            id,
            reading: H3Reading::Frame,
            incoming: Vec::new(),
            blocked: None,
            received: VecDeque::new(),
            received_head: false,
            received_fin: false,
            ended: false,
            outgoing: Vec::new(),
            fin_pending: false,
            sent_head: false,
            sent_end: false,
            method,
            content_length: None,
            content_received: 0,
            no_content: false,
            trailers: false,
            waiting: false,
            sent: HTTPContentLength::new(None, false),
            discard: false,
        }
    }

    /// Whether the exchange is over and read.
    pub fn is_done(&self) -> bool {
        self.sent_end && self.outgoing.is_empty() && !self.fin_pending && self.ended && self.received.is_empty()
    }
}
