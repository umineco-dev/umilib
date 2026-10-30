use alloc::vec::Vec;

use crate::runtime::Instant;

use super::{QUICConnectionID, QUICStreamID};

/// What a sent packet carried that matters once it is acknowledged or lost
/// (RFC 9000 §13.3): the data to release or send again, and the frames
/// whose newest value must reach the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QUICSentFrame {
    /// An ACK frame of this largest packet number: once acknowledged, the
    /// ranges below it need not be acknowledged again (RFC 9000 §13.2.4).
    ACK {
        largest: u64,
    },
    Crypto {
        offset: u64,
        length: usize,
    },
    Stream {
        stream: QUICStreamID,
        offset: u64,
        length: usize,
        fin: bool,
    },
    ResetStream {
        stream: QUICStreamID,
    },
    StopSending {
        stream: QUICStreamID,
    },
    MaxData,
    MaxStreamData {
        stream: QUICStreamID,
    },
    MaxStreams {
        bidirectional: bool,
    },
    DataBlocked,
    StreamDataBlocked {
        stream: QUICStreamID,
    },
    StreamsBlocked {
        bidirectional: bool,
    },
    NewConnectionID {
        sequence: u64,
        id: QUICConnectionID,
    },
    RetireConnectionID {
        sequence: u64,
    },
    NewToken {
        token: Vec<u8>,
    },
    HandshakeDone,
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    Ping,
    /// DATAGRAM frames are never sent again (RFC 9221 §5.2).
    Datagram,
    /// A frame of an extension, not sent again either.
    Extension,
}

/// A packet sent and not yet acknowledged or declared lost (RFC 9002 §2,
/// Appendix A.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QUICSentPacket {
    pub number: u64,
    pub time: Instant,
    /// Its bytes in the datagram: what counts in flight.
    pub size: usize,
    pub ack_eliciting: bool,
    /// Whether it counts in bytes in flight: ack-eliciting, or with PADDING.
    pub in_flight: bool,
    pub frames: Vec<QUICSentFrame>,
}
