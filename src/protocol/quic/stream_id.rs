use super::QUICRole;

/// A stream ID (RFC 9000 §2.1): a 62-bit integer whose least significant
/// bit tells who opened the stream (0 the client, 1 the server) and the next
/// whether it is unidirectional; the rest counts the streams of that kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct QUICStreamID(pub u64);

impl QUICStreamID {
    /// The largest stream ID: 2^62 - 1.
    pub const MAXIMUM: u64 = (1 << 62) - 1;
    /// The most streams of one kind: 2^60 (RFC 9000 §4.6).
    pub const MAXIMUM_COUNT: u64 = 1 << 60;

    /// The `index`th stream (from 0) of its kind that `initiator` opens.
    pub const fn new(initiator: QUICRole, bidirectional: bool, index: u64) -> QUICStreamID {
        let role = match initiator {
            QUICRole::Client => 0,
            QUICRole::Server => 1,
        };
        let direction = if bidirectional { 0 } else { 2 };
        QUICStreamID((index << 2) | direction | role)
    }

    /// Who opened the stream.
    pub const fn initiator(self) -> QUICRole {
        if self.0 & 1 == 0 { QUICRole::Client } else { QUICRole::Server }
    }

    pub const fn is_bidirectional(self) -> bool {
        self.0 & 2 == 0
    }

    /// The stream's position among those of its kind and initiator.
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }
}
