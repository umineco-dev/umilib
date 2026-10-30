use super::{QUICError, QUICErrorCode};

/// The credit of flow control a peer gave this end, for a stream or the
/// connection (RFC 9000 §4.1): the limit of offsets, the bytes sent
/// against it, and whether the block at it was signalled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICSendCredit {
    /// The peer's largest MAX_DATA or MAX_STREAM_DATA.
    pub limit: u64,
    /// The bytes sent against it.
    pub used: u64,
    /// The limit at which a DATA_BLOCKED or STREAM_DATA_BLOCKED was last
    /// queued, so that one is sent per limit (RFC 9000 §4.1).
    pub blocked_at: Option<u64>,
}

impl QUICSendCredit {
    pub fn new(limit: u64) -> QUICSendCredit {
        QUICSendCredit { limit, used: 0, blocked_at: None }
    }

    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// A new limit from the peer: only an increase counts, as frames may
    /// arrive out of order (RFC 9000 §4.1). Returns whether it grew.
    pub fn raise(&mut self, limit: u64) -> bool {
        if limit > self.limit {
            self.limit = limit;
            true
        } else {
            false
        }
    }

    /// Whether a blocked frame is due: sending is blocked at the limit, and
    /// none was sent for it yet.
    pub fn is_blocked(&self) -> bool {
        self.available() == 0 && self.blocked_at != Some(self.limit)
    }
}

/// The credit this end gives its peer (RFC 9000 §4.1, §4.2): the limit
/// advertised, the data received against it, and what the reader took,
/// from which the limit is raised as a window that slides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICReceiveCredit {
    /// The largest limit advertised.
    pub limit: u64,
    /// The data received: the sum of the highest offsets (RFC 9000 §4.1).
    pub received: u64,
    /// The data the reader took.
    pub consumed: u64,
    /// The window kept open past what the reader took.
    pub window: u64,
}

impl QUICReceiveCredit {
    pub fn new(window: u64) -> QUICReceiveCredit {
        QUICReceiveCredit { limit: window, received: 0, consumed: 0, window }
    }

    /// `length` more bytes received; fails with FLOW_CONTROL_ERROR past the
    /// limit advertised (RFC 9000 §4.1).
    pub fn receive(&mut self, length: u64) -> Result<(), QUICError> {
        let received = self.received.saturating_add(length);
        if received > self.limit {
            return Err(QUICError::transport(QUICErrorCode::FLOW_CONTROL_ERROR, "data past the flow control limit"));
        }
        self.received = received;
        Ok(())
    }

    /// `length` more bytes taken by the reader.
    pub fn consume(&mut self, length: u64) {
        self.consumed = self.consumed.saturating_add(length).min(self.received);
    }

    /// The new limit to advertise, when the reader took half the window
    /// since the last: the window past what it took (RFC 9000 §4.2).
    pub fn update(&mut self) -> Option<u64> {
        let next = self.consumed.saturating_add(self.window);
        if next.saturating_sub(self.limit) >= self.window / 2 && next > self.limit {
            self.limit = next;
            Some(next)
        } else {
            None
        }
    }
}
