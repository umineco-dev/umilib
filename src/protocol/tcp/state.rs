/// The state of a connection (RFC 9293 §3.3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCPState {
    #[default]
    Closed = 0,
    Listen = 1,
    SYNSent = 2,
    SYNReceived = 3,
    Established = 4,
    FINWait1 = 5,
    FINWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastACK = 9,
    TimeWait = 10,
}

impl TCPState {
    /// Whether the state is past the handshake (RFC 9293 §3.5.2).
    pub const fn is_synchronized(self) -> bool {
        !matches!(self, TCPState::Closed | TCPState::Listen | TCPState::SYNSent | TCPState::SYNReceived)
    }

    /// Whether data may still be sent: the application has not closed.
    pub const fn can_send(self) -> bool {
        matches!(self, TCPState::SYNSent | TCPState::SYNReceived | TCPState::Established | TCPState::CloseWait)
    }

    /// Whether data may still arrive: no FIN was received.
    pub const fn can_receive(self) -> bool {
        matches!(self, TCPState::SYNReceived | TCPState::Established | TCPState::FINWait1 | TCPState::FINWait2)
    }
}
