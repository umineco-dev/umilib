/// The state of a connection (RFC 9293 §3.3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCPState {
    #[default]
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

impl TCPState {
    /// Whether the state is past the handshake (RFC 9293 §3.5.2).
    pub const fn is_synchronized(self) -> bool {
        !matches!(self, TCPState::Closed | TCPState::Listen | TCPState::SynSent | TCPState::SynReceived)
    }

    /// Whether data may still be sent: the application has not closed.
    pub const fn can_send(self) -> bool {
        matches!(self, TCPState::SynSent | TCPState::SynReceived | TCPState::Established | TCPState::CloseWait)
    }

    /// Whether data may still arrive: no FIN was received.
    pub const fn can_receive(self) -> bool {
        matches!(self, TCPState::SynReceived | TCPState::Established | TCPState::FinWait1 | TCPState::FinWait2)
    }
}
