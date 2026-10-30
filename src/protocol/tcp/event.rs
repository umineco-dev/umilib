/// Why a connection closed, which the application learns (RFC 9293 MUST-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCPCloseReason {
    /// Both ends sent a FIN and it was acknowledged.
    Normal = 0,
    /// The peer reset the connection.
    Reset = 1,
    /// The peer refused the connection with a reset to its SYN.
    Refused = 2,
    /// Retransmissions or keep-alives went unanswered for R2 (MUST-20).
    Timeout = 3,
    /// The application aborted the connection.
    Aborted = 4,
    /// An ICMP hard error (RFC 9293 §3.9.2.2, SHLD-26).
    Unreachable = 5,
}

/// What happened to a connection, for the application (RFC 9293 §3.9.1.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TCPEvent {
    /// The handshake completed.
    Connected,
    /// Data can be read.
    Readable,
    /// Room was freed in the send buffer.
    Writable,
    /// The urgent pointer arrived or advanced (MUST-32).
    Urgent,
    /// The peer sent a FIN: no more data comes.
    PeerClosed,
    /// R1 retransmissions of a segment went unanswered (SHLD-9), or an ICMP
    /// soft error arrived (MUST-56, SHLD-25). The connection goes on.
    Trouble,
    /// The connection is closed.
    Closed(TCPCloseReason),
}
