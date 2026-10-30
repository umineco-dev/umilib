/// The control bits of a segment (RFC 9293 §3.1, RFC 3168 §6.1 for ECE and
/// CWR).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TCPFlags(pub u8);

impl TCPFlags {
    pub const NONE: TCPFlags = TCPFlags(0);
    /// No more data from the sender.
    pub const FIN: TCPFlags = TCPFlags(0x01);
    /// Synchronize sequence numbers.
    pub const SYN: TCPFlags = TCPFlags(0x02);
    /// Reset the connection.
    pub const RST: TCPFlags = TCPFlags(0x04);
    /// Push.
    pub const PSH: TCPFlags = TCPFlags(0x08);
    /// The acknowledgment number is significant.
    pub const ACK: TCPFlags = TCPFlags(0x10);
    /// The urgent pointer is significant.
    pub const URG: TCPFlags = TCPFlags(0x20);
    /// ECN-Echo.
    pub const ECE: TCPFlags = TCPFlags(0x40);
    /// Congestion Window Reduced.
    pub const CWR: TCPFlags = TCPFlags(0x80);

    pub const fn contains(self, other: TCPFlags) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: TCPFlags) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn union(self, other: TCPFlags) -> TCPFlags {
        TCPFlags(self.0 | other.0)
    }

    pub const fn difference(self, other: TCPFlags) -> TCPFlags {
        TCPFlags(self.0 & !other.0)
    }
}
