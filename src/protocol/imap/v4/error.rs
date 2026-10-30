use core::fmt;

/// An error of IMAP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IMAPError {
    /// Text not of the grammar of RFC 9051 §9; at the octet `position` of what was read.
    Syntax { position: usize, reason: &'static str },
    /// A line, a literal or a command longer than the configuration takes.
    TooLong { length: u64, maximum: u64 },
    /// A command the state does not take (RFC 9051 §3), or of a capability the server did not
    /// announce.
    State { reason: &'static str },
    /// No response within the configured time.
    Timeout,
    /// The connection is closed, or closing (BYE, LOGOUT).
    Closed,
}

impl fmt::Display for IMAPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IMAPError::Syntax { position, reason } => write!(formatter, "syntax error at {position}: {reason}"),
            IMAPError::TooLong { length, maximum } => write!(formatter, "{length} octets, more than {maximum}"),
            IMAPError::State { reason } => write!(formatter, "not in this state: {reason}"),
            IMAPError::Timeout => formatter.write_str("timed out"),
            IMAPError::Closed => formatter.write_str("the connection is closed"),
        }
    }
}

impl core::error::Error for IMAPError {}
