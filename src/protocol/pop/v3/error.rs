use core::fmt;

/// An error of POP3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum POP3Error {
    /// Text not of the grammar of what was read: a command, a response, a capability.
    Syntax { reason: &'static str },
    /// A line longer than the configuration takes (RFC 2449 §4).
    TooLong { length: usize, maximum: usize },
    /// A command the state does not take (RFC 1939 §3), or of an extension the server did not
    /// announce (RFC 2449 §5).
    State { reason: &'static str },
    /// No response within the configured time.
    Timeout,
    /// The connection is closed, or closing.
    Closed,
}

impl fmt::Display for POP3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            POP3Error::Syntax { reason } => write!(formatter, "syntax error: {reason}"),
            POP3Error::TooLong { length, maximum } => {
                write!(formatter, "a line of {length} octets, more than {maximum}")
            }
            POP3Error::State { reason } => write!(formatter, "not in this state: {reason}"),
            POP3Error::Timeout => formatter.write_str("timed out"),
            POP3Error::Closed => formatter.write_str("the connection is closed"),
        }
    }
}

impl core::error::Error for POP3Error {}
