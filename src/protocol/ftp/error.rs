use core::fmt;

/// An error of FTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FTPError {
    /// Text not of the grammar of what was read: a command, a reply, an address, a fact.
    Syntax { reason: &'static str },
    /// A line longer than the configuration takes.
    TooLong { length: usize, maximum: usize },
    /// A command the state does not take (RFC 959 §5.4), or of a feature the server did not
    /// list (RFC 2389).
    State { reason: &'static str },
    /// No reply within the configured time.
    Timeout,
    /// The connection is closed, or closing (221, 421).
    Closed,
}

impl fmt::Display for FTPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FTPError::Syntax { reason } => write!(formatter, "syntax error: {reason}"),
            FTPError::TooLong { length, maximum } => {
                write!(formatter, "a line of {length} octets, more than {maximum}")
            }
            FTPError::State { reason } => write!(formatter, "not in this state: {reason}"),
            FTPError::Timeout => formatter.write_str("timed out"),
            FTPError::Closed => formatter.write_str("the connection is closed"),
        }
    }
}

impl core::error::Error for FTPError {}
