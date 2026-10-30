use core::fmt;

/// An error of SMTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SMTPError {
    /// Text not of the grammar of what was read: a command, a reply, a path, a parameter.
    Syntax { reason: &'static str },
    /// A line longer than the configuration takes (RFC 5321 §4.5.3.1).
    TooLong { length: usize, maximum: usize },
    /// A message larger than the configuration, or than the server's SIZE, takes (RFC 1870).
    TooLarge { size: u64, maximum: u64 },
    /// A command the state does not take: out of sequence (RFC 5321 §4.1.4), or of an
    /// extension the other end did not advertise.
    State { reason: &'static str },
    /// A message that is not of its body type: a CR or LF alone, a line longer than 1000
    /// octets, or 8-bit data where 7-bit is declared (RFC 5321 §2.3.8, §4.5.3.1.6, RFC 6152).
    Content { reason: &'static str },
    /// No reply within the time of RFC 5321 §4.5.3.2.
    Timeout,
    /// The connection is closed, or closing (a 421 reply, QUIT).
    Closed,
    /// The domain takes no mail: its null MX (RFC 7505), or no host left to try (RFC 5321 §5.1).
    NoMail,
}

impl fmt::Display for SMTPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SMTPError::Syntax { reason } => write!(formatter, "syntax error: {reason}"),
            SMTPError::TooLong { length, maximum } => {
                write!(formatter, "a line of {length} octets, more than {maximum}")
            }
            SMTPError::TooLarge { size, maximum } => {
                write!(formatter, "a message of {size} octets, more than {maximum}")
            }
            SMTPError::State { reason } => write!(formatter, "not in this state: {reason}"),
            SMTPError::Content { reason } => write!(formatter, "message content: {reason}"),
            SMTPError::Timeout => formatter.write_str("timed out"),
            SMTPError::Closed => formatter.write_str("the connection is closed"),
            SMTPError::NoMail => formatter.write_str("the domain takes no mail"),
        }
    }
}

impl core::error::Error for SMTPError {}
