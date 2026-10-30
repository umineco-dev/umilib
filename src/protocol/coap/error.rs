use core::fmt;

/// An error of CoAP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoAPError {
    /// Bytes that are not a CoAP message: a message format error (RFC 7252 §3, §4.2).
    Malformed(&'static str),
    /// An option of a value its definition does not allow (RFC 7252 §5.4.3).
    Option(&'static str),
    /// A message larger than it may be.
    TooLarge,
    /// What the call asks for is not possible now.
    State,
    /// A configuration that cannot work.
    Config,
    /// The source of randomness failed.
    Random,
}

impl fmt::Display for CoAPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoAPError::Malformed(reason) => write!(formatter, "a malformed CoAP message: {reason}"),
            CoAPError::Option(reason) => write!(formatter, "a CoAP option not valid: {reason}"),
            CoAPError::TooLarge => formatter.write_str("a CoAP message too large"),
            CoAPError::State => formatter.write_str("not possible in this state"),
            CoAPError::Config => formatter.write_str("a CoAP configuration that cannot work"),
            CoAPError::Random => formatter.write_str("the source of randomness failed"),
        }
    }
}

impl core::error::Error for CoAPError {}
