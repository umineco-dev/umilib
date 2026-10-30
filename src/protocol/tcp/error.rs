use crate::bytes::BytesError;
use crate::protocol::ip::IPError;

/// Why a TCP segment cannot be read or written, or a connection cannot do
/// what is asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TCPError {
    /// Fewer bytes than the header, a data offset below 5 words or beyond the
    /// bytes, or a segment too long for its IP version.
    Length,
    /// A checksum that is wrong.
    Checksum,
    /// An option whose length is illegal, or options that do not fit the 40
    /// bytes of the header (RFC 9293 §3.1).
    Option,
    /// Addresses of different IP versions.
    Family,
    /// An address that names no single host where one is needed (RFC 9293
    /// MUST-46, MUST-57, MUST-63).
    Address,
    /// An operation that the connection's state does not allow.
    State,
    /// A configuration that cannot work ([`super::TCPConfig::check`]).
    Config,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for TCPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TCPError::Length => formatter.write_str("the TCP segment's length is wrong"),
            TCPError::Checksum => formatter.write_str("the TCP checksum is wrong"),
            TCPError::Option => formatter.write_str("a TCP option is malformed or the options do not fit"),
            TCPError::Family => formatter.write_str("the addresses are of different IP versions"),
            TCPError::Address => formatter.write_str("the address names no single host"),
            TCPError::State => formatter.write_str("the connection's state does not allow it"),
            TCPError::Config => formatter.write_str("the TCP configuration cannot work"),
            TCPError::Write(error) => write!(formatter, "the segment cannot be written: {error}"),
        }
    }
}

impl core::error::Error for TCPError {}

impl From<BytesError> for TCPError {
    fn from(error: BytesError) -> TCPError {
        TCPError::Write(error)
    }
}

impl From<IPError> for TCPError {
    fn from(error: IPError) -> TCPError {
        match error {
            IPError::Family => TCPError::Family,
            _ => TCPError::Length,
        }
    }
}
