use crate::bytes::BytesError;

/// Why an ICMP or ICMPv6 message cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ICMPError {
    /// Fewer bytes than the message's header, length attribute or options say.
    Length,
    /// A checksum that is wrong.
    Checksum,
    /// An extension structure of a version other than 2 (RFC 4884 §7).
    Version,
    /// A message that fails the validity checks of its type (the hop limit,
    /// code, length and options of a Neighbor Discovery message, RFC 4861).
    Invalid,
    /// More neighbors known and being resolved than the configuration allows.
    Limit,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for ICMPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ICMPError::Length => formatter.write_str("the ICMP message is shorter than its fields say"),
            ICMPError::Checksum => formatter.write_str("the ICMP checksum is wrong"),
            ICMPError::Version => formatter.write_str("the ICMP extension structure is not of version 2"),
            ICMPError::Invalid => formatter.write_str("the ICMP message fails the validity checks of its type"),
            ICMPError::Limit => formatter.write_str("the neighbor cache is full"),
            ICMPError::Write(error) => write!(formatter, "the message cannot be written: {error}"),
        }
    }
}

impl core::error::Error for ICMPError {}

impl From<BytesError> for ICMPError {
    fn from(error: BytesError) -> ICMPError {
        ICMPError::Write(error)
    }
}
