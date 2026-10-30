use crate::bytes::BytesError;

/// Why an ARP packet cannot be read or written, or an address not resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ARPError {
    /// Fewer bytes than the packet's lengths say, or address lengths other
    /// than those of the packet's address types.
    Length,
    /// More addresses being resolved or resolved than the configuration allows.
    Limit,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for ARPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ARPError::Length => formatter.write_str("the lengths of the ARP packet are not consistent"),
            ARPError::Limit => formatter.write_str("the ARP cache is full"),
            ARPError::Write(error) => write!(formatter, "the packet cannot be written: {error}"),
        }
    }
}

impl core::error::Error for ARPError {}

impl From<BytesError> for ARPError {
    fn from(error: BytesError) -> ARPError {
        ARPError::Write(error)
    }
}
