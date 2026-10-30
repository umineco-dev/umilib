use crate::bytes::BytesError;

/// Why an Ethernet frame cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthernetError {
    /// Fewer bytes than the header, or than the length of an IEEE 802.3 frame says.
    Length,
    /// More VLAN tags than [`super::EthernetHeader::MAXIMUM_TAGS`], or a
    /// tag whose fields do not fit.
    Tag,
    /// A type field between 1,500 and 1,536, which is neither a length nor
    /// an EtherType (IEEE 802.3 §3.2.6).
    EtherType,
    /// A text that is not a MAC address.
    Syntax,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for EthernetError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EthernetError::Length => formatter.write_str("the frame is shorter than its header or length"),
            EthernetError::Tag => formatter.write_str("the VLAN tags are invalid"),
            EthernetError::EtherType => formatter.write_str("the type field is neither a length nor an EtherType"),
            EthernetError::Syntax => formatter.write_str("the text is not a MAC address"),
            EthernetError::Write(error) => write!(formatter, "the frame cannot be written: {error}"),
        }
    }
}

impl core::error::Error for EthernetError {}

impl From<BytesError> for EthernetError {
    fn from(error: BytesError) -> EthernetError {
        EthernetError::Write(error)
    }
}
