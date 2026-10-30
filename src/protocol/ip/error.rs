/// Why an address or a pseudo-header cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IPError {
    /// A text that is not an address in one of the forms of RFC 4291 §2.2 (IPv6)
    /// or in dotted decimal (IPv4).
    Syntax,
    /// Addresses of different versions where one version is needed.
    Family,
    /// A length that does not fit the field that carries it, or a fragment
    /// beyond the end or the limit of its datagram.
    Length,
    /// A fragment that overlaps another fragment of its datagram.
    Overlap,
}

impl core::fmt::Display for IPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            IPError::Syntax => "the text is not an IP address",
            IPError::Family => "the addresses are of different IP versions",
            IPError::Length => "the length does not fit its field or the datagram",
            IPError::Overlap => "the fragment overlaps another fragment",
        })
    }
}

impl core::error::Error for IPError {}
