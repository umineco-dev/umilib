use super::super::IPError;
use crate::bytes::BytesError;

/// Why an IPv6 packet cannot be read, made, fragmented or reassembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IPv6Error {
    /// A version other than 6.
    Version,
    /// Fewer bytes than the header, an extension header or the payload
    /// length says, or a payload beyond 65,535 bytes.
    Length,
    /// An extension header out of place: a Hop-by-Hop Options header that
    /// does not follow the IPv6 header (RFC 8200 §4.1).
    ExtensionHeader,
    /// Options that do not follow the format of RFC 8200 §4.2.
    Option,
    /// A first fragment without the whole header chain (RFC 7112, RFC 8200 §4.5).
    HeaderChain,
    /// An MTU too small to carry the unfragmentable headers and 8 bytes of
    /// data per fragment.
    Fragment,
    /// A fragment that the reassembly buffer refuses (see [`IPError`]).
    Reassembly(IPError),
    /// A fragment that cannot fit the limits of the configuration, even alone.
    Limit,
    /// A fragment of a datagram whose reassembly deadline is past, which
    /// `expire` has not given back yet.
    Expired,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for IPv6Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IPv6Error::Version => formatter.write_str("the packet is not of IP version 6"),
            IPv6Error::Length => formatter.write_str("the lengths of the packet are not consistent"),
            IPv6Error::ExtensionHeader => formatter.write_str("an extension header is out of place"),
            IPv6Error::Option => formatter.write_str("the options are malformed"),
            IPv6Error::HeaderChain => formatter.write_str("the first fragment does not hold the whole header chain"),
            IPv6Error::Fragment => formatter.write_str("the packet cannot be fragmented to fit the MTU"),
            IPv6Error::Reassembly(error) => write!(formatter, "the fragment cannot be reassembled: {error}"),
            IPv6Error::Limit => formatter.write_str("the fragment does not fit the reassembly limits"),
            IPv6Error::Expired => formatter.write_str("the reassembly deadline of the datagram is past"),
            IPv6Error::Write(error) => write!(formatter, "the packet cannot be written: {error}"),
        }
    }
}

impl core::error::Error for IPv6Error {}

impl From<IPError> for IPv6Error {
    fn from(error: IPError) -> IPv6Error {
        IPv6Error::Reassembly(error)
    }
}

impl From<BytesError> for IPv6Error {
    fn from(error: BytesError) -> IPv6Error {
        IPv6Error::Write(error)
    }
}
