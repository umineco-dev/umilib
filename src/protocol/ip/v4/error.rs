use super::super::IPError;
use crate::bytes::BytesError;

/// Why an IPv4 packet cannot be read, made, fragmented or reassembled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IPv4Error {
    /// A version other than 4.
    Version,
    /// Fewer bytes than the header or the total length says, a header
    /// length below 20 bytes, or a total length beyond 65,535.
    Length,
    /// A header whose checksum is wrong (RFC 1122 §3.2.1.2).
    Checksum,
    /// Options that do not follow the formats of RFC 791 §3.1, or more than 40 bytes of them.
    Option,
    /// A datagram larger than the MTU that may not be fragmented (Don't
    /// Fragment), or an MTU too small to carry 8 bytes of data per fragment.
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

impl core::fmt::Display for IPv4Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IPv4Error::Version => formatter.write_str("the packet is not of IP version 4"),
            IPv4Error::Length => formatter.write_str("the lengths of the packet are not consistent"),
            IPv4Error::Checksum => formatter.write_str("the header checksum is wrong"),
            IPv4Error::Option => formatter.write_str("the options are malformed"),
            IPv4Error::Fragment => formatter.write_str("the datagram cannot be fragmented to fit the MTU"),
            IPv4Error::Reassembly(error) => write!(formatter, "the fragment cannot be reassembled: {error}"),
            IPv4Error::Limit => formatter.write_str("the fragment does not fit the reassembly limits"),
            IPv4Error::Expired => formatter.write_str("the reassembly deadline of the datagram is past"),
            IPv4Error::Write(error) => write!(formatter, "the packet cannot be written: {error}"),
        }
    }
}

impl core::error::Error for IPv4Error {}

impl From<IPError> for IPv4Error {
    fn from(error: IPError) -> IPv4Error {
        IPv4Error::Reassembly(error)
    }
}

impl From<BytesError> for IPv4Error {
    fn from(error: BytesError) -> IPv4Error {
        IPv4Error::Write(error)
    }
}
