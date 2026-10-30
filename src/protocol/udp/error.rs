use crate::bytes::BytesError;
use crate::protocol::ip::IPError;

/// Why a UDP datagram cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UDPError {
    /// Fewer bytes than the header, a length field below 8 or beyond the
    /// bytes, or a datagram too long for its IP version.
    Length,
    /// A checksum that is wrong.
    Checksum,
    /// A zero checksum over IPv6 on a port that does not allow it (RFC 6936 §4).
    ZeroChecksum,
    /// Addresses of different IP versions.
    Family,
    /// A source address that names no single host: multicast, or the IPv4
    /// limited broadcast (RFC 1122 §4.1.3.6, RFC 4291 §2.7).
    Source,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl core::fmt::Display for UDPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UDPError::Length => formatter.write_str("the UDP datagram's length is wrong"),
            UDPError::Checksum => formatter.write_str("the UDP checksum is wrong"),
            UDPError::ZeroChecksum => formatter.write_str("the UDP datagram over IPv6 has no checksum"),
            UDPError::Family => formatter.write_str("the addresses are of different IP versions"),
            UDPError::Source => formatter.write_str("the source address names no single host"),
            UDPError::Write(error) => write!(formatter, "the datagram cannot be written: {error}"),
        }
    }
}

impl core::error::Error for UDPError {}

impl From<BytesError> for UDPError {
    fn from(error: BytesError) -> UDPError {
        UDPError::Write(error)
    }
}

impl From<IPError> for UDPError {
    fn from(error: IPError) -> UDPError {
        match error {
            IPError::Family => UDPError::Family,
            _ => UDPError::Length,
        }
    }
}
