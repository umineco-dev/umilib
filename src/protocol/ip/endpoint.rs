use core::fmt;
use core::str::FromStr;

use super::{IPAddress, IPError, IPv6Address};

/// An endpoint of a transport protocol over IP (UDP, TCP): an address and a
/// port (RFC 6335). It has no zone: a link-local address names an
/// interface of the caller's choosing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IPEndpoint {
    pub address: IPAddress,
    pub port: u16,
}

impl IPEndpoint {
    pub const fn new(address: IPAddress, port: u16) -> IPEndpoint {
        IPEndpoint { address, port }
    }

    /// Reads `address:port` for IPv4 and `[address]:port` for IPv6, the
    /// forms of the authority of RFC 3986 §3.2.2; a zone (RFC 6874) is refused.
    pub fn from_ascii(text: &[u8]) -> Result<IPEndpoint, IPError> {
        let colon = text.iter().rposition(|&byte| byte == b':').ok_or(IPError::Syntax)?;
        let (host, port) = (&text[..colon], &text[colon + 1..]);
        let port = core::str::from_utf8(port).ok().filter(|port| !port.starts_with('+')).ok_or(IPError::Syntax)?;
        let port = port.parse::<u16>().map_err(|_| IPError::Syntax)?;
        let address = match host {
            [b'[', inner @ .., b']'] => IPAddress::V6(IPv6Address::from_ascii(inner)?),
            _ if host.contains(&b':') => return Err(IPError::Syntax),
            _ => IPAddress::from_ascii(host)?,
        };
        Ok(IPEndpoint { address, port })
    }
}

impl FromStr for IPEndpoint {
    type Err = IPError;

    fn from_str(text: &str) -> Result<IPEndpoint, IPError> {
        IPEndpoint::from_ascii(text.as_bytes())
    }
}

impl fmt::Display for IPEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IPAddress::V4(address) => write!(formatter, "{address}:{}", self.port),
            IPAddress::V6(address) => write!(formatter, "[{address}]:{}", self.port),
        }
    }
}

/// The local and the remote endpoint of what a transport protocol carries:
/// what an [`IPEndpointPattern`] is matched against.
pub trait IPEndpoints {
    fn local(&self) -> IPEndpoint;
    fn remote(&self) -> IPEndpoint;
}

/// A set of endpoints: those whose address has a prefix (any address if
/// `prefix` is `None`) and whose port is from `first_port` to `last_port`.
/// IPv4-mapped IPv6 addresses (RFC 4291 §2.5.5.2) match as IPv4 addresses,
/// and a prefix of at least 96 bits of them is the IPv4 prefix it maps
/// ([`IPAddress::to_canonical_prefix`]); no other prefix matches an address
/// of the other version. A prefix length beyond the address's bits is all
/// of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IPEndpointPattern {
    /// The address and the length of the prefix in bits.
    pub prefix: Option<(IPAddress, u8)>,
    pub first_port: u16,
    pub last_port: u16,
}

impl IPEndpointPattern {
    /// Every endpoint.
    pub const ANY: IPEndpointPattern = IPEndpointPattern { prefix: None, first_port: 0, last_port: u16::MAX };

    /// The endpoints of any address with the port `port`.
    pub const fn port(port: u16) -> IPEndpointPattern {
        IPEndpointPattern { prefix: None, first_port: port, last_port: port }
    }

    /// The endpoints of any address with a port from `first` to `last`.
    pub const fn ports(first: u16, last: u16) -> IPEndpointPattern {
        IPEndpointPattern { prefix: None, first_port: first, last_port: last }
    }

    /// These endpoints, of the address `address` only.
    pub const fn with_address(self, address: IPAddress) -> IPEndpointPattern {
        let length = match address {
            IPAddress::V4(_) => 32,
            IPAddress::V6(_) => 128,
        };
        self.with_prefix(address, length)
    }

    /// These endpoints, of the addresses whose first `length` bits are those
    /// of `address`; the prefix is kept as [`IPAddress::to_canonical_prefix`]
    /// makes it, so that equal sets compare equal.
    pub const fn with_prefix(self, address: IPAddress, length: u8) -> IPEndpointPattern {
        IPEndpointPattern { prefix: Some(address.to_canonical_prefix(length)), ..self }
    }

    pub fn matches(&self, endpoint: &IPEndpoint) -> bool {
        let address_matches = match self.prefix {
            None => true,
            Some((prefix, length)) => {
                let (prefix, length) = prefix.to_canonical_prefix(length);
                endpoint.address.to_canonical().has_prefix(&prefix, length)
            }
        };
        address_matches && (self.first_port..=self.last_port).contains(&endpoint.port)
    }
}

impl Default for IPEndpointPattern {
    fn default() -> IPEndpointPattern {
        IPEndpointPattern::ANY
    }
}
