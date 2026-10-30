//! DNS: `udp` — a message a datagram (RFC 1035 §4.2.1): the port, which
//! datagrams may be a response (RFC 5452 §9.1), and the sizes that EDNS
//! allows ([`super::DNSMessage::udp_response_limit`]); a response that
//! does not fit is truncated, and its question asked again over TCP (RFC
//! 7766 §5), which [`super::DNSResolver`] does.

use crate::protocol::ip::IPEndpoint;

/// The rules of DNS over UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSUDP;

impl DNSUDP {
    /// The port of DNS (RFC 1035 §4.2).
    pub const PORT: u16 = 53;

    /// Whether a datagram from `source` may be the response to a query
    /// sent to `destination`: from the same address and port (RFC 5452 §9.1).
    pub fn accepts(source: &IPEndpoint, destination: &IPEndpoint) -> bool {
        source.address.to_canonical() == destination.address.to_canonical() && source.port == destination.port
    }
}
