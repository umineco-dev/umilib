use crate::protocol::ip::IPEndpoint;

/// How DNS messages are carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DNSTransport {
    /// One message a datagram (RFC 1035 §4.2.1).
    UDP,
    /// Messages after their 2-byte length (RFC 1035 §4.2.2, RFC 7766).
    TCP,
    /// TCP's messages over TLS (RFC 7858).
    TLS,
    /// A message an HTTP exchange (RFC 8484).
    HTTPS,
    /// A message a QUIC stream, after its 2-byte length (RFC 9250).
    QUIC,
}

impl DNSTransport {
    /// The port servers listen on (RFC 1035 §4.2, RFC 7858 §3.1, RFC 9250 §4.1.1).
    pub fn port(&self) -> u16 {
        match self {
            DNSTransport::UDP | DNSTransport::TCP => 53,
            DNSTransport::TLS | DNSTransport::QUIC => 853,
            DNSTransport::HTTPS => 443,
        }
    }

    /// Whether messages are encrypted, so that they are padded (RFC 7830, RFC 8467).
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, DNSTransport::UDP | DNSTransport::TCP)
    }

    /// Whether a message may be of up to 65535 bytes, not limited as a UDP payload.
    pub fn is_stream(&self) -> bool {
        *self != DNSTransport::UDP
    }

    /// Whether messages are matched to queries by their exchange, not
    /// their ID, which is then 0 (RFC 8484 §4.1, RFC 9250 §4.2.1).
    pub fn has_zero_id(&self) -> bool {
        matches!(self, DNSTransport::HTTPS | DNSTransport::QUIC)
    }
}

/// The other end of an exchange: where it is and how it is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSPeer {
    pub endpoint: IPEndpoint,
    pub transport: DNSTransport,
}
