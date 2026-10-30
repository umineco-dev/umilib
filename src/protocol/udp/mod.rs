//! The User Datagram Protocol (RFC 768) over IPv4 and IPv6: the header, the
//! datagram with its checksum over the pseudo-header (RFC 768, RFC 8200
//! §8.1), the zero checksum of IPv6 tunnels (RFC 6935, RFC 6936), jumbograms
//! (RFC 2675 §4), and the rule that routes datagrams to services by their
//! endpoints.

mod config;
mod datagram;
mod error;
mod header;
mod rule;

pub use config::UDPConfig;
pub use datagram::UDPDatagram;
pub use error::UDPError;
pub use header::UDPHeader;
pub use rule::{UDPRequest, UDPRule};
