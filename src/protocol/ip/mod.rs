//! The Internet Protocol: what both versions share — addresses (RFC 791,
//! RFC 4291, with the text form of RFC 5952), protocol numbers, the Internet
//! checksum (RFC 1071, updated incrementally as RFC 1624), the pseudo-header
//! of upper-layer checksums, the reassembly of fragments and the endpoints
//! of transport protocols (an address and a port) — and
//! each version in [`v4`] and [`v6`].

mod checksum;
mod endpoint;
mod error;
mod fragment_buffer;
mod ip_address;
mod ipv4_address;
mod ipv6_address;
mod protocol;
mod pseudo_header;
mod reassembly;

pub use checksum::InternetChecksum;
pub use endpoint::{IPEndpoint, IPEndpointPattern, IPEndpoints};
pub use error::IPError;
pub use fragment_buffer::IPFragmentBuffer;
pub use ip_address::IPAddress;
pub use ipv4_address::IPv4Address;
pub use ipv6_address::IPv6Address;
pub use protocol::IPProtocol;
pub use pseudo_header::IPPseudoHeader;
pub use reassembly::{IPFirstFragment, IPReassembly, IPReassemblyTable};

#[cfg(umilib_feature = "protocol-ip-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-ip-v6")]
pub mod v6;
