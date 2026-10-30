//! IPv6 (RFC 8200): the header, the extension headers with their options,
//! the fragmentation of packets by their source and their reassembly
//! (RFC 8200 §4.5, RFC 5722, RFC 6946, RFC 7112), without I/O.

mod error;
mod extension;
mod fragment;
mod fragmenter;
mod header;
mod option;
mod reassembler;
mod routing;

pub use error::IPv6Error;
pub use extension::{IPv6ExtensionHeader, IPv6ExtensionHeaders};
pub use fragment::IPv6FragmentHeader;
pub use fragmenter::{IPv6Fragment, IPv6Fragmenter};
pub use header::IPv6Header;
pub use option::{IPv6Option, IPv6OptionIterator, IPv6OptionKind, IPv6OptionsHeader};
pub use reassembler::{
    IPv6FirstFragment, IPv6FragmentParts, IPv6Reassembler, IPv6Reassembly, IPv6ReassemblyConfig, IPv6ReassemblyKey,
};
pub use routing::IPv6RoutingHeader;
