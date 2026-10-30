//! IPv4 (RFC 791): the header with its options and checksum, the
//! fragmentation of datagrams for an MTU and their reassembly (RFC 815,
//! RFC 1122 §3.3.2), without I/O.

mod error;
mod fragmenter;
mod header;
mod option;
mod reassembler;

pub use error::IPv4Error;
pub use fragmenter::IPv4Fragmenter;
pub use header::IPv4Header;
pub use option::{IPv4Option, IPv4OptionIterator, IPv4OptionKind, IPv4Options};
pub use reassembler::{IPv4Reassembler, IPv4Reassembly, IPv4ReassemblyConfig, IPv4ReassemblyKey};
