//! HTTP/1.1 (RFC 9112), without I/O: [`H1Connection`] reads and writes the
//! messages of a byte stream (TCP or TLS) for a client or a server, with
//! persistent connections, pipelining, the chunked transfer coding, and
//! the switch to a tunnel after CONNECT or Upgrade; [`H1Parser`] reads
//! message heads and chunks, [`H1Writer`] writes them.

mod config;
mod connection;
mod parser;
mod writer;

pub use config::H1Config;
pub use connection::{H1Body, H1Chunk, H1Connection, H1Exchange, H1Framing, H1Reading, H1State};
pub use parser::{H1Head, H1Parser, H1StartLine};
pub use writer::H1Writer;
