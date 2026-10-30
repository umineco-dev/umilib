//! Tests of `umilib::protocol::quic` against the examples and rules of
//! RFC 9000, RFC 9001, RFC 9002, RFC 9221, RFC 9287, RFC 9368 and RFC 9369.

mod codec;
pub mod connection;
mod endpoint;
mod parameters;
mod protection;
mod recovery;
mod rules;

use crate::{RFC, Vectors};

/// The RFC texts of `tests/vectors/protocol/quic`.
pub struct QUICVectors;

impl QUICVectors {
    pub fn path(rfc: u32) -> String {
        format!("protocol/quic/rfc{rfc}.txt")
    }

    /// The bytes of the hexadecimal block after the line containing `marker` in RFC `rfc`.
    pub fn block(rfc: u32, marker: &str) -> Vec<u8> {
        Vectors::hex(&RFC::block(&QUICVectors::path(rfc), marker, None))
    }
}
