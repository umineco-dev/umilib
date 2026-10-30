//! Tests of `umilib::protocol::http` against RFC 9110, RFC 9651 (with the
//! structured field tests of the HTTP working group), RFC 9218 and the
//! RFCs of each version.

mod coding;
mod rule;
mod semantics;
mod structured;
#[cfg(umilib_feature = "protocol-http-v1")]
mod v1;
#[cfg(umilib_feature = "protocol-http-v2")]
mod v2;
#[cfg(umilib_feature = "protocol-http-v3")]
mod v3;
#[cfg(umilib_feature = "protocol-http-websocket")]
mod websocket;
