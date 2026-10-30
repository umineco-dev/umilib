//! HTTP/2 (RFC 9113), without I/O: [`H2Connection`] reads and writes the
//! frames of a byte stream (TLS with ALPN "h2", or TCP with prior
//! knowledge) for a client or a server, with HPACK, flow control, the
//! priorities of RFC 9218 and extended CONNECT (RFC 8441); server push is
//! off. [`H2Frame`] reads and writes frames, [`H2Settings`] settings.

mod config;
mod connection;
mod error;
mod frame;
mod settings;
mod stream;

pub use config::H2Config;
pub use connection::{H2Connection, H2FieldBlock, H2State};
pub use error::{H2Error, H2ErrorCode};
pub use frame::{H2Flags, H2Frame, H2FrameHeader, H2FrameType, H2PriorityField};
pub use settings::{H2SettingID, H2Settings};
pub use stream::{H2Stream, H2StreamState};
