//! HTTP/3 (RFC 9114), without I/O: [`H3Connection`] is the HTTP/3 layer
//! of a QUIC connection, with QPACK (RFC 9204), extended CONNECT (RFC
//! 9220) and the priorities of RFC 9218; [`H3Session`] binds it to its QUIC
//! connection as an [`HTTPConnection`](crate::protocol::http::HTTPConnection).
//! Server push is off.

mod config;
mod connection;
mod error;
mod frame;
mod settings;
mod stream;

pub use config::H3Config;
pub use connection::{H3Connection, H3Session, H3State, H3Unidirectional};
pub use error::{H3Error, H3ErrorCode};
pub use frame::{H3FrameHeader, H3FrameType, H3StreamType};
pub use settings::H3Settings;
pub use stream::{H3Reading, H3Stream};
