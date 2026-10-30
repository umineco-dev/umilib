//! WebSocket (RFC 6455), without I/O: [`WebSocketConnection`] exchanges
//! messages over a byte stream once an opening handshake made one (over
//! HTTP, `protocol::http::websocket`), with permessage-deflate (RFC 7692,
//! [`WebSocketDeflate`]); [`WebSocketFrameHeader`] reads and writes frames.

mod config;
mod connection;
mod deflate;
mod frame;

pub use config::WebSocketConfig;
pub use connection::{WebSocketConnection, WebSocketEvent, WebSocketFragments, WebSocketRole, WebSocketState};
pub use deflate::{WebSocketDeflate, WebSocketDeflateParameters};
pub use frame::{WebSocketCloseCode, WebSocketFrameHeader, WebSocketOpcode};
