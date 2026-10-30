//! WebSocket over HTTP (RFC 6455 §4, RFC 8441, RFC 9220): the opening
//! handshake of either end, over HTTP/1.1's Upgrade or the extended
//! CONNECT of HTTP/2 and HTTP/3, after which the stream (the tunnel of
//! HTTP/1.1, the stream of the others) carries a
//! [`WebSocketConnection`](crate::protocol::websocket::WebSocketConnection).

mod handshake;

pub use handshake::{WebSocketAgreement, WebSocketExtension, WebSocketHandshake, WebSocketOffer};
