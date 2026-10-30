//! HTTP (RFC 9110): the semantics every version shares, without I/O.
//!
//! This root module holds the messages ([`HTTPRequest`], [`HTTPResponse`])
//! and their parts — methods, status codes, fields, targets — [`HTTPRule`]
//! to route requests, structured
//! field values (RFC 9651) and priorities (RFC 9218), content codings, and
//! [`HTTPConnection`], the interface of connections of every version. Each
//! version is a module of its own: `v1` (feature `protocol-http-v1`, RFC
//! 9112), `v2` (`protocol-http-v2`, RFC 9113) and `v3` (`protocol-http-v3`,
//! RFC 9114); `websocket` (`protocol-http-websocket`) opens WebSocket
//! connections over them (RFC 6455, RFC 8441, RFC 9220).

mod coding;
mod config;
mod connection;
mod error;
mod field;
mod length;
mod message;
mod method;
mod priority;
mod pseudo;
mod rule;
mod status;
mod structured;
mod syntax;
mod target;
mod version;

#[cfg(umilib_feature = "protocol-http-v1")]
pub mod v1;
#[cfg(umilib_feature = "protocol-http-v2")]
pub mod v2;
#[cfg(umilib_feature = "protocol-http-v3")]
pub mod v3;
#[cfg(umilib_feature = "protocol-http-websocket")]
pub mod websocket;

pub use coding::{HTTPAcceptEncoding, HTTPContentCoding, HTTPContentDecoder, HTTPContentEncoder};
pub use config::HTTPConfig;
pub use connection::{HTTPConnection, HTTPEvent, HTTPReset, HTTPRole, HTTPStreamID};
pub use error::HTTPError;
pub use field::{HTTPField, HTTPFields};
pub use length::HTTPContentLength;
pub use message::{HTTPRequest, HTTPResponse};
pub use method::HTTPMethod;
pub use priority::HTTPPriority;
pub use pseudo::HTTPPseudoField;
pub use rule::HTTPRule;
pub use status::HTTPStatus;
pub use structured::{HTTPBareItem, HTTPItem, HTTPMember, HTTPParameters, HTTPStructuredField};
pub use syntax::HTTPSyntax;
pub use target::{HTTPAuthority, HTTPTarget};
pub use version::HTTPVersion;
