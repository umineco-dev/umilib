//! SCRAM (RFC 5802) over SHA-1 and SHA-256 (RFC 7677), with and without
//! channel binding (the `-PLUS` variants, RFC 5802 §6): the four messages,
//! the keys, the credentials a server keeps, and a client and a server
//! without I/O.
//!
//! ```text
//! client.client_first()           -> client-first-message
//! server.receive_client_first()   (the application looks up server.username())
//! server.server_first(credentials, nonce) -> server-first-message
//! client.receive_server_first()   -> client-final-message
//! server.receive_client_final()   -> server-final-message
//! client.receive_server_final()
//! ```

mod client;
mod error;
mod hash;
mod keys;
mod message;
mod server;

pub use client::{SCRAMClient, SCRAMClientState, SCRAMSecret};
pub use error::{SCRAMError, SCRAMServerError};
pub use hash::SCRAMHash;
pub use keys::{SCRAMConfig, SCRAMCredentials, SCRAMKeys};
pub use message::{SCRAMAttribute, SCRAMClientFinal, SCRAMClientFirst, SCRAMNonce, SCRAMServerFinal, SCRAMServerFirst};
pub use server::{SCRAMServer, SCRAMServerState};
