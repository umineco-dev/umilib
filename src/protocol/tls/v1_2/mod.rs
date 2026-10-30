//! TLS 1.2 (RFC 5246) with the ECDHE key exchanges and AEAD ciphers only
//! (RFC 9325): the PRF, record protection, the messages only this version
//! has, and the handshakes of client and server.

mod client;
mod established;
mod message;
mod prf;
mod record;
mod secrets;
mod server;

pub use client::{TLS12Client, TLS12ClientState};
pub use established::TLS12Established;
pub use message::{TLS12Certificate, TLS12CertificateRequest, TLS12ClientKeyExchange, TLS12ServerKeyExchange};
pub use prf::TLS12PRF;
pub use record::TLS12RecordProtection;
pub use secrets::TLS12Secrets;
pub use server::{TLS12Selection, TLS12Server, TLS12ServerState};
