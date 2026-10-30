//! POP3 (RFC 1939) without I/O: a client ([`POP3Client`]) and a server
//! ([`POP3Server`]), their commands ([`POP3Command`]), status lines
//! ([`POP3Response`], with the response codes of RFC 2449 §8), the lines
//! of multi-line responses ([`POP3MultiLineReader`], [`POP3MultiLineWriter`]),
//! and the capabilities of CAPA ([`POP3Capabilities`], RFC 2449): STLS (RFC
//! 2595), SASL (RFC 5034), UTF8 and LANG (RFC 6856). The SASL exchange of
//! AUTH, TLS, and the maildrop are the user's: the server tells each
//! command and the user answers it.

mod client;
mod command;
mod config;
mod error;
mod multi_line;
mod response;
mod server;

pub use client::{POP3Client, POP3ClientEvent, POP3State};
pub use command::POP3Command;
pub use config::{POP3Config, POP3ServerConfig};
pub use error::POP3Error;
pub use multi_line::{POP3MultiLineReader, POP3MultiLineState, POP3MultiLineWriter};
pub use response::{POP3Capabilities, POP3Capability, POP3Response};
pub use server::{POP3Server, POP3ServerEvent, POP3ServerPending};
