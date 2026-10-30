//! SMTP (RFC 5321) without I/O: a client ([`SMTPClient`]) and a server
//! ([`SMTPServer`]), their commands ([`SMTPCommand`]), replies
//! ([`SMTPReply`], [`SMTPEnhancedStatus`] of RFC 3463), paths
//! ([`SMTPPath`], [`SMTPMailbox`]), mail data ([`SMTPData`],
//! [`SMTPDataReader`]), and the extensions of the reply to EHLO
//! ([`SMTPExtensions`]): SIZE (RFC 1870), PIPELINING (RFC 2920), STARTTLS
//! (RFC 3207), AUTH (RFC 4954), 8BITMIME (RFC 6152), ENHANCEDSTATUSCODES
//! (RFC 2034), CHUNKING and BINARYMIME (RFC 3030), SMTPUTF8 (RFC 6531) and
//! DSN (RFC 3461, [`SMTPXText`]). The SASL exchange of AUTH is the user's:
//! the client and the server carry its messages. TLS is the user's too:
//! STARTTLS ends in an event, and implicit TLS (RFC 8314) is a connection
//! that is secure from its start. With `protocol-dns`, the hosts of a
//! domain's mail are ordered by [`SMTPMailExchanger`] (RFC 5321 §5.1, RFC 7505).

mod client;
mod command;
mod config;
mod data;
mod error;
mod extension;
mod path;
mod reply;
#[cfg(umilib_feature = "protocol-dns")]
mod route;
mod server;

pub use client::{SMTPClient, SMTPClientEvent, SMTPClientPending, SMTPClientSent, SMTPClientTransaction};
pub use command::{SMTPCommand, SMTPParameter};
pub use config::{SMTPConfig, SMTPServerConfig};
pub use data::{SMTPData, SMTPDataReader, SMTPDataState};
pub use error::SMTPError;
pub use extension::{SMTPExtension, SMTPExtensions};
pub use path::{SMTPMailbox, SMTPPath, SMTPXText};
pub use reply::{SMTPEnhancedStatus, SMTPReply, SMTPReplyReader};
#[cfg(umilib_feature = "protocol-dns")]
pub use route::SMTPMailExchanger;
pub use server::{SMTPServer, SMTPServerEvent, SMTPServerPending, SMTPServerPhase, SMTPServerTransaction};
