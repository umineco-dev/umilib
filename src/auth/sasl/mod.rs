//! SASL (RFC 4422): the messages of the mechanisms PLAIN (RFC 4616),
//! EXTERNAL (RFC 4422 appendix A), ANONYMOUS (RFC 4505), SCRAM-SHA-1 and
//! SCRAM-SHA-256 with their `-PLUS` variants (RFC 5802, RFC 7677), and
//! OAUTHBEARER (RFC 7628).
//!
//! Each mechanism is a set of messages and, where the mechanism has
//! several steps, a client and a server without I/O: the application
//! carries the messages in its protocol (SMTP, IMAP, ...), looks up the
//! credentials a server needs, and decides the outcome.

mod error;
mod gs2;
mod mechanism;

#[cfg(umilib_feature = "auth-sasl-anonymous")]
pub mod anonymous;
#[cfg(umilib_feature = "auth-sasl-external")]
pub mod external;
#[cfg(umilib_feature = "auth-sasl-oauthbearer")]
pub mod oauthbearer;
#[cfg(umilib_feature = "auth-sasl-plain")]
pub mod plain;
#[cfg(umilib_feature = "auth-sasl-scram")]
pub mod scram;

pub use error::SASLError;
pub use gs2::{GS2ChannelBinding, GS2Header};
pub use mechanism::SASLMechanism;
