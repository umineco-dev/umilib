//! ICMP for IPv4 (RFC 792, with RFC 1122 §3.2.2): the messages, their
//! types and codes, the rules of error messages, and the extensions of
//! RFC 4884 in the error messages that carry them.

mod kind;
mod message;

pub use kind::{ICMPv4Code, ICMPv4Type};
pub use message::ICMPv4Message;
