//! What POSIX systems (Linux, Android, Darwin) share: sockets with every
//! option ([`Socket`]), the system's socket addresses ([`RawSocketAddress`]),
//! network interfaces, and the readiness types of the pollers of
//! `platform-linux` and `platform-darwin` ([`Interest`], [`PollEvent`]).
//! Declared from the C headers of each system; compiled on those systems only.

mod address;
mod interface;
mod poll;
mod socket;
pub mod sys;

pub use address::RawSocketAddress;
pub use interface::NetworkInterface;
pub use poll::{Interest, PollEvent, PollMode};
pub use socket::{Socket, SocketDomain, SocketKind};
