//! What Windows gives: Winsock sockets with every option and their
//! duplication into other processes ([`Socket`], [`SocketDuplicate`]), I/O
//! completion ports ([`CompletionPort`]) and the system's random bytes
//! ([`Random`]). Compiled on Windows only.

mod address;
mod completion_port;
mod random;
mod socket;
pub mod sys;

pub use address::RawSocketAddress;
pub use completion_port::{Completion, CompletionPort};
pub use random::Random;
pub use socket::{Socket, SocketDomain, SocketDuplicate, SocketKind};
