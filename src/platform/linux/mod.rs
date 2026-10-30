//! What Linux kernels give (on Linux and Android): the readiness poller on
//! `epoll` ([`Poller`]), `eventfd` ([`EventFD`]), the kernel's random bytes
//! ([`Random`]), packet sockets ([`PacketSocket`], [`LinkAddress`]) and TUN
//! and TAP interfaces ([`TUNDevice`]).
//! Compiled on Linux and Android only.

mod event_fd;
mod packet;
mod poller;
mod random;
pub mod sys;
mod tun;

pub use event_fd::EventFD;
pub use packet::{LinkAddress, PacketSocket};
pub use poller::Poller;
pub use random::Random;
pub use tun::{InterfaceRequest, TUNDevice, TUNKind};
