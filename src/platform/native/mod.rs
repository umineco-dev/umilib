//! The operating system umilib is compiled for, under one set of names:
//! [`Random`] and [`Socket`] (with `SocketDomain`, `SocketKind` and
//! `RawSocketAddress`) everywhere; on Linux, Android and Darwin the
//! readiness `Poller` (`Interest`, `PollEvent`, `PollMode`) and
//! `NetworkInterface`; on Windows the `CompletionPort` (`Completion`) and
//! `SocketDuplicate`. [`System::NAME`] tells which system it is.

mod system;

pub use system::System;

#[cfg(target_vendor = "apple")]
pub use super::darwin::{Poller, Random};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use super::linux::{Poller, Random};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub use super::unix::{
    Interest, NetworkInterface, PollEvent, PollMode, RawSocketAddress, Socket, SocketDomain, SocketKind,
};
#[cfg(windows)]
pub use super::windows::{
    Completion, CompletionPort, Random, RawSocketAddress, Socket, SocketDomain, SocketDuplicate, SocketKind,
};
