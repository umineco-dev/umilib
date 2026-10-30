use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::Path;
use std::string::String;

use super::sys::{self, Linux};
use crate::platform::unix::Socket;
use crate::platform::unix::sys::{self as unix, POSIX};

/// What a [`TUNDevice`] carries: IP packets (`IFF_TUN`) or Ethernet frames
/// (`IFF_TAP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TUNKind {
    /// IP packets, IPv4 or IPv6 by their version field.
    TUN,
    /// Ethernet frames, with their header and without their FCS.
    TAP,
}

impl TUNKind {
    /// The `IFF_` flag of the kind.
    pub fn flag(self) -> i16 {
        match self {
            TUNKind::TUN => Linux::IFF_TUN,
            TUNKind::TAP => Linux::IFF_TAP,
        }
    }
}

/// A TUN or TAP interface of the Linux kernel (`Documentation/networking/tuntap.rst`):
/// each [`TUNDevice::receive`] reads one packet the kernel routed to the
/// interface, and each [`TUNDevice::send`] gives the kernel one packet as if
/// it arrived on the interface. Packets carry no packet information header
/// (`IFF_NO_PI`). Opening one needs `CAP_NET_ADMIN`; the interface is
/// brought up and given addresses with the system's tools (`ip link`, `ip
/// address`) or netlink.
#[derive(Debug)]
pub struct TUNDevice {
    pub file: File,
    /// The name of the interface, as the kernel chose it if it was asked to.
    pub name: String,
    pub kind: TUNKind,
}

impl TUNDevice {
    /// The clone device of TUN and TAP interfaces.
    pub const PATH: &'static str = "/dev/net/tun";
    /// The longest interface name, without its NUL (`IFNAMSIZ` - 1).
    pub const NAME_LENGTH: usize = 15;

    /// Opens the interface `name` of `kind` through [`TUNDevice::PATH`],
    /// creating it if it does not exist. An empty name, or one with `%d`
    /// (such as `tun%d`), lets the kernel choose the name. Fails with
    /// `InvalidInput` for a name longer than [`TUNDevice::NAME_LENGTH`] or
    /// with a NUL.
    pub fn open(name: &str, kind: TUNKind) -> io::Result<TUNDevice> {
        TUNDevice::open_at(Path::new(TUNDevice::PATH), name, kind)
    }

    /// [`TUNDevice::open`] through the clone device at `path`.
    pub fn open_at(path: &Path, name: &str, kind: TUNKind) -> io::Result<TUNDevice> {
        if name.len() > TUNDevice::NAME_LENGTH || name.as_bytes().contains(&0) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // std opens files with O_CLOEXEC.
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut request = InterfaceRequest::default();
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        request.flags = kind.flag() | Linux::IFF_NO_PI;
        // SAFETY: a valid descriptor and a `struct ifreq` that lives during
        // the call, as large as the kernel's; the result is checked.
        Socket::check(unsafe {
            sys::ioctl(file.as_raw_fd(), Linux::TUNSETIFF as _, &mut request as *mut InterfaceRequest)
        })?;
        let length = request.name.iter().position(|byte| *byte == 0).unwrap_or(request.name.len());
        let name = String::from_utf8_lossy(&request.name[..length]).into_owned();
        Ok(TUNDevice { file, name, kind })
    }

    /// Reads one packet into `packet` and returns its length. Give it room
    /// for the MTU: a longer packet is lost, and the read fails with
    /// `InvalidData` (the kernel copies what fits and returns the length of
    /// the whole packet).
    pub fn receive(&self, packet: &mut [u8]) -> io::Result<usize> {
        let length = (&self.file).read(packet)?;
        if length > packet.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the packet is longer than the buffer"));
        }
        Ok(length)
    }

    /// Gives the kernel the packet `packet` and returns its length.
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        (&self.file).write(packet)
    }

    /// Sets or clears `O_NONBLOCK`: without it, [`TUNDevice::receive`]
    /// waits for a packet.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // SAFETY: a valid descriptor; the results are checked.
        let flags = Socket::check(unsafe { unix::fcntl(self.as_raw_fd(), POSIX::F_GETFL) })?;
        let flags = if nonblocking { flags | POSIX::O_NONBLOCK } else { flags & !POSIX::O_NONBLOCK };
        Socket::check(unsafe { unix::fcntl(self.as_raw_fd(), POSIX::F_SETFL, flags) }).map(|_| ())
    }

    /// Whether `O_NONBLOCK` is set.
    pub fn nonblocking(&self) -> io::Result<bool> {
        // SAFETY: a valid descriptor; the result is checked.
        let flags = Socket::check(unsafe { unix::fcntl(self.as_raw_fd(), POSIX::F_GETFL) })?;
        Ok(flags & POSIX::O_NONBLOCK != 0)
    }
}

impl AsRawFd for TUNDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl AsFd for TUNDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// `struct ifreq` as `TUNSETIFF` reads and writes it: the name and the
/// flags, then the rest of the union. 40 bytes, the size on 64-bit systems,
/// which is also enough for 32-bit ones (32 bytes).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, align(8))]
pub struct InterfaceRequest {
    pub name: [u8; 16],
    pub flags: i16,
    pub rest: [u8; 22],
}
