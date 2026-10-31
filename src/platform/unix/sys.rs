//! The POSIX functions and constants the Unix layer uses, declared from the
//! C headers of each system (glibc and bionic for Linux and Android, the
//! macOS SDK for Darwin); the C library is the one std links.

use core::ffi::{c_int, c_void};

/// `socklen_t`.
pub type SocketLength = u32;

unsafe extern "C" {
    pub fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    pub fn bind(socket: c_int, address: *const c_void, length: SocketLength) -> c_int;
    pub fn listen(socket: c_int, backlog: c_int) -> c_int;
    pub fn connect(socket: c_int, address: *const c_void, length: SocketLength) -> c_int;
    pub fn accept(socket: c_int, address: *mut c_void, length: *mut SocketLength) -> c_int;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn accept4(socket: c_int, address: *mut c_void, length: *mut SocketLength, flags: c_int) -> c_int;
    pub fn setsockopt(socket: c_int, level: c_int, name: c_int, value: *const c_void, length: SocketLength) -> c_int;
    pub fn getsockopt(socket: c_int, level: c_int, name: c_int, value: *mut c_void, length: *mut SocketLength)
    -> c_int;
    pub fn getsockname(socket: c_int, address: *mut c_void, length: *mut SocketLength) -> c_int;
    pub fn getpeername(socket: c_int, address: *mut c_void, length: *mut SocketLength) -> c_int;
    pub fn shutdown(socket: c_int, how: c_int) -> c_int;
    pub fn send(socket: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
    pub fn recv(socket: c_int, data: *mut c_void, length: usize, flags: c_int) -> isize;
    pub fn sendto(
        socket: c_int,
        data: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_length: SocketLength,
    ) -> isize;
    pub fn recvfrom(
        socket: c_int,
        data: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut c_void,
        address_length: *mut SocketLength,
    ) -> isize;
    pub fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
    pub fn if_nametoindex(name: *const core::ffi::c_char) -> u32;
}

/// The constants of the declarations, per system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct POSIX;

// The Linux values below are those of the kernel's generic headers
// (`asm-generic/socket.h`, `asm-generic/fcntl.h`, `linux/net.h`), which these
// architectures use. Others define their own (MIPS: `SOCK_STREAM` 2,
// `SOL_SOCKET` 0xFFFF, `O_NONBLOCK` 0x80; SPARC, Alpha and PA-RISC differ as
// well), and are refused rather than given values never run.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x"
    ))
))]
compile_error!("the socket and file constants of Linux are verified only for the architectures of the generic headers");

#[cfg(any(target_os = "linux", target_os = "android"))]
impl POSIX {
    pub const AF_INET6: c_int = 10;
    pub const AF_PACKET: c_int = 17;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_REUSEADDR: c_int = 2;
    pub const SO_TYPE: c_int = 3;
    pub const SO_ERROR: c_int = 4;
    pub const SO_BROADCAST: c_int = 6;
    pub const SO_SNDBUF: c_int = 7;
    pub const SO_RCVBUF: c_int = 8;
    pub const SO_KEEPALIVE: c_int = 9;
    pub const SO_REUSEPORT: c_int = 15;
    pub const IP_TTL: c_int = 2;
    pub const IPV6_V6ONLY: c_int = 26;
    pub const O_NONBLOCK: c_int = 0o4000;
    pub const SOCK_NONBLOCK: c_int = 0o4000;
    pub const SOCK_CLOEXEC: c_int = 0o2000000;
    pub const MSG_NOSIGNAL: c_int = 0x4000;
}

#[cfg(target_vendor = "apple")]
impl POSIX {
    pub const AF_INET6: c_int = 30;
    pub const SOL_SOCKET: c_int = 0xFFFF;
    pub const SO_REUSEADDR: c_int = 0x0004;
    pub const SO_KEEPALIVE: c_int = 0x0008;
    pub const SO_BROADCAST: c_int = 0x0020;
    pub const SO_REUSEPORT: c_int = 0x0200;
    pub const SO_SNDBUF: c_int = 0x1001;
    pub const SO_RCVBUF: c_int = 0x1002;
    pub const SO_ERROR: c_int = 0x1007;
    pub const SO_TYPE: c_int = 0x1008;
    pub const SO_NOSIGPIPE: c_int = 0x1022;
    pub const IP_TTL: c_int = 4;
    pub const IPV6_V6ONLY: c_int = 27;
    pub const O_NONBLOCK: c_int = 0x0004;
    pub const MSG_NOSIGNAL: c_int = 0;
}

impl POSIX {
    pub const AF_UNSPEC: c_int = 0;
    pub const AF_INET: c_int = 2;
    pub const SOCK_STREAM: c_int = 1;
    pub const SOCK_DGRAM: c_int = 2;
    pub const SOCK_RAW: c_int = 3;
    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    pub const TCP_NODELAY: c_int = 1;
    pub const SHUT_RD: c_int = 0;
    pub const SHUT_WR: c_int = 1;
    pub const SHUT_RDWR: c_int = 2;
    pub const F_GETFD: c_int = 1;
    pub const F_SETFD: c_int = 2;
    pub const F_GETFL: c_int = 3;
    pub const F_SETFL: c_int = 4;
    pub const FD_CLOEXEC: c_int = 1;
    /// The size of `struct sockaddr_storage`.
    pub const SOCKADDR_STORAGE: usize = 128;
}
