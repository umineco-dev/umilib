//! The Linux functions and constants the Linux layer uses, declared from
//! the kernel's and glibc's headers (bionic has the same ones).

use core::ffi::{c_int, c_long};

/// `struct epoll_event`, packed on x86-64 as the kernel declares it there.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

unsafe extern "C" {
    pub fn epoll_create1(flags: c_int) -> c_int;
    pub fn epoll_ctl(epoll: c_int, operation: c_int, descriptor: c_int, event: *mut EpollEvent) -> c_int;
    pub fn epoll_wait(epoll: c_int, events: *mut EpollEvent, maximum: c_int, timeout: c_int) -> c_int;
    pub fn eventfd(initial: u32, flags: c_int) -> c_int;
    pub fn syscall(number: c_long, ...) -> c_long;
    /// glibc declares the request `unsigned long`; musl and bionic, `int`.
    #[cfg(target_env = "gnu")]
    pub fn ioctl(descriptor: c_int, request: core::ffi::c_ulong, ...) -> c_int;
    #[cfg(not(target_env = "gnu"))]
    pub fn ioctl(descriptor: c_int, request: c_int, ...) -> c_int;
}

/// The constants of the declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Linux;

impl Linux {
    pub const EPOLL_CLOEXEC: c_int = 0o2000000;
    pub const EPOLL_CTL_ADD: c_int = 1;
    pub const EPOLL_CTL_DEL: c_int = 2;
    pub const EPOLL_CTL_MOD: c_int = 3;
    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const EPOLLRDHUP: u32 = 0x2000;
    pub const EPOLLONESHOT: u32 = 1 << 30;
    pub const EPOLLET: u32 = 1 << 31;
    pub const EFD_CLOEXEC: c_int = 0o2000000;
    pub const EFD_NONBLOCK: c_int = 0o4000;
    pub const EINTR: i32 = 4;
    pub const EIO: i32 = 5;
    pub const ENOSYS: i32 = 38;
    /// The number of the `getrandom` system call of the architecture (`None`
    /// where it is not known: the random source then reads `/dev/urandom`).
    pub const SYS_GETRANDOM: Option<c_long> = if cfg!(target_arch = "x86_64") {
        Some(318)
    } else if cfg!(target_arch = "x86") {
        Some(355)
    } else if cfg!(target_arch = "arm") {
        Some(384)
    } else if cfg!(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "riscv32",
        target_arch = "loongarch64"
    )) {
        Some(278)
    } else if cfg!(target_arch = "s390x") {
        Some(349)
    } else if cfg!(any(target_arch = "powerpc", target_arch = "powerpc64")) {
        Some(359)
    } else {
        None
    };
    /// The packet socket address: `struct sockaddr_ll` (20 bytes).
    pub const SOCKADDR_LL: usize = 20;
    /// Every protocol, for packet sockets (`ETH_P_ALL`).
    pub const ETH_P_ALL: u16 = 0x0003;
    /// `TUNSETIFF`: `_IOW('T', 202, int)`, whose direction bits differ on
    /// the architectures that do not use the generic `ioctl` numbers.
    pub const TUNSETIFF: u32 = if cfg!(any(
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc",
        target_arch = "sparc64"
    )) {
        0x8004_54CA
    } else {
        0x4004_54CA
    };
    /// The kinds and options of TUN interfaces (`<linux/if_tun.h>`).
    pub const IFF_TUN: i16 = 0x0001;
    pub const IFF_TAP: i16 = 0x0002;
    pub const IFF_NO_PI: i16 = 0x1000;
}
