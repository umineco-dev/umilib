//! The Windows functions and constants the Windows layer uses, declared
//! from the Windows SDK headers (as mingw-w64 has them): Winsock 2
//! (`ws2_32`), I/O completion ports (`kernel32`) and `ProcessPrng`
//! (`bcryptprimitives`, the system's random generator since Windows 10).

use core::ffi::{c_int, c_void};

/// `SOCKET`.
pub type RawSocket = usize;
/// `HANDLE`.
pub type Handle = *mut c_void;

/// `OVERLAPPED` (and `WSAOVERLAPPED`).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Overlapped {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub event: Handle,
}

impl Default for Overlapped {
    fn default() -> Overlapped {
        Overlapped { internal: 0, internal_high: 0, offset: 0, offset_high: 0, event: core::ptr::null_mut() }
    }
}

/// `WSABUF`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct WSABuffer {
    pub length: u32,
    pub data: *mut u8,
}

/// `GUID`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// `LPFN_CONNECTEX`.
pub type ConnectEx = unsafe extern "system" fn(
    socket: RawSocket,
    address: *const c_void,
    length: c_int,
    send: *const c_void,
    send_length: u32,
    sent: *mut u32,
    overlapped: *mut Overlapped,
) -> c_int;

/// `OVERLAPPED_ENTRY`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct OverlappedEntry {
    pub key: usize,
    pub overlapped: *mut c_void,
    pub internal: usize,
    pub bytes: u32,
}

impl Default for OverlappedEntry {
    fn default() -> OverlappedEntry {
        OverlappedEntry { key: 0, overlapped: core::ptr::null_mut(), internal: 0, bytes: 0 }
    }
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    pub fn WSAStartup(version: u16, data: *mut c_void) -> c_int;
    pub fn WSAGetLastError() -> c_int;
    pub fn WSASocketW(
        family: c_int,
        kind: c_int,
        protocol: c_int,
        information: *const c_void,
        group: u32,
        flags: u32,
    ) -> RawSocket;
    pub fn WSADuplicateSocketW(socket: RawSocket, process: u32, information: *mut c_void) -> c_int;
    pub fn closesocket(socket: RawSocket) -> c_int;
    pub fn bind(socket: RawSocket, address: *const c_void, length: c_int) -> c_int;
    pub fn listen(socket: RawSocket, backlog: c_int) -> c_int;
    pub fn connect(socket: RawSocket, address: *const c_void, length: c_int) -> c_int;
    pub fn accept(socket: RawSocket, address: *mut c_void, length: *mut c_int) -> RawSocket;
    pub fn setsockopt(socket: RawSocket, level: c_int, name: c_int, value: *const c_void, length: c_int) -> c_int;
    pub fn getsockopt(socket: RawSocket, level: c_int, name: c_int, value: *mut c_void, length: *mut c_int) -> c_int;
    pub fn getsockname(socket: RawSocket, address: *mut c_void, length: *mut c_int) -> c_int;
    pub fn getpeername(socket: RawSocket, address: *mut c_void, length: *mut c_int) -> c_int;
    pub fn shutdown(socket: RawSocket, how: c_int) -> c_int;
    pub fn send(socket: RawSocket, data: *const c_void, length: c_int, flags: c_int) -> c_int;
    pub fn recv(socket: RawSocket, data: *mut c_void, length: c_int, flags: c_int) -> c_int;
    pub fn sendto(
        socket: RawSocket,
        data: *const c_void,
        length: c_int,
        flags: c_int,
        address: *const c_void,
        address_length: c_int,
    ) -> c_int;
    pub fn recvfrom(
        socket: RawSocket,
        data: *mut c_void,
        length: c_int,
        flags: c_int,
        address: *mut c_void,
        address_length: *mut c_int,
    ) -> c_int;
    pub fn ioctlsocket(socket: RawSocket, command: i32, argument: *mut u32) -> c_int;
    pub fn WSARecv(
        socket: RawSocket,
        buffers: *const WSABuffer,
        count: u32,
        received: *mut u32,
        flags: *mut u32,
        overlapped: *mut Overlapped,
        routine: *const c_void,
    ) -> c_int;
    pub fn WSASend(
        socket: RawSocket,
        buffers: *const WSABuffer,
        count: u32,
        sent: *mut u32,
        flags: u32,
        overlapped: *mut Overlapped,
        routine: *const c_void,
    ) -> c_int;
    pub fn WSARecvFrom(
        socket: RawSocket,
        buffers: *const WSABuffer,
        count: u32,
        received: *mut u32,
        flags: *mut u32,
        from: *mut c_void,
        from_length: *mut c_int,
        overlapped: *mut Overlapped,
        routine: *const c_void,
    ) -> c_int;
    pub fn WSASendTo(
        socket: RawSocket,
        buffers: *const WSABuffer,
        count: u32,
        sent: *mut u32,
        flags: u32,
        to: *const c_void,
        to_length: c_int,
        overlapped: *mut Overlapped,
        routine: *const c_void,
    ) -> c_int;
    pub fn WSAIoctl(
        socket: RawSocket,
        code: u32,
        input: *const c_void,
        input_length: u32,
        output: *mut c_void,
        output_length: u32,
        returned: *mut u32,
        overlapped: *mut Overlapped,
        routine: *const c_void,
    ) -> c_int;
    pub fn WSAGetOverlappedResult(
        socket: RawSocket,
        overlapped: *const Overlapped,
        transferred: *mut u32,
        wait: c_int,
        flags: *mut u32,
    ) -> c_int;
}

#[link(name = "mswsock")]
unsafe extern "system" {
    pub fn AcceptEx(
        listener: RawSocket,
        accepted: RawSocket,
        output: *mut c_void,
        receive_length: u32,
        local_length: u32,
        remote_length: u32,
        received: *mut u32,
        overlapped: *mut Overlapped,
    ) -> c_int;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn CreateIoCompletionPort(file: Handle, port: Handle, key: usize, threads: u32) -> Handle;
    pub fn GetQueuedCompletionStatusEx(
        port: Handle,
        entries: *mut OverlappedEntry,
        count: u32,
        removed: *mut u32,
        milliseconds: u32,
        alertable: c_int,
    ) -> c_int;
    pub fn PostQueuedCompletionStatus(port: Handle, bytes: u32, key: usize, overlapped: *mut c_void) -> c_int;
    pub fn SetHandleInformation(object: Handle, mask: u32, flags: u32) -> c_int;
    pub fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> c_int;
}

#[cfg_attr(target_arch = "x86", link(name = "bcryptprimitives", kind = "raw-dylib", import_name_type = "undecorated"))]
#[cfg_attr(not(target_arch = "x86"), link(name = "bcryptprimitives", kind = "raw-dylib"))]
unsafe extern "system" {
    pub fn ProcessPrng(data: *mut u8, length: usize) -> c_int;
}

/// The constants of the declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Windows;

impl Windows {
    pub const AF_INET: c_int = 2;
    pub const AF_INET6: c_int = 23;
    pub const SOCK_STREAM: c_int = 1;
    pub const SOCK_DGRAM: c_int = 2;
    pub const SOCK_RAW: c_int = 3;
    pub const SOL_SOCKET: c_int = 0xFFFF;
    pub const SO_REUSEADDR: c_int = 0x0004;
    pub const SO_EXCLUSIVEADDRUSE: c_int = !0x0004;
    pub const SO_KEEPALIVE: c_int = 0x0008;
    pub const SO_BROADCAST: c_int = 0x0020;
    pub const SO_SNDBUF: c_int = 0x1001;
    pub const SO_RCVBUF: c_int = 0x1002;
    pub const SO_ERROR: c_int = 0x1007;
    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    pub const IP_TTL: c_int = 4;
    pub const IPV6_V6ONLY: c_int = 27;
    pub const TCP_NODELAY: c_int = 1;
    pub const SD_RECEIVE: c_int = 0;
    pub const SD_SEND: c_int = 1;
    pub const SD_BOTH: c_int = 2;
    pub const INVALID_SOCKET: RawSocket = !0;
    pub const SOCKET_ERROR: c_int = -1;
    /// `_IOW('f', 126, u_long)`.
    pub const FIONBIO: i32 = 0x8004_667Eu32 as i32;
    pub const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    pub const HANDLE_FLAG_INHERIT: u32 = 0x01;
    pub const WSA_IO_PENDING: i32 = 997;
    pub const ERROR_OPERATION_ABORTED: i32 = 995;
    pub const SO_UPDATE_ACCEPT_CONTEXT: c_int = 0x700B;
    pub const SO_UPDATE_CONNECT_CONTEXT: c_int = 0x7010;
    /// `_WSAIORW(IOC_WS2, 6)`.
    pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    /// `_WSAIOW(IOC_VENDOR, 12)` (mswsock.h): whether an ICMP port
    /// unreachable fails the next receive of a UDP socket.
    pub const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    pub const WSAEMSGSIZE: i32 = 10040;
    /// `WSAID_CONNECTEX`.
    pub const WSAID_CONNECTEX: GUID = GUID {
        data1: 0x25a2_07b9,
        data2: 0xddf3,
        data3: 0x4660,
        data4: [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
    };
    /// The room AcceptEx needs for each address: `SOCKADDR_STORAGE` plus 16 bytes.
    pub const ACCEPT_ADDRESS_LENGTH: usize = 128 + 16;
    /// `FROM_PROTOCOL_INFO`: the family, type and protocol of the protocol information given.
    pub const FROM_PROTOCOL_INFO: c_int = -1;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const WSAEINVAL: i32 = 10022;
    pub const INFINITE: u32 = u32::MAX;
    pub const WAIT_TIMEOUT: i32 = 258;
    /// The size of `WSAPROTOCOL_INFOW`.
    pub const PROTOCOL_INFO_SIZE: usize = 628;
    /// The size of `SOCKADDR_STORAGE`.
    pub const SOCKADDR_STORAGE: usize = 128;
    /// The Winsock version asked for (2.2).
    pub const WINSOCK_VERSION: u16 = 0x0202;
}
