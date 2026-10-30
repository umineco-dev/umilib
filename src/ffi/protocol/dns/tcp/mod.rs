//! The C ABI of [`crate::protocol::dns::tcp`].
//!
//! A framer and a server's connection are handles; the connection answers
//! with an authoritative server of [`crate::ffi::protocol::dns`]. Times are
//! nanoseconds of the caller's monotonic clock (`now`) and, for cookies,
//! seconds since 1970 (`time`); durations milliseconds.

use core::time::Duration;

use crate::ffi::protocol::ip::FFIIPEndpoint;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dns::tcp::{DNSTCPFramer, DNSTCPServer, DNSTCPServerConfig};
use crate::protocol::dns::{DNSAuthority, DNSPeer, DNSTransport};
use crate::runtime::Instant;

impl Value for DNSTCPFramer {
    const TYPE: Type = Type::Named("umilib_protocol_dns_tcp_DNSTCPFramer");
}

impl Value for DNSTCPServer {
    const TYPE: Type = Type::Named("umilib_protocol_dns_tcp_DNSTCPServer");
}

crate::ffi_functions! {
    /// Writes the `length` bytes at `message` after their length in two bytes (RFC 1035 §4.2.2) into
    /// `out`; fails with TooLarge above 65535 bytes.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_framer_frame(message: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let message = unsafe { Pointer::slice(message, length) }?;
            let framed = DNSTCPFramer::frame(message).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(framed)) }
        })())
    }

    /// Writes a framer of nothing received into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_framer_new(out: *mut *mut DNSTCPFramer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, DNSTCPFramer::new()) })
    }

    /// Releases a framer. Does nothing if `framer` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_framer_free(framer: *mut DNSTCPFramer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(framer) }
    }

    /// Takes the `length` bytes at `bytes` of the stream.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_framer_receive(framer: *mut DNSTCPFramer, bytes: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let framer = unsafe { Pointer::reference_mut(framer) }?;
            framer.receive(unsafe { Pointer::slice(bytes, length) }?);
            Ok(())
        })())
    }

    /// Writes whether a whole message is received into `out_found` and the message into `out`; fails
    /// with Malformed for a length of 0.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_framer_next_message(framer: *mut DNSTCPFramer, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let framer = unsafe { Pointer::reference_mut(framer) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let message = framer.next_message().transpose().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, message.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(message.unwrap_or_default())) }
        })())
    }

    /// Writes a server's connection with `peer`, idle after `idle_timeout` milliseconds and after
    /// `read_timeout` with a query partly received, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_server_new(peer: FFIIPEndpoint, idle_timeout: u32, read_timeout: u32, now: u64, out: *mut *mut DNSTCPServer) -> *const Status {
        Status::from_result((|| {
            let peer = DNSPeer { endpoint: peer.endpoint()?, transport: DNSTransport::TCP };
            let config = DNSTCPServerConfig {
                idle_timeout: Duration::from_millis(u64::from(idle_timeout)),
                read_timeout: Duration::from_millis(u64::from(read_timeout)),
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, DNSTCPServer::new(config, peer, Instant::from_nanos(now))) }
        })())
    }

    /// Releases a server's connection. Does nothing if `server` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_server_free(server: *mut DNSTCPServer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(server) }
    }

    /// Takes the `length` bytes at `bytes` of the stream and answers each whole query with
    /// `authority` at `now` and `time`; fails with Malformed for a length of 0, which ends the connection.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_server_receive(server: *mut DNSTCPServer, bytes: *const u8, length: usize, authority: *const DNSAuthority, now: u64, time: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and readable bytes.
            let server = unsafe { Pointer::reference_mut(server) }?;
            let authority = unsafe { Pointer::reference(authority) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            server.receive(bytes, authority, Instant::from_nanos(now), time).map_err(|error| error.to_status())
        })())
    }

    /// Writes the bytes to send into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_server_transmit(server: *mut DNSTCPServer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference_mut(server) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(server.transmit())) }
        })())
    }

    /// Writes whether the connection should be closed at `now` into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_tcp_dns_tcp_server_is_idle(server: *const DNSTCPServer, now: u64, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let server = unsafe { Pointer::reference(server) }?;
            unsafe { Pointer::write(out, server.is_idle(Instant::from_nanos(now))) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "tcp",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_dns_tcp_DNSTCPFramer",
            documentation: " The framing of DNS messages on a stream.",
        },
        Definition::Opaque {
            name: "umilib_protocol_dns_tcp_DNSTCPServer",
            documentation: " A server's connection over TCP.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
