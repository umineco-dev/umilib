//! The C ABI of [`crate::protocol::http::v1`].
//!
//! A connection is a handle; its limits a structure, timeouts in
//! milliseconds with 0 for none. Times are nanoseconds of the caller's
//! monotonic clock (`now`). The functions of every version's connection are
//! those of [`crate::ffi::protocol::http`]'s `ffi_http_connection!`.

use alloc::vec::Vec;

use crate::ffi::protocol::http::FFIHTTPTimeout;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::protocol::http::HTTPConfig;
use crate::protocol::http::v1::{H1Config, H1Connection};
use crate::runtime::Instant;

/// The limits of an [`H1Config`]: every field but the scheme, timeouts in
/// milliseconds (0 for none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIH1Limits {
    pub http: HTTPConfig,
    pub maximum_pipelined: usize,
    pub maximum_chunk_line: usize,
    pub idle_timeout: u64,
    pub head_timeout: u64,
    pub continue_automatically: bool,
}

impl FFIH1Limits {
    pub fn of(config: &H1Config) -> FFIH1Limits {
        FFIH1Limits {
            http: config.http,
            maximum_pipelined: config.maximum_pipelined,
            maximum_chunk_line: config.maximum_chunk_line,
            idle_timeout: FFIHTTPTimeout::milliseconds(config.idle_timeout),
            head_timeout: FFIHTTPTimeout::milliseconds(config.head_timeout),
            continue_automatically: config.continue_automatically,
        }
    }

    /// The configuration of these limits and `scheme`.
    pub fn config(&self, scheme: &[u8]) -> H1Config {
        H1Config {
            http: self.http,
            scheme: scheme.to_ascii_lowercase(),
            maximum_pipelined: self.maximum_pipelined,
            maximum_chunk_line: self.maximum_chunk_line,
            idle_timeout: FFIHTTPTimeout::timeout(self.idle_timeout),
            head_timeout: FFIHTTPTimeout::timeout(self.head_timeout),
            continue_automatically: self.continue_automatically,
        }
    }

    /// # Safety
    /// As [`Pointer::reference`], [`Pointer::slice`] and [`Pointer::write_handle`].
    pub unsafe fn connection(
        limits: *const FFIH1Limits,
        scheme: *const u8,
        length: usize,
        server: bool,
        now: u64,
        out: *mut *mut H1Connection,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let limits = unsafe { Pointer::reference(limits) }?;
        let scheme = unsafe { Pointer::slice(scheme, length) }?;
        let config = limits.config(scheme);
        let now = Instant::from_nanos(now);
        let connection = if server { H1Connection::server(config, now) } else { H1Connection::client(config, now) };
        unsafe { Pointer::write_handle(out, connection) }
    }
}

impl Value for FFIH1Limits {
    const TYPE: Type = Type::Named("umilib_protocol_http_v1_H1Limits");
}

impl Value for H1Connection {
    const TYPE: Type = Type::Named("umilib_protocol_http_v1_H1Connection");
}

crate::ffi_http_connection! {
    H1Connection;
    umilib_protocol_http_v1_h1_connection_send_request,
    umilib_protocol_http_v1_h1_connection_send_response,
    umilib_protocol_http_v1_h1_connection_send_data,
    umilib_protocol_http_v1_h1_connection_send_trailers,
    umilib_protocol_http_v1_h1_connection_read_data,
    umilib_protocol_http_v1_h1_connection_reset,
    umilib_protocol_http_v1_h1_connection_poll_event,
    umilib_protocol_http_v1_h1_connection_shutdown,
    umilib_protocol_http_v1_h1_connection_is_closed,
    umilib_protocol_http_v1_h1_connection_version;

    /// Writes the default limits into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_limits_default(out: *mut FFIH1Limits) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIH1Limits::of(&H1Config::default())) })
    }

    /// Writes a client's connection of `limits`, for requests over `scheme`, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_client(limits: *const FFIH1Limits, scheme: *const u8, length: usize, now: u64, out: *mut *mut H1Connection) -> *const Status {
        // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
        Status::from_result(unsafe { FFIH1Limits::connection(limits, scheme, length, false, now, out) })
    }

    /// Writes a server's connection of `limits`, whose requests in origin-form are of `scheme`, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_server(limits: *const FFIH1Limits, scheme: *const u8, length: usize, now: u64, out: *mut *mut H1Connection) -> *const Status {
        // SAFETY: the caller passes a valid structure, readable bytes and a writable pointer.
        Status::from_result(unsafe { FFIH1Limits::connection(limits, scheme, length, true, now, out) })
    }

    /// Releases a connection. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_free(connection: *mut H1Connection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Takes the `length` bytes at `bytes` that arrived at `now`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_receive(connection: *mut H1Connection, bytes: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            connection.receive(bytes, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Takes the end of the byte stream from the peer, at `now`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_receive_close(connection: *mut H1Connection, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.receive_close(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Writes whether the connection takes more bytes now into `out` (false while the application has not read what arrived).
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_wants_receive(connection: *const H1Connection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_receive()) }
        })())
    }

    /// Writes the bytes to send into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_transmit(connection: *mut H1Connection, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out, 1)?;
            let mut bytes = Vec::new();
            connection.transmit(&mut bytes);
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes whether the byte stream should be closed, once what was transmitted is sent, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_wants_close(connection: *const H1Connection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_close()) }
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_poll_timeout(connection: *const H1Connection, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let timeout = connection.poll_timeout();
            unsafe { Pointer::write(out_found, timeout.is_some()) }?;
            unsafe { Pointer::write(out, timeout.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Fires the timers due at `now`.
    pub unsafe extern "C" fn umilib_protocol_http_v1_h1_connection_expire(connection: *mut H1Connection, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v1",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_http_v1_H1Limits",
            documentation: " The limits of HTTP/1.1 connections; timeouts in milliseconds, 0 for none.",
            fields: &[
                Parameter { name: "http", value: <HTTPConfig as Value>::TYPE },
                Parameter { name: "maximum_pipelined", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_chunk_line", value: <usize as Value>::TYPE },
                Parameter { name: "idle_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "head_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "continue_automatically", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_http_v1_H1Connection",
            documentation: " An HTTP/1.1 connection without I/O.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
