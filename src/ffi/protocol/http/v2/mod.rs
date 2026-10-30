//! The C ABI of [`crate::protocol::http::v2`].
//!
//! A connection is a handle; its configuration a structure, timeouts in
//! milliseconds with 0 for none. Times are nanoseconds of the caller's
//! monotonic clock (`now`). The functions every version's connection has
//! are those of [`crate::ffi::protocol::http`]'s `ffi_http_connection!`.

use alloc::vec::Vec;
use core::time::Duration;

use crate::codec::hpack::{HPACKDecoderConfig, HPACKEncoderConfig};
use crate::ffi::protocol::http::FFIHTTPTimeout;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::protocol::http::HTTPConfig;
use crate::protocol::http::v2::{H2Config, H2Connection};
use crate::runtime::Instant;

/// An [`H2Config`], durations in milliseconds (0 for no timeout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIH2Config {
    pub http: HTTPConfig,
    pub hpack_encoder: HPACKEncoderConfig,
    pub hpack_decoder: HPACKDecoderConfig,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub connection_window: u32,
    pub max_frame_size: u32,
    pub enable_connect_protocol: bool,
    pub settings_timeout: u64,
    pub idle_timeout: u64,
    pub maximum_resets: u32,
    pub reset_window: u64,
    pub maximum_pending_control: usize,
    pub maximum_field_block: usize,
}

impl FFIH2Config {
    pub fn of(config: &H2Config) -> FFIH2Config {
        FFIH2Config {
            http: config.http,
            hpack_encoder: config.hpack_encoder,
            hpack_decoder: config.hpack_decoder,
            max_concurrent_streams: config.max_concurrent_streams,
            initial_window_size: config.initial_window_size,
            connection_window: config.connection_window,
            max_frame_size: config.max_frame_size,
            enable_connect_protocol: config.enable_connect_protocol,
            settings_timeout: FFIHTTPTimeout::milliseconds(config.settings_timeout),
            idle_timeout: FFIHTTPTimeout::milliseconds(config.idle_timeout),
            maximum_resets: config.maximum_resets,
            reset_window: config.reset_window.as_millis() as u64,
            maximum_pending_control: config.maximum_pending_control,
            maximum_field_block: config.maximum_field_block,
        }
    }

    pub fn config(&self) -> H2Config {
        H2Config {
            http: self.http,
            hpack_encoder: self.hpack_encoder,
            hpack_decoder: self.hpack_decoder,
            max_concurrent_streams: self.max_concurrent_streams,
            initial_window_size: self.initial_window_size,
            connection_window: self.connection_window,
            max_frame_size: self.max_frame_size,
            enable_connect_protocol: self.enable_connect_protocol,
            settings_timeout: FFIHTTPTimeout::timeout(self.settings_timeout),
            idle_timeout: FFIHTTPTimeout::timeout(self.idle_timeout),
            maximum_resets: self.maximum_resets,
            reset_window: Duration::from_millis(self.reset_window),
            maximum_pending_control: self.maximum_pending_control,
            maximum_field_block: self.maximum_field_block,
        }
    }

    /// # Safety
    /// As [`Pointer::reference`] and [`Pointer::write_handle`].
    pub unsafe fn connection(
        config: *const FFIH2Config,
        server: bool,
        now: u64,
        out: *mut *mut H2Connection,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let config = unsafe { Pointer::reference(config) }?.config();
        let now = Instant::from_nanos(now);
        let connection = if server { H2Connection::server(config, now) } else { H2Connection::client(config, now) };
        unsafe { Pointer::write_handle(out, connection) }
    }
}

impl Value for FFIH2Config {
    const TYPE: Type = Type::Named("umilib_protocol_http_v2_H2Config");
}

impl Value for H2Connection {
    const TYPE: Type = Type::Named("umilib_protocol_http_v2_H2Connection");
}

crate::ffi_http_connection! {
    H2Connection;
    umilib_protocol_http_v2_h2_connection_send_request,
    umilib_protocol_http_v2_h2_connection_send_response,
    umilib_protocol_http_v2_h2_connection_send_data,
    umilib_protocol_http_v2_h2_connection_send_trailers,
    umilib_protocol_http_v2_h2_connection_read_data,
    umilib_protocol_http_v2_h2_connection_reset,
    umilib_protocol_http_v2_h2_connection_poll_event,
    umilib_protocol_http_v2_h2_connection_shutdown,
    umilib_protocol_http_v2_h2_connection_is_closed,
    umilib_protocol_http_v2_h2_connection_version;

    /// Writes the default configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_config_default(out: *mut FFIH2Config) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, FFIH2Config::of(&H2Config::default())) })
    }

    /// Writes a client's connection of `config`, opened at `now`, into `out`; it sends the preface first.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_client(config: *const FFIH2Config, now: u64, out: *mut *mut H2Connection) -> *const Status {
        // SAFETY: the caller passes a valid structure and a writable pointer.
        Status::from_result(unsafe { FFIH2Config::connection(config, false, now, out) })
    }

    /// Writes a server's connection of `config`, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_server(config: *const FFIH2Config, now: u64, out: *mut *mut H2Connection) -> *const Status {
        // SAFETY: the caller passes a valid structure and a writable pointer.
        Status::from_result(unsafe { FFIH2Config::connection(config, true, now, out) })
    }

    /// Releases a connection. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_free(connection: *mut H2Connection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Takes the `length` bytes at `bytes` that arrived at `now`.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_receive(connection: *mut H2Connection, bytes: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            connection.receive(bytes, Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Takes the end of the byte stream from the peer.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_receive_close(connection: *mut H2Connection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.receive_close();
            Ok(())
        })())
    }

    /// Writes the bytes to send into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_transmit(connection: *mut H2Connection, out: *mut Buffer) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_wants_close(connection: *const H2Connection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_close()) }
        })())
    }

    /// Writes whether to read more from the transport into `out`: false while events wait up to their limit.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_wants_receive(connection: *const H2Connection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_receive()) }
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_poll_timeout(connection: *const H2Connection, out_found: *mut bool, out: *mut u64) -> *const Status {
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
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_expire(connection: *mut H2Connection, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.expire(Instant::from_nanos(now));
            Ok(())
        })())
    }

    /// Sends a PING of the 8 bytes at `data` (RFC 9113 §6.7).
    pub unsafe extern "C" fn umilib_protocol_http_v2_h2_connection_ping(connection: *mut H2Connection, data: *const u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and 8 readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let data = unsafe { Pointer::slice(data, 8) }?;
            connection.ping(data.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?);
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v2",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_http_v2_H2Config",
            documentation: " The configuration of HTTP/2 connections; durations in milliseconds, 0 for no timeout.",
            fields: &[
                Parameter { name: "http", value: <HTTPConfig as Value>::TYPE },
                Parameter { name: "hpack_encoder", value: <HPACKEncoderConfig as Value>::TYPE },
                Parameter { name: "hpack_decoder", value: <HPACKDecoderConfig as Value>::TYPE },
                Parameter { name: "max_concurrent_streams", value: <u32 as Value>::TYPE },
                Parameter { name: "initial_window_size", value: <u32 as Value>::TYPE },
                Parameter { name: "connection_window", value: <u32 as Value>::TYPE },
                Parameter { name: "max_frame_size", value: <u32 as Value>::TYPE },
                Parameter { name: "enable_connect_protocol", value: <bool as Value>::TYPE },
                Parameter { name: "settings_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "idle_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_resets", value: <u32 as Value>::TYPE },
                Parameter { name: "reset_window", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_pending_control", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_field_block", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_http_v2_H2Connection",
            documentation: " An HTTP/2 connection without I/O.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
