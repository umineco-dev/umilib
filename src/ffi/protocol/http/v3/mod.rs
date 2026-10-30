//! The C ABI of [`crate::protocol::http::v3`].
//!
//! An HTTP/3 connection is a handle of its state ([`H3Connection`]); its
//! QUIC connection is one of an endpoint of [`crate::ffi::protocol::quic`],
//! named by the endpoint and the connection's number in every call, as an
//! [`H3Session`] joins the two. The configuration is a structure. Times are
//! nanoseconds of the caller's monotonic clock (`now`), the endpoint's.

use crate::ffi::protocol::http::{FFIHTTPConnection, FFIHTTPEvent};
use crate::ffi::protocol::quic::{FFIQUICEvent, QUICStatus};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::protocol::http::v3::{H3Config, H3Connection, H3Session};
use crate::protocol::http::{HTTPConnection, HTTPFields, HTTPRequest, HTTPResponse};
use crate::protocol::quic::QUICEndpoint;
use crate::runtime::Instant;

/// The [`H3Session`] of the calls of this module.
pub struct FFIH3Session;

impl FFIH3Session {
    /// Calls `call` with the session of `connection` and the QUIC connection `quic` of `endpoint`.
    ///
    /// # Safety
    /// As [`Pointer::reference_mut`].
    pub unsafe fn with(
        connection: *mut H3Connection,
        endpoint: *mut QUICEndpoint,
        quic: u64,
        call: impl FnOnce(&mut H3Session<'_>) -> Result<(), &'static Status>,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let connection = unsafe { Pointer::reference_mut(connection) }?;
        let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
        let quic = QUICStatus::connection(endpoint, quic)?;
        call(&mut H3Session::new(connection, quic))
    }
}

impl Value for H3Config {
    const TYPE: Type = Type::Named("umilib_protocol_http_v3_H3Config");
}

impl Value for H3Connection {
    const TYPE: Type = Type::Named("umilib_protocol_http_v3_H3Connection");
}

crate::ffi_functions! {
    /// Writes the default configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_config_default(out: *mut H3Config) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, H3Config::default()) })
    }

    /// Writes the state of a client's connection of `config`, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_client(config: H3Config, now: u64, out: *mut *mut H3Connection) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, H3Connection::client(config, Instant::from_nanos(now))) })
    }

    /// Writes the state of a server's connection of `config`, opened at `now`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_server(config: H3Config, now: u64, out: *mut *mut H3Connection) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, H3Connection::server(config, Instant::from_nanos(now))) })
    }

    /// Releases a connection's state. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_free(connection: *mut H3Connection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Handles what the QUIC connection `quic` of `endpoint` received, at `now`: call it after the endpoint takes datagrams and fires timers.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_process(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, now: u64) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                session.process(Instant::from_nanos(now));
                Ok(())
            })
        })
    }

    /// A client starts an exchange with `request`, which has no content if `end`; writes its stream into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_send_request(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, request: *const HTTPRequest, end: bool, out: *mut u64) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::send_request(session, request, end, out)
            })
        })
    }

    /// A server answers `stream` with `response` (interim ones first), with no content if `end`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_send_response(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, response: *const HTTPResponse, end: bool) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::send_response(session, stream, response, end)
            })
        })
    }

    /// Writes the `length` bytes at `data` as content of `stream`, the last if `end`; writes how many were taken into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_send_data(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, data: *const u8, length: usize, end: bool, out: *mut usize) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::send_data(session, stream, data, length, end, out)
            })
        })
    }

    /// Ends the message of `stream` with the trailer section `trailers`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_send_trailers(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, trailers: *const HTTPFields) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::send_trailers(session, stream, trailers)
            })
        })
    }

    /// Reads up to `capacity` bytes of content of `stream` into `out`; writes how many into `out_count`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_read_data(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, out: *mut u8, capacity: usize, out_count: *mut usize) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::read_data(session, stream, out, capacity, out_count)
            })
        })
    }

    /// Abandons `stream` for `reason` (0 Cancel, 1 Refused, 2 Internal, 3 NoError).
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_reset(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, stream: u64, reason: u8) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::reset(session, stream, reason)
            })
        })
    }

    /// Writes whether an event is pending into `out_found` and the event into `out`; the request
    /// of a Request, the response of a Response and the fields of Trailers into `out_request`,
    /// `out_response` and `out_fields` (null otherwise), which the caller releases.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_poll_event(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, out_found: *mut bool, out: *mut FFIHTTPEvent, out_request: *mut *mut HTTPRequest, out_response: *mut *mut HTTPResponse, out_fields: *mut *mut HTTPFields) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::poll_event(session, out_found, out, out_request, out_response, out_fields)
            })
        })
    }

    /// Takes no new exchanges: those under way finish, then the connection closes.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_shutdown(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                HTTPConnection::shutdown(session);
                Ok(())
            })
        })
    }

    /// Writes whether the connection is closed into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_is_closed(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                Pointer::write(out, HTTPConnection::is_closed(session))
            })
        })
    }

    /// Writes the major and minor numbers of the version (3 and 0) into `out_major` and `out_minor`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_version(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, out_major: *mut u8, out_minor: *mut u8) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                FFIHTTPConnection::version(session, out_major, out_minor)
            })
        })
    }

    /// Writes whether the QUIC connection has an event HTTP/3 does not handle (a DATAGRAM, say)
    /// into `out_found`, the event into `out` and its bytes into `out_bytes`.
    pub unsafe extern "C" fn umilib_protocol_http_v3_h3_connection_poll_quic_event(connection: *mut H3Connection, endpoint: *mut QUICEndpoint, quic: u64, out_found: *mut bool, out: *mut FFIQUICEvent, out_bytes: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes valid handles, readable memory and writable pointers.
        Status::from_result(unsafe {
            FFIH3Session::with(connection, endpoint, quic, |session| {
                Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
                Pointer::check_range(out_found, 1)?;
                Pointer::check_range(out, 1)?;
                Pointer::check_range(out_bytes, 1)?;
                let event = session.poll_quic_event();
                Pointer::write(out_found, event.is_some())?;
                let (structure, bytes) = event.map(FFIQUICEvent::of).unwrap_or_default();
                Pointer::write(out, structure)?;
                Pointer::write(out_bytes, Buffer::from_vec(bytes))
            })
        })
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v3",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_http_v3_H3Config",
            documentation: " The configuration of HTTP/3 connections.",
            fields: &[
                Parameter { name: "http", value: <crate::protocol::http::HTTPConfig as Value>::TYPE },
                Parameter { name: "qpack_encoder", value: <crate::codec::qpack::QPACKEncoderConfig as Value>::TYPE },
                Parameter { name: "qpack_decoder", value: <crate::codec::qpack::QPACKDecoderConfig as Value>::TYPE },
                Parameter { name: "enable_connect_protocol", value: <bool as Value>::TYPE },
                Parameter { name: "grease", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_http_v3_H3Connection",
            documentation: " The state of an HTTP/3 connection over a QUIC connection.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
