//! The C ABI of [`crate::protocol::http`].
//!
//! Fields, requests, responses and rules are handles; [`HTTPConfig`] and an
//! event are structures. Text crosses as bytes with their length; a pattern
//! of a rule as the text of [`Pattern::parse`]. The connections of each
//! version are handles of the version's module, whose functions of the
//! common interface ([`HTTPConnection`]) call [`FFIHTTPConnection`], so
//! every version behaves alike.

#[cfg(umilib_feature = "protocol-http-v1")]
pub mod v1;
#[cfg(umilib_feature = "protocol-http-v2")]
pub mod v2;
#[cfg(umilib_feature = "protocol-http-v3")]
pub mod v3;
#[cfg(umilib_feature = "protocol-http-websocket")]
pub mod websocket;

use alloc::vec::Vec;
use core::time::Duration;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::http::{
    HTTPConfig, HTTPConnection, HTTPError, HTTPEvent, HTTPFields, HTTPMethod, HTTPRequest, HTTPReset, HTTPResponse,
    HTTPRule, HTTPStatus, HTTPStreamID,
};
use crate::service::{Pattern, Rule};

/// The statuses of [`HTTPError`], one per variant, and of the arguments of this module.
pub struct HTTPErrorStatus;

impl HTTPErrorStatus {
    pub const MALFORMED: Status = Status::new(c"protocol.http", c"Malformed", c"the message breaks the rules of HTTP");
    pub const TOO_LARGE: Status =
        Status::new(c"protocol.http", c"TooLarge", c"the message is larger than this end takes");
    pub const CONTENT_CODING: Status = Status::new(
        c"protocol.http",
        c"ContentCoding",
        c"a content coding not supported, or content that does not decode",
    );
    pub const PROTOCOL: Status =
        Status::new(c"protocol.http", c"Protocol", c"a rule of the version's protocol is broken");
    pub const STATE: Status = Status::new(c"protocol.http", c"State", c"the connection's state does not allow it");
    pub const CONFIG: Status = Status::new(c"protocol.http", c"Config", c"the HTTP configuration cannot work");
    pub const INVALID_PATTERN: Status = Status::new(c"protocol.http", c"InvalidPattern", c"not the text of a pattern");
    pub const NO_SUCH_FIELD: Status =
        Status::new(c"protocol.http", c"NoSuchField", c"the fields have none of that index");

    /// The pattern of the `length` bytes of text at `text`.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn pattern(text: *const u8, length: usize) -> Result<Pattern, &'static Status> {
        // SAFETY: the caller's promise.
        let text = unsafe { Pointer::slice(text, length) }?;
        Pattern::parse(text).map_err(|_| &HTTPErrorStatus::INVALID_PATTERN)
    }

    /// The bytes at `data` (`length` of them), or none if `data` is null.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn optional(data: *const u8, length: usize) -> Result<Option<Vec<u8>>, &'static Status> {
        match data.is_null() {
            true => Ok(None),
            // SAFETY: the caller's promise.
            false => Ok(Some(unsafe { Pointer::slice(data, length) }?.to_vec())),
        }
    }
}

impl ToStatus for HTTPError {
    fn to_status(&self) -> &'static Status {
        match self {
            HTTPError::Malformed(_) => &HTTPErrorStatus::MALFORMED,
            HTTPError::TooLarge(_) => &HTTPErrorStatus::TOO_LARGE,
            HTTPError::ContentCoding(_) => &HTTPErrorStatus::CONTENT_CODING,
            HTTPError::Protocol { .. } => &HTTPErrorStatus::PROTOCOL,
            HTTPError::State => &HTTPErrorStatus::STATE,
            HTTPError::Config => &HTTPErrorStatus::CONFIG,
        }
    }
}

/// A timeout across the C ABI: milliseconds, 0 for none.
pub struct FFIHTTPTimeout;

impl FFIHTTPTimeout {
    /// The milliseconds of `timeout` (at least 1), 0 for none.
    pub fn milliseconds(timeout: Option<Duration>) -> u64 {
        timeout.map_or(0, |timeout| (timeout.as_millis() as u64).max(1))
    }

    /// The timeout of `milliseconds`, none for 0.
    pub fn timeout(milliseconds: u64) -> Option<Duration> {
        (milliseconds != 0).then(|| Duration::from_millis(milliseconds))
    }
}

/// An [`HTTPEvent`]: `kind` the number of its variant (0 Request, 1
/// Response, 2 Data, 3 Trailers, 4 End, 5 Reset, 6 Writable, 7 GoAway, 8
/// Closed), its stream (the last one of GoAway), whether a head ends its
/// message (`end`), the version's error code of Reset or of a Protocol
/// error, and the error a Closed event reports as the number of its
/// [`HTTPError`] variant plus one (0 when it closed cleanly: 1 Malformed, 2
/// TooLarge, 3 ContentCoding, 4 Protocol, 5 State, 6 Config). The request,
/// response or trailer fields go in handles of their own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIHTTPEvent {
    pub kind: u8,
    pub stream: u64,
    pub end: bool,
    pub code: u64,
    pub error: u8,
}

impl FFIHTTPEvent {
    /// The number of `error` in [`FFIHTTPEvent::error`] and its code.
    pub fn error_of(error: &HTTPError) -> (u8, u64) {
        match error {
            HTTPError::Malformed(_) => (1, 0),
            HTTPError::TooLarge(_) => (2, 0),
            HTTPError::ContentCoding(_) => (3, 0),
            HTTPError::Protocol { code, .. } => (4, *code),
            HTTPError::State => (5, 0),
            HTTPError::Config => (6, 0),
        }
    }
}

/// The functions of [`HTTPConnection`] across the C ABI, which each
/// version's module calls with its connection.
pub struct FFIHTTPConnection;

impl FFIHTTPConnection {
    /// The reason of number `reason`: 0 Cancel, 1 Refused, 2 Internal, 3 NoError.
    pub fn reset_of(reason: u8) -> Result<HTTPReset, &'static Status> {
        match reason {
            0 => Ok(HTTPReset::Cancel),
            1 => Ok(HTTPReset::Refused),
            2 => Ok(HTTPReset::Internal),
            3 => Ok(HTTPReset::NoError),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// # Safety
    /// As [`Pointer::reference`] and [`Pointer::write`].
    pub unsafe fn send_request(
        connection: &mut dyn HTTPConnection,
        request: *const HTTPRequest,
        end: bool,
        out: *mut u64,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let request = unsafe { Pointer::reference(request) }?;
        Pointer::check_range(out, 1)?;
        let stream = connection.send_request(request, end).map_err(|error| error.to_status())?;
        unsafe { Pointer::write(out, stream.0) }
    }

    /// # Safety
    /// As [`Pointer::reference`].
    pub unsafe fn send_response(
        connection: &mut dyn HTTPConnection,
        stream: u64,
        response: *const HTTPResponse,
        end: bool,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let response = unsafe { Pointer::reference(response) }?;
        connection.send_response(HTTPStreamID(stream), response, end).map_err(|error| error.to_status())
    }

    /// # Safety
    /// As [`Pointer::slice`] and [`Pointer::write`].
    pub unsafe fn send_data(
        connection: &mut dyn HTTPConnection,
        stream: u64,
        data: *const u8,
        length: usize,
        end: bool,
        out: *mut usize,
    ) -> Result<(), &'static Status> {
        Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
        // SAFETY: the caller's promise.
        let data = unsafe { Pointer::slice(data, length) }?;
        Pointer::check_range(out, 1)?;
        let count = connection.send_data(HTTPStreamID(stream), data, end).map_err(|error| error.to_status())?;
        unsafe { Pointer::write(out, count) }
    }

    /// # Safety
    /// As [`Pointer::reference`].
    pub unsafe fn send_trailers(
        connection: &mut dyn HTTPConnection,
        stream: u64,
        trailers: *const HTTPFields,
    ) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        let trailers = unsafe { Pointer::reference(trailers) }?;
        connection.send_trailers(HTTPStreamID(stream), trailers).map_err(|error| error.to_status())
    }

    /// # Safety
    /// As [`Pointer::slice_mut`] and [`Pointer::write`].
    pub unsafe fn read_data(
        connection: &mut dyn HTTPConnection,
        stream: u64,
        out: *mut u8,
        capacity: usize,
        out_count: *mut usize,
    ) -> Result<(), &'static Status> {
        Pointer::check_ranges(&[], &[Pointer::range(out, capacity), Pointer::range(out_count, 1)])?;
        // SAFETY: the caller's promise.
        let out = unsafe { Pointer::slice_mut(out, capacity) }?;
        Pointer::check_range(out_count, 1)?;
        let count = connection.read_data(HTTPStreamID(stream), out).map_err(|error| error.to_status())?;
        unsafe { Pointer::write(out_count, count) }
    }

    pub fn reset(connection: &mut dyn HTTPConnection, stream: u64, reason: u8) -> Result<(), &'static Status> {
        let reason = FFIHTTPConnection::reset_of(reason)?;
        connection.reset(HTTPStreamID(stream), reason).map_err(|error| error.to_status())
    }

    /// Writes the next event, if any: see [`FFIHTTPEvent`]; the request of
    /// Request, the response of Response and the fields of Trailers go into
    /// `out_request`, `out_response` and `out_fields`, the others null.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn poll_event(
        connection: &mut dyn HTTPConnection,
        out_found: *mut bool,
        out: *mut FFIHTTPEvent,
        out_request: *mut *mut HTTPRequest,
        out_response: *mut *mut HTTPResponse,
        out_fields: *mut *mut HTTPFields,
    ) -> Result<(), &'static Status> {
        for range in [
            out_found as *const u8,
            out as *const u8,
            out_request as *const u8,
            out_response as *const u8,
            out_fields as *const u8,
        ] {
            Pointer::check_range(range, 1)?;
        }
        Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
        let event = connection.poll_event();
        let mut structure = FFIHTTPEvent::default();
        let (mut request, mut response, mut fields) =
            (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
        match &event {
            None => {}
            Some(HTTPEvent::Request { stream, request: head, end }) => {
                (structure.kind, structure.stream, structure.end) = (0, stream.0, *end);
                request = Pointer::into_handle(head.clone());
            }
            Some(HTTPEvent::Response { stream, response: head, end }) => {
                (structure.kind, structure.stream, structure.end) = (1, stream.0, *end);
                response = Pointer::into_handle(head.clone());
            }
            Some(HTTPEvent::Data { stream }) => (structure.kind, structure.stream) = (2, stream.0),
            Some(HTTPEvent::Trailers { stream, fields: trailers }) => {
                (structure.kind, structure.stream) = (3, stream.0);
                fields = Pointer::into_handle(trailers.clone());
            }
            Some(HTTPEvent::End { stream }) => (structure.kind, structure.stream) = (4, stream.0),
            Some(HTTPEvent::Reset { stream, code }) => {
                (structure.kind, structure.stream, structure.code) = (5, stream.0, *code)
            }
            Some(HTTPEvent::Writable { stream }) => (structure.kind, structure.stream) = (6, stream.0),
            Some(HTTPEvent::GoAway { last }) => (structure.kind, structure.stream) = (7, last.0),
            Some(HTTPEvent::Closed { error }) => {
                structure.kind = 8;
                if let Some(error) = error {
                    (structure.error, structure.code) = FFIHTTPEvent::error_of(error);
                }
            }
        }
        // SAFETY: the caller's promise; every range was checked above.
        unsafe { Pointer::write(out_found, event.is_some()) }?;
        unsafe { Pointer::write(out, structure) }?;
        unsafe { Pointer::write(out_request, request) }?;
        unsafe { Pointer::write(out_response, response) }?;
        unsafe { Pointer::write(out_fields, fields) }
    }

    /// Writes the version's major and minor numbers into `out_major` and `out_minor`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn version(
        connection: &dyn HTTPConnection,
        out_major: *mut u8,
        out_minor: *mut u8,
    ) -> Result<(), &'static Status> {
        Pointer::check_ranges(&[], &[Pointer::range(out_major, 1), Pointer::range(out_minor, 1)])?;
        Pointer::check_range(out_major, 1)?;
        Pointer::check_range(out_minor, 1)?;
        let version = connection.version();
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out_major, version.major) }?;
        unsafe { Pointer::write(out_minor, version.minor) }
    }
}

/// Defines the exported functions of a version module, as
/// [`ffi_functions!`](crate::ffi_functions) does: its own functions (after
/// the second `;`), then those of [`HTTPConnection`] for its connection
/// type, with the names given, which call [`FFIHTTPConnection`].
#[macro_export]
macro_rules! ffi_http_connection {
    ($connection:ty; $send_request:ident, $send_response:ident, $send_data:ident, $send_trailers:ident, $read_data:ident, $reset:ident, $poll_event:ident, $shutdown:ident, $is_closed:ident, $version:ident; $($functions:tt)*) => {
        $crate::ffi_functions! {
            $($functions)*

            /// A client starts an exchange with `request`, which has no content if `end`; writes its stream into `out`.
            pub unsafe extern "C" fn $send_request(connection: *mut $connection, request: *const $crate::protocol::http::HTTPRequest, end: bool, out: *mut u64) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes valid handles and a writable pointer.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::send_request(connection, request, end, out) }
                })())
            }

            /// A server answers `stream` with `response` (interim ones first), with no content if `end`.
            pub unsafe extern "C" fn $send_response(connection: *mut $connection, stream: u64, response: *const $crate::protocol::http::HTTPResponse, end: bool) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes valid handles.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::send_response(connection, stream, response, end) }
                })())
            }

            /// Writes the `length` bytes at `data` as content of `stream`, the last if `end`; writes how many were taken into `out`.
            pub unsafe extern "C" fn $send_data(connection: *mut $connection, stream: u64, data: *const u8, length: usize, end: bool, out: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::send_data(connection, stream, data, length, end, out) }
                })())
            }

            /// Ends the message of `stream` with the trailer section `trailers`.
            pub unsafe extern "C" fn $send_trailers(connection: *mut $connection, stream: u64, trailers: *const $crate::protocol::http::HTTPFields) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes valid handles.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::send_trailers(connection, stream, trailers) }
                })())
            }

            /// Reads up to `capacity` bytes of content of `stream` into `out`; writes how many into `out_count`.
            pub unsafe extern "C" fn $read_data(connection: *mut $connection, stream: u64, out: *mut u8, capacity: usize, out_count: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and writable memory.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::read_data(connection, stream, out, capacity, out_count) }
                })())
            }

            /// Abandons `stream` for `reason` (0 Cancel, 1 Refused, 2 Internal, 3 NoError).
            pub unsafe extern "C" fn $reset(connection: *mut $connection, stream: u64, reason: u8) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    $crate::ffi::protocol::http::FFIHTTPConnection::reset(connection, stream, reason)
                })())
            }

            /// Writes whether an event is pending into `out_found` and the event into `out`; the request
            /// of a Request, the response of a Response and the fields of Trailers into `out_request`,
            /// `out_response` and `out_fields` (null otherwise), which the caller releases.
            pub unsafe extern "C" fn $poll_event(connection: *mut $connection, out_found: *mut bool, out: *mut $crate::ffi::protocol::http::FFIHTTPEvent, out_request: *mut *mut $crate::protocol::http::HTTPRequest, out_response: *mut *mut $crate::protocol::http::HTTPResponse, out_fields: *mut *mut $crate::protocol::http::HTTPFields) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and writable pointers.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::poll_event(connection, out_found, out, out_request, out_response, out_fields) }
                })())
            }

            /// Takes no new exchanges: those under way finish, then the connection closes.
            pub unsafe extern "C" fn $shutdown(connection: *mut $connection) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    let connection = unsafe { $crate::ffi::Pointer::reference_mut(connection) }?;
                    $crate::protocol::http::HTTPConnection::shutdown(connection);
                    Ok(())
                })())
            }

            /// Writes whether the connection is closed into `out`.
            pub unsafe extern "C" fn $is_closed(connection: *const $connection, out: *mut bool) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let connection = unsafe { $crate::ffi::Pointer::reference(connection) }?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::protocol::http::HTTPConnection::is_closed(connection)) }
                })())
            }

            /// Writes the major and minor numbers of the connection's version into `out_major` and `out_minor`.
            pub unsafe extern "C" fn $version(connection: *const $connection, out_major: *mut u8, out_minor: *mut u8) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and writable pointers.
                    let connection = unsafe { $crate::ffi::Pointer::reference(connection) }?;
                    unsafe { $crate::ffi::protocol::http::FFIHTTPConnection::version(connection, out_major, out_minor) }
                })())
            }
        }
    };
}

impl Value for HTTPConfig {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPConfig");
}

impl Value for FFIHTTPEvent {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPEvent");
}

impl Value for HTTPFields {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPFields");
}

impl Value for HTTPRequest {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPRequest");
}

impl Value for HTTPResponse {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPResponse");
}

impl Value for HTTPRule {
    const TYPE: Type = Type::Named("umilib_protocol_http_HTTPRule");
}

crate::ffi_functions! {
    /// Writes the default limits into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_config_default(out: *mut HTTPConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, HTTPConfig::default()) })
    }

    /// Writes the reason phrase of the status code `status` into `out` (empty if it has none).
    pub unsafe extern "C" fn umilib_protocol_http_http_status_reason(status: u16, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(HTTPStatus(status).reason().as_bytes().to_vec())) })
    }

    /// Writes an empty field section into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_new(out: *mut *mut HTTPFields) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, HTTPFields::new()) })
    }

    /// Appends the field of `name` (lowercased) and `value`; fails with Malformed if either is not valid (RFC 9110 §5).
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_append(fields: *mut HTTPFields, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            fields.append(name, value).map_err(|error| error.to_status())
        })())
    }

    /// Replaces the fields of `name` with one of `value`.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_set(fields: *mut HTTPFields, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            fields.set(name, value).map_err(|error| error.to_status())
        })())
    }

    /// Removes the fields of `name`; writes whether there were any into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_remove(fields: *mut HTTPFields, name: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::slice(name, length) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, fields.remove(name)) }
        })())
    }

    /// Writes the values of the fields of `name`, joined by ", " (RFC 9110 §5.3), into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_get(fields: *const HTTPFields, name: *const u8, length: usize, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(name, length)], &[Pointer::range(out_found, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable pointers.
            let fields = unsafe { Pointer::reference(fields) }?;
            let name = unsafe { Pointer::slice(name, length) }?;
            unsafe { Pointer::write_optional(fields.combined(name).as_deref().map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Writes the number of field lines into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_count(fields: *const HTTPFields, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let fields = unsafe { Pointer::reference(fields) }?;
            unsafe { Pointer::write(out, fields.len()) }
        })())
    }

    /// Writes the name and value of the field line `index` into `out_name` and `out_value`, and
    /// whether it is sensitive into `out_sensitive`; fails with NoSuchField past the end.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_line(fields: *const HTTPFields, index: usize, out_name: *mut Buffer, out_value: *mut Buffer, out_sensitive: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_value, 1)?;
            Pointer::check_range(out_sensitive, 1)?;
            let field = fields.fields.get(index).ok_or(&HTTPErrorStatus::NO_SUCH_FIELD)?;
            unsafe { Pointer::write(out_sensitive, field.sensitive) }?;
            unsafe { Pointer::write(out_name, Buffer::from_vec(field.name.clone())) }?;
            unsafe { Pointer::write(out_value, Buffer::from_vec(field.value.clone())) }
        })())
    }

    /// Marks the field line `index` sensitive or not: a sensitive one is never indexed by HPACK or QPACK.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_set_sensitive(fields: *mut HTTPFields, index: usize, sensitive: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            fields.fields.get_mut(index).ok_or(&HTTPErrorStatus::NO_SUCH_FIELD)?.sensitive = sensitive;
            Ok(())
        })())
    }

    /// Releases a field section. Does nothing if `fields` is null.
    pub unsafe extern "C" fn umilib_protocol_http_http_fields_free(fields: *mut HTTPFields) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(fields) }
    }

    /// Writes a request of `method` for `path` of `authority` over `scheme` into `out`, without fields;
    /// fails with Malformed for a method that is not a token.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_new(method: *const u8, method_length: usize, scheme: *const u8, scheme_length: usize, authority: *const u8, authority_length: usize, path: *const u8, path_length: usize, out: *mut *mut HTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let method = HTTPMethod::parse(unsafe { Pointer::slice(method, method_length) }?).map_err(|error| error.to_status())?;
            let scheme = unsafe { Pointer::slice(scheme, scheme_length) }?;
            let authority = unsafe { Pointer::slice(authority, authority_length) }?;
            let path = unsafe { Pointer::slice(path, path_length) }?;
            unsafe { Pointer::write_handle(out, HTTPRequest::new(method, scheme, authority, path)) }
        })())
    }

    /// Writes a CONNECT request for a tunnel to `authority` into `out` (RFC 9110 §9.3.6).
    pub unsafe extern "C" fn umilib_protocol_http_http_request_connect(authority: *const u8, length: usize, out: *mut *mut HTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let authority = unsafe { Pointer::slice(authority, length) }?;
            unsafe { Pointer::write_handle(out, HTTPRequest::connect(authority)) }
        })())
    }

    /// Writes the method into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_method(request: *const HTTPRequest, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(request.method.as_bytes().to_vec())) }
        })())
    }

    /// Writes the scheme into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_scheme(request: *const HTTPRequest, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_optional(request.scheme.as_deref().map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Writes the authority (of the target, else of the Host field) into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_host(request: *const HTTPRequest, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_optional(request.host().map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Writes the path and query (empty for CONNECT) into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_path(request: *const HTTPRequest, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(request.path.clone())) }
        })())
    }

    /// Writes the protocol of an extended CONNECT (RFC 8441 §4) into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_protocol(request: *const HTTPRequest, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_optional(request.protocol.as_deref().map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Sets the protocol of an extended CONNECT to the `length` bytes at `protocol`, or none if it is null.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_set_protocol(request: *mut HTTPRequest, protocol: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes or null.
            let request = unsafe { Pointer::reference_mut(request) }?;
            request.protocol = unsafe { HTTPErrorStatus::optional(protocol, length) }?;
            Ok(())
        })())
    }

    /// Writes a copy of the request's header fields into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_fields(request: *const HTTPRequest, out: *mut *mut HTTPFields) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write_handle(out, request.fields.clone()) }
        })())
    }

    /// Sets the request's header fields to a copy of `fields`.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_set_fields(request: *mut HTTPRequest, fields: *const HTTPFields) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let request = unsafe { Pointer::reference_mut(request) }?;
            request.fields = unsafe { Pointer::reference(fields) }?.clone();
            Ok(())
        })())
    }

    /// Checks the rules of the head every version shares (RFC 9110 §7.1, §9.3.6, RFC 8441 §4).
    pub unsafe extern "C" fn umilib_protocol_http_http_request_check(request: *const HTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference(request) }?.check().map_err(|error| error.to_status())
        })())
    }

    /// Releases a request. Does nothing if `request` is null.
    pub unsafe extern "C" fn umilib_protocol_http_http_request_free(request: *mut HTTPRequest) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(request) }
    }

    /// Writes a response of `status` (100 to 599) into `out`, without fields.
    pub unsafe extern "C" fn umilib_protocol_http_http_response_new(status: u16, out: *mut *mut HTTPResponse) -> *const Status {
        Status::from_result((|| {
            let status = HTTPStatus::new(status).ok_or(&Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, HTTPResponse::new(status)) }
        })())
    }

    /// Writes the status code into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_response_status(response: *const HTTPResponse, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write(out, response.status.0) }
        })())
    }

    /// Writes a copy of the response's header fields into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_response_fields(response: *const HTTPResponse, out: *mut *mut HTTPFields) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            unsafe { Pointer::write_handle(out, response.fields.clone()) }
        })())
    }

    /// Sets the response's header fields to a copy of `fields`.
    pub unsafe extern "C" fn umilib_protocol_http_http_response_set_fields(response: *mut HTTPResponse, fields: *const HTTPFields) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let response = unsafe { Pointer::reference_mut(response) }?;
            response.fields = unsafe { Pointer::reference(fields) }?.clone();
            Ok(())
        })())
    }

    /// Releases a response. Does nothing if `response` is null.
    pub unsafe extern "C" fn umilib_protocol_http_http_response_free(response: *mut HTTPResponse) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(response) }
    }

    /// Writes the rule of the requests whose host (without case) and path match the patterns of
    /// the texts `host` and `path` into `out`; fails with InvalidPattern.
    pub unsafe extern "C" fn umilib_protocol_http_http_rule_new(host: *const u8, host_length: usize, path: *const u8, path_length: usize, out: *mut *mut HTTPRule) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let host = unsafe { HTTPErrorStatus::pattern(host, host_length) }?;
            let path = unsafe { HTTPErrorStatus::pattern(path, path_length) }?;
            unsafe { Pointer::write_handle(out, HTTPRule::new(host, path)) }
        })())
    }

    /// Makes the rule match requests of `method` only.
    pub unsafe extern "C" fn umilib_protocol_http_http_rule_set_method(rule: *mut HTTPRule, method: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let rule = unsafe { Pointer::reference_mut(rule) }?;
            rule.method = Some(HTTPMethod::parse(unsafe { Pointer::slice(method, length) }?).map_err(|error| error.to_status())?);
            Ok(())
        })())
    }

    /// Makes the rule match requests with a field `name` whose value matches the pattern of the text `value`.
    pub unsafe extern "C" fn umilib_protocol_http_http_rule_add_field(rule: *mut HTTPRule, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let rule = unsafe { Pointer::reference_mut(rule) }?;
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let value = unsafe { HTTPErrorStatus::pattern(value, value_length) }?;
            rule.fields.push((name.to_ascii_lowercase(), value));
            Ok(())
        })())
    }

    /// Writes whether `request` matches the rule into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_http_rule_matches(rule: *const HTTPRule, request: *const HTTPRequest, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let request = unsafe { Pointer::reference(request) }?;
            unsafe { Pointer::write(out, rule.matches(request)) }
        })())
    }

    /// Releases a rule. Does nothing if `rule` is null.
    pub unsafe extern "C" fn umilib_protocol_http_http_rule_free(rule: *mut HTTPRule) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(rule) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "http",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_http_HTTPConfig",
            documentation: " The limits every version of HTTP keeps on what a peer sends.",
            fields: &[
                Parameter { name: "maximum_field_section_size", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_target_length", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_buffered_content", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_events", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_http_HTTPEvent",
            documentation: " An event of an HTTP connection.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "stream", value: <u64 as Value>::TYPE },
                Parameter { name: "end", value: <bool as Value>::TYPE },
                Parameter { name: "code", value: <u64 as Value>::TYPE },
                Parameter { name: "error", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Opaque { name: "umilib_protocol_http_HTTPFields", documentation: " A header or trailer section." },
        Definition::Opaque { name: "umilib_protocol_http_HTTPRequest", documentation: " The head of an HTTP request." },
        Definition::Opaque {
            name: "umilib_protocol_http_HTTPResponse",
            documentation: " The head of an HTTP response.",
        },
        Definition::Opaque {
            name: "umilib_protocol_http_HTTPRule",
            documentation: " A rule that routes HTTP requests.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-http-v1")]
        v1::MODULE,
        #[cfg(umilib_feature = "protocol-http-v2")]
        v2::MODULE,
        #[cfg(umilib_feature = "protocol-http-v3")]
        v3::MODULE,
        #[cfg(umilib_feature = "protocol-http-websocket")]
        websocket::MODULE,
    ],
};
