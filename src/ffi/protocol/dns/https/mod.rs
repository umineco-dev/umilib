//! The C ABI of [`crate::protocol::dns::https`].
//!
//! The HTTP exchange is the caller's (with an HTTP connection of
//! [`crate::ffi::protocol::http`]); these functions give its parts: the
//! path of a GET, the query of a request, and the Cache-Control of a
//! response (RFC 8484).

use crate::ffi::{Buffer, Module, Pointer, Status, ToStatus};
use crate::protocol::dns::DNSMessage;
use crate::protocol::dns::https::DNSHTTPS;
use crate::protocol::http::{HTTPFields, HTTPMethod, HTTPRequest, HTTPResponse, HTTPStatus};

crate::ffi_functions! {
    /// Writes the path of the GET request of the query of the `length` bytes at `query` to the path
    /// of the text at `path` ("/dns-query"), the message in its "dns" variable as base64url without
    /// padding (RFC 8484 §4.1), into `out`; fails with Malformed for bytes that are not a message.
    pub unsafe extern "C" fn umilib_protocol_dns_https_dns_https_get_path(query: *const u8, length: usize, path: *const u8, path_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and text and a writable pointer.
            let query = DNSMessage::decode(unsafe { Pointer::slice(query, length) }?).map_err(|error| error.to_status())?;
            let path = unsafe { Pointer::text(path, path_length) }?;
            let request = DNSHTTPS::get(&query, b"", path.as_bytes()).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(request.path)) }
        })())
    }

    /// Writes the query of a request of the method of the text at `method`, the path of `path`, the
    /// Content-Type of `content_type` (none if its length is 0) and the `length` bytes of content at
    /// `content` into `out`, and into `out_status` 0, or the status to answer with (405, 415, 413,
    /// 414 or 400, RFC 8484 §4.1).
    pub unsafe extern "C" fn umilib_protocol_dns_https_dns_https_query(method: *const u8, method_length: usize, path: *const u8, path_length: usize, content_type: *const u8, content_type_length: usize, content: *const u8, length: usize, out_status: *mut u16, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(method, method_length),
                    Pointer::range(path, path_length),
                    Pointer::range(content_type, content_type_length),
                    Pointer::range(content, length),
                ],
                &[Pointer::range(out_status, 1)],
            )?;
            // SAFETY: the caller passes readable text and bytes and writable pointers.
            let method = HTTPMethod::parse(unsafe { Pointer::slice(method, method_length) }?).map_err(|_| &Status::INVALID_ARGUMENT)?;
            let path = unsafe { Pointer::slice(path, path_length) }?;
            let content_type = unsafe { Pointer::slice(content_type, content_type_length) }?;
            let content = unsafe { Pointer::slice(content, length) }?;
            Pointer::check_range(out_status, 1)?;
            Pointer::check_range(out, 1)?;
            let mut fields = HTTPFields::new();
            if !content_type.is_empty() {
                fields.append(b"content-type", content_type).map_err(|_| &Status::INVALID_ARGUMENT)?;
            }
            let request = HTTPRequest::new(method, b"https", b"", path).with_fields(fields);
            let (status, query) = match DNSHTTPS::query(&request, content) {
                Ok(query) => (0, query),
                Err(status) => (status.0, alloc::vec::Vec::new()),
            };
            unsafe { Pointer::write(out_status, status) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(query)) }
        })())
    }

    /// Writes the Cache-Control value of the 200 response of the DNS response of the `length` bytes
    /// at `message` (its least TTL, RFC 8484 §5.1) into `out`; fails with Malformed.
    pub unsafe extern "C" fn umilib_protocol_dns_https_dns_https_cache_control(message: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let response = DNSHTTPS::response(unsafe { Pointer::slice(message, length) }?).map_err(|error| error.to_status())?;
            let control = response.fields.get(b"cache-control").unwrap_or_default().to_vec();
            unsafe { Pointer::write(out, Buffer::from_vec(control)) }
        })())
    }

    /// Checks the HTTP response of `status`, the Content-Type of `content_type` and the content of the
    /// `length` bytes at `content` (RFC 8484 §4.2.1: a 2xx of "application/dns-message"); fails with Malformed.
    pub unsafe extern "C" fn umilib_protocol_dns_https_dns_https_check_response(status: u16, content_type: *const u8, content_type_length: usize, content: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes.
            let content_type = unsafe { Pointer::slice(content_type, content_type_length) }?;
            let content = unsafe { Pointer::slice(content, length) }?;
            let fields = HTTPFields::new().with(b"content-type", content_type).map_err(|_| &Status::INVALID_ARGUMENT)?;
            let response = HTTPResponse::new(HTTPStatus(status)).with_fields(fields);
            DNSHTTPS::decode_response(&response, content).map(|_| ()).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "https", definitions: &[], functions: FUNCTIONS, modules: &[] };
