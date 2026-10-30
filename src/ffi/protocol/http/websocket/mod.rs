//! The C ABI of [`crate::protocol::http::websocket`].
//!
//! An offer and an agreement are handles; requests and responses those of
//! [`crate::ffi::protocol::http`], the parameters of permessage-deflate the
//! structure of [`crate::ffi::protocol::websocket`]. Subprotocols cross as
//! arrays of UTF-8 byte strings with their lengths. A client's key is drawn
//! from an HMAC-DRBG seeded by the caller with at least 48 bytes.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ffi::protocol::http::HTTPErrorStatus;
use crate::ffi::protocol::websocket::{FFIWebSocketDeflateParameters, WebSocketStatus};
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::http::websocket::{WebSocketAgreement, WebSocketHandshake, WebSocketOffer};
use crate::protocol::http::{HTTPRequest, HTTPResponse, HTTPVersion};

/// The statuses and arguments of this module.
pub struct WebSocketHandshakeStatus;

impl WebSocketHandshakeStatus {
    pub const REJECTED: Status = Status::new(
        c"protocol.http.websocket",
        c"Rejected",
        c"the response does not complete the WebSocket handshake that was offered",
    );

    /// The status of a response that does not complete the handshake.
    pub fn rejected(_reason: &'static str) -> &'static Status {
        &WebSocketHandshakeStatus::REJECTED
    }

    /// The `count` subprotocols at `protocols` and `lengths`, each UTF-8.
    ///
    /// # Safety
    /// As [`Pointer::slices`].
    pub unsafe fn protocols(
        protocols: *const *const u8,
        lengths: *const usize,
        count: usize,
    ) -> Result<Vec<String>, &'static Status> {
        // SAFETY: the caller's promise.
        let slices = unsafe { Pointer::slices(protocols, lengths, count) }?;
        slices.into_iter().map(|bytes| String::from_utf8(bytes.to_vec()).map_err(|_| &Status::INVALID_UTF8)).collect()
    }

    /// The borrowed forms of `protocols`.
    pub fn borrowed(protocols: &[String]) -> Vec<&str> {
        protocols.iter().map(String::as_str).collect()
    }

    /// Writes the parameters `parameters`, if any, into `out` and whether there are into `out_found`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn write_deflate(
        parameters: Option<&crate::protocol::websocket::WebSocketDeflateParameters>,
        out_found: *mut bool,
        out: *mut FFIWebSocketDeflateParameters,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_found, 1)?;
        Pointer::check_range(out, 1)?;
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out_found, parameters.is_some()) }?;
        unsafe { Pointer::write(out, parameters.map(FFIWebSocketDeflateParameters::of).unwrap_or_default()) }
    }
}

impl Value for WebSocketOffer {
    const TYPE: Type = Type::Named("umilib_protocol_http_websocket_WebSocketOffer");
}

impl Value for WebSocketAgreement {
    const TYPE: Type = Type::Named("umilib_protocol_http_websocket_WebSocketAgreement");
}

crate::ffi_functions! {
    /// Writes the Sec-WebSocket-Accept value of the key of `length` bytes at `key` into `out` (RFC 6455 §4.2.2).
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_accept(key: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = unsafe { Pointer::slice(key, length) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(WebSocketHandshake::accept(key))) }
        })())
    }

    /// Writes a client's HTTP/1.1 request for `path` of `authority` over `scheme` into `out_request`
    /// and its key into `out_key` (RFC 6455 §4.1), offering the `count` subprotocols and
    /// permessage-deflate of `deflate` (none if null); the key's randomness is seeded by the
    /// `seed_length` bytes at `seed` (at least 48).
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_request(scheme: *const u8, scheme_length: usize, authority: *const u8, authority_length: usize, path: *const u8, path_length: usize, protocols: *const *const u8, lengths: *const usize, count: usize, deflate: *const FFIWebSocketDeflateParameters, seed: *const u8, seed_length: usize, out_request: *mut *mut HTTPRequest, out_key: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and structures, and writable pointers.
            let scheme = unsafe { Pointer::slice(scheme, scheme_length) }?;
            let authority = unsafe { Pointer::slice(authority, authority_length) }?;
            let path = unsafe { Pointer::slice(path, path_length) }?;
            let protocols = unsafe { WebSocketHandshakeStatus::protocols(protocols, lengths, count) }?;
            let deflate = unsafe { FFIWebSocketDeflateParameters::optional(deflate) }?;
            let mut random = unsafe { WebSocketStatus::random(seed, seed_length) }?;
            Pointer::check_range(out_request, 1)?;
            Pointer::check_range(out_key, 1)?;
            let protocols = WebSocketHandshakeStatus::borrowed(&protocols);
            let (request, key) = WebSocketHandshake::request(scheme, authority, path, &protocols, deflate, &mut *random)
                .map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_key, Buffer::from_vec(key)) }?;
            unsafe { Pointer::write_handle(out_request, request) }
        })())
    }

    /// Writes a client's extended CONNECT over HTTP/2 or HTTP/3 into `out` (RFC 8441 §4, RFC 9220 §3),
    /// offering the `count` subprotocols and permessage-deflate of `deflate` (none if null).
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_connect_request(scheme: *const u8, scheme_length: usize, authority: *const u8, authority_length: usize, path: *const u8, path_length: usize, protocols: *const *const u8, lengths: *const usize, count: usize, deflate: *const FFIWebSocketDeflateParameters, out: *mut *mut HTTPRequest) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and structures, and a writable pointer.
            let scheme = unsafe { Pointer::slice(scheme, scheme_length) }?;
            let authority = unsafe { Pointer::slice(authority, authority_length) }?;
            let path = unsafe { Pointer::slice(path, path_length) }?;
            let protocols = unsafe { WebSocketHandshakeStatus::protocols(protocols, lengths, count) }?;
            let deflate = unsafe { FFIWebSocketDeflateParameters::optional(deflate) }?;
            Pointer::check_range(out, 1)?;
            let protocols = WebSocketHandshakeStatus::borrowed(&protocols);
            let request = WebSocketHandshake::connect_request(scheme, authority, path, &protocols, deflate)
                .map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, request) }
        })())
    }

    /// A server checks `request`, which came over HTTP `major`.`minor`: writes its offer into
    /// `out_offer` and null into `out_response`, or, if it is not a handshake to accept, null and
    /// the response to send (400, or 426 for another WebSocket version).
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_check_request(request: *const HTTPRequest, major: u8, minor: u8, out_offer: *mut *mut WebSocketOffer, out_response: *mut *mut HTTPResponse) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let request = unsafe { Pointer::reference(request) }?;
            Pointer::check_range(out_offer, 1)?;
            Pointer::check_range(out_response, 1)?;
            match WebSocketHandshake::check_request(request, HTTPVersion { major, minor }) {
                Ok(offer) => {
                    unsafe { Pointer::write(out_response, core::ptr::null_mut()) }?;
                    unsafe { Pointer::write_handle(out_offer, offer) }
                }
                Err(response) => {
                    unsafe { Pointer::write(out_offer, core::ptr::null_mut()) }?;
                    unsafe { Pointer::write_handle(out_response, response) }
                }
            }
        })())
    }

    /// Writes the client's key (none over HTTP/2 and HTTP/3) into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_key(offer: *const WebSocketOffer, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let offer = unsafe { Pointer::reference(offer) }?;
            unsafe { Pointer::write_optional(offer.key.as_deref().map(|value| Buffer::from_vec(value.to_vec())), out_found, out) }
        })())
    }

    /// Writes the number of subprotocols offered into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_protocol_count(offer: *const WebSocketOffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            unsafe { Pointer::write(out, offer.protocols.len()) }
        })())
    }

    /// Writes the subprotocol `index`, in the client's order of preference, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_protocol(offer: *const WebSocketOffer, index: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            let protocol = offer.protocols.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, Buffer::from_vec(protocol.clone().into_bytes())) }
        })())
    }

    /// Writes the number of valid offers of permessage-deflate into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_deflate_count(offer: *const WebSocketOffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            unsafe { Pointer::write(out, offer.deflate.len()) }
        })())
    }

    /// Writes the offer of permessage-deflate `index`, in the client's order, into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_deflate(offer: *const WebSocketOffer, index: usize, out: *mut FFIWebSocketDeflateParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            let parameters = offer.deflate.get(index).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, FFIWebSocketDeflateParameters::of(parameters)) }
        })())
    }

    /// Releases an offer. Does nothing if `offer` is null.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_offer_free(offer: *mut WebSocketOffer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(offer) }
    }

    /// Writes the agreement of a server into `out`: the first of the `count` subprotocols it
    /// supports that the client offered, and the client's first offer of permessage-deflate if `deflate`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_agree(offer: *const WebSocketOffer, protocols: *const *const u8, lengths: *const usize, count: usize, deflate: bool, out: *mut *mut WebSocketAgreement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable byte strings and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            let protocols = unsafe { WebSocketHandshakeStatus::protocols(protocols, lengths, count) }?;
            let agreement = WebSocketHandshake::agree(offer, &WebSocketHandshakeStatus::borrowed(&protocols), deflate);
            unsafe { Pointer::write_handle(out, agreement) }
        })())
    }

    /// Writes the response that accepts `offer` with `agreement` into `out`: 101 over HTTP/1.1, 200 otherwise.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_response(offer: *const WebSocketOffer, agreement: *const WebSocketAgreement, out: *mut *mut HTTPResponse) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?;
            let agreement = unsafe { Pointer::reference(agreement) }?;
            Pointer::check_range(out, 1)?;
            let response = WebSocketHandshake::response(offer, agreement).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, response) }
        })())
    }

    /// A client checks `response` against its key (null over HTTP/2 and HTTP/3), the `count`
    /// subprotocols and the permessage-deflate (null for none) it offered; writes the agreement into `out`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_handshake_check_response(response: *const HTTPResponse, key: *const u8, key_length: usize, protocols: *const *const u8, lengths: *const usize, count: usize, deflate: *const FFIWebSocketDeflateParameters, out: *mut *mut WebSocketAgreement) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and structures, and a writable pointer.
            let response = unsafe { Pointer::reference(response) }?;
            let key = unsafe { HTTPErrorStatus::optional(key, key_length) }?;
            let protocols = unsafe { WebSocketHandshakeStatus::protocols(protocols, lengths, count) }?;
            let deflate = unsafe { FFIWebSocketDeflateParameters::optional(deflate) }?;
            Pointer::check_range(out, 1)?;
            let agreement = WebSocketHandshake::check_response(response, key.as_deref(), &WebSocketHandshakeStatus::borrowed(&protocols), deflate.as_ref())
                .map_err(WebSocketHandshakeStatus::rejected)?;
            unsafe { Pointer::write_handle(out, agreement) }
        })())
    }

    /// Writes the subprotocol agreed into `out` and whether there is one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_agreement_protocol(agreement: *const WebSocketAgreement, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let agreement = unsafe { Pointer::reference(agreement) }?;
            unsafe { Pointer::write_optional(agreement.protocol.clone().map(|value| Buffer::from_vec(value.into_bytes())), out_found, out) }
        })())
    }

    /// Writes the parameters of permessage-deflate agreed into `out` and whether there are any into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_agreement_deflate(agreement: *const WebSocketAgreement, out_found: *mut bool, out: *mut FFIWebSocketDeflateParameters) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let agreement = unsafe { Pointer::reference(agreement) }?;
            unsafe { WebSocketHandshakeStatus::write_deflate(agreement.deflate.as_ref(), out_found, out) }
        })())
    }

    /// Releases an agreement. Does nothing if `agreement` is null.
    pub unsafe extern "C" fn umilib_protocol_http_websocket_websocket_agreement_free(agreement: *mut WebSocketAgreement) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(agreement) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "websocket",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_http_websocket_WebSocketOffer",
            documentation: " What a client's WebSocket handshake offers.",
        },
        Definition::Opaque {
            name: "umilib_protocol_http_websocket_WebSocketAgreement",
            documentation: " What the two ends of a WebSocket handshake agreed.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
