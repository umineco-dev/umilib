//! The C ABI of [`crate::protocol::websocket`].
//!
//! A connection is a handle; its configuration, the parameters of
//! permessage-deflate and an event are structures. A connection draws the
//! masks of a client's frames from an HMAC-DRBG (SP 800-90A) seeded by the
//! caller with at least 48 bytes from the operating system.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::random::HMACDRBG;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, Type, Value};
use crate::hash::sha::v2::SHA256;
use crate::protocol::websocket::{
    WebSocketCloseCode, WebSocketConfig, WebSocketConnection, WebSocketDeflateParameters, WebSocketEvent,
    WebSocketRole, WebSocketState,
};

/// The statuses of this module.
pub struct WebSocketStatus;

impl WebSocketStatus {
    pub const REFUSED: Status = Status::new(
        c"protocol.websocket",
        c"Refused",
        c"the connection's state does not allow it, or the message, code or reason is not one to send",
    );
    pub const CONFIG: Status =
        Status::new(c"protocol.websocket", c"Config", c"the WebSocket configuration or parameters cannot work");
    /// The fewest bytes of seed a source of randomness takes.
    pub const SEED_LENGTH: usize = 48;

    /// A DRBG seeded with the `length` bytes at `seed`, at least 48.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn random(seed: *const u8, length: usize) -> Result<Box<HMACDRBG<SHA256>>, &'static Status> {
        // SAFETY: the caller's promise.
        let seed = unsafe { Pointer::slice(seed, length) }?;
        if seed.len() < WebSocketStatus::SEED_LENGTH {
            return Err(&Status::INVALID_ARGUMENT);
        }
        let (entropy, nonce) = seed.split_at(32);
        let random =
            HMACDRBG::new(entropy, nonce, b"umilib protocol websocket").map_err(|_| &Status::INVALID_ARGUMENT)?;
        Ok(Box::new(random))
    }

    /// The status of a call this end could not make.
    pub fn refused(_reason: &'static str) -> &'static Status {
        &WebSocketStatus::REFUSED
    }
}

/// The parameters of permessage-deflate (RFC 7692 §7.1): a window of 0
/// bits is none given; `client_max_window_bits` counts only if
/// `has_client_max_window_bits`, and 0 there is the parameter without a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIWebSocketDeflateParameters {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    pub server_max_window_bits: u8,
    pub has_client_max_window_bits: bool,
    pub client_max_window_bits: u8,
}

impl FFIWebSocketDeflateParameters {
    pub fn of(parameters: &WebSocketDeflateParameters) -> FFIWebSocketDeflateParameters {
        FFIWebSocketDeflateParameters {
            server_no_context_takeover: parameters.server_no_context_takeover,
            client_no_context_takeover: parameters.client_no_context_takeover,
            server_max_window_bits: parameters.server_max_window_bits.unwrap_or(0),
            has_client_max_window_bits: parameters.client_max_window_bits.is_some(),
            client_max_window_bits: parameters.client_max_window_bits.flatten().unwrap_or(0),
        }
    }

    pub fn parameters(&self) -> WebSocketDeflateParameters {
        WebSocketDeflateParameters {
            server_no_context_takeover: self.server_no_context_takeover,
            client_no_context_takeover: self.client_no_context_takeover,
            server_max_window_bits: (self.server_max_window_bits != 0).then_some(self.server_max_window_bits),
            client_max_window_bits: self
                .has_client_max_window_bits
                .then_some((self.client_max_window_bits != 0).then_some(self.client_max_window_bits)),
        }
    }

    /// The parameters at `parameters`, or none if it is null.
    ///
    /// # Safety
    /// As [`Pointer::optional_reference`].
    pub unsafe fn optional(
        parameters: *const FFIWebSocketDeflateParameters,
    ) -> Result<Option<WebSocketDeflateParameters>, &'static Status> {
        // SAFETY: the caller's promise.
        Ok(unsafe { Pointer::optional_reference(parameters) }?.map(FFIWebSocketDeflateParameters::parameters))
    }
}

/// A [`WebSocketEvent`]: `kind` the number of its variant (0 Text, 1
/// Binary, 2 Ping, 3 Pong, 4 Closed) and the code of Closed; the text,
/// data or reason goes in a buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIWebSocketEvent {
    pub kind: u8,
    pub code: u16,
}

impl FFIWebSocketEvent {
    /// The structure of `event` and its bytes.
    pub fn of(event: WebSocketEvent) -> (FFIWebSocketEvent, Vec<u8>) {
        match event {
            WebSocketEvent::Text(text) => (FFIWebSocketEvent { kind: 0, code: 0 }, text.into_bytes()),
            WebSocketEvent::Binary(data) => (FFIWebSocketEvent { kind: 1, code: 0 }, data),
            WebSocketEvent::Ping(data) => (FFIWebSocketEvent { kind: 2, code: 0 }, data),
            WebSocketEvent::Pong(data) => (FFIWebSocketEvent { kind: 3, code: 0 }, data),
            WebSocketEvent::Closed { code, reason } => {
                (FFIWebSocketEvent { kind: 4, code: code.0 }, reason.into_bytes())
            }
        }
    }
}

impl Value for WebSocketConfig {
    const TYPE: Type = Type::Named("umilib_protocol_websocket_WebSocketConfig");
}

impl Value for FFIWebSocketDeflateParameters {
    const TYPE: Type = Type::Named("umilib_protocol_websocket_WebSocketDeflateParameters");
}

impl Value for FFIWebSocketEvent {
    const TYPE: Type = Type::Named("umilib_protocol_websocket_WebSocketEvent");
}

impl Value for WebSocketConnection {
    const TYPE: Type = Type::Named("umilib_protocol_websocket_WebSocketConnection");
}

crate::ffi_functions! {
    /// Writes the default configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_config_default(out: *mut WebSocketConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, WebSocketConfig::default()) })
    }

    /// Writes the parameters a server accepts for the offer `offer` into `out` (RFC 7692 §7.1).
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_deflate_parameters_accept(offer: *const FFIWebSocketDeflateParameters, out: *mut FFIWebSocketDeflateParameters) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(offer, 1)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid structure and a writable pointer.
            let offer = unsafe { Pointer::reference(offer) }?.parameters();
            unsafe { Pointer::write(out, FFIWebSocketDeflateParameters::of(&WebSocketDeflateParameters::accept(&offer))) }
        })())
    }

    /// Writes a connection into `out`: a client's if `server` is false, of `config`, with
    /// permessage-deflate of the agreed `deflate` (none if null); its randomness is seeded by the
    /// `seed_length` bytes at `seed` (at least 48).
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_new(server: bool, config: WebSocketConfig, deflate: *const FFIWebSocketDeflateParameters, seed: *const u8, seed_length: usize, out: *mut *mut WebSocketConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure or null, readable bytes and a writable pointer.
            let deflate = unsafe { FFIWebSocketDeflateParameters::optional(deflate) }?;
            let random = unsafe { WebSocketStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let role = if server { WebSocketRole::Server } else { WebSocketRole::Client };
            let connection = WebSocketConnection::new(role, config, deflate, random).map_err(|_| &WebSocketStatus::CONFIG)?;
            unsafe { Pointer::write_handle(out, connection) }
        })())
    }

    /// Releases a connection. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_free(connection: *mut WebSocketConnection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Takes the `length` bytes at `bytes` that arrived.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_receive(connection: *mut WebSocketConnection, bytes: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.receive(unsafe { Pointer::slice(bytes, length) }?);
            Ok(())
        })())
    }

    /// Takes the end of the transport.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_receive_close(connection: *mut WebSocketConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(connection) }?.receive_close();
            Ok(())
        })())
    }

    /// Writes the bytes to send into `out`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_transmit(connection: *mut WebSocketConnection, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out, 1)?;
            let mut bytes = Vec::new();
            connection.transmit(&mut bytes);
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Writes whether the transport should be closed, once what was transmitted is sent, into `out`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_wants_close(connection: *const WebSocketConnection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_close()) }
        })())
    }

    /// Writes whether to read more from the transport into `out`: false while events wait up to their limit.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_wants_receive(connection: *const WebSocketConnection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, connection.wants_receive()) }
        })())
    }

    /// Writes the state into `out`: 0 open, 1 closing (this end sent Close), 2 closed.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_state(connection: *const WebSocketConnection, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            let state = match connection.state {
                WebSocketState::Open => 0,
                WebSocketState::Closing => 1,
                WebSocketState::Closed => 2,
            };
            unsafe { Pointer::write(out, state) }
        })())
    }

    /// Sends the text message of the `length` bytes of UTF-8 at `text`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_send_text(connection: *mut WebSocketConnection, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            connection.send_text(text).map_err(WebSocketStatus::refused)
        })())
    }

    /// Sends the binary message of the `length` bytes at `data`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_send_binary(connection: *mut WebSocketConnection, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.send_binary(unsafe { Pointer::slice(data, length) }?).map_err(WebSocketStatus::refused)
        })())
    }

    /// Sends a Ping of the `length` bytes at `data` (at most 125).
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_send_ping(connection: *mut WebSocketConnection, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.send_ping(unsafe { Pointer::slice(data, length) }?).map_err(WebSocketStatus::refused)
        })())
    }

    /// Starts the closing handshake with `code` and the reason of the `length` bytes of UTF-8 at `reason`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_close(connection: *mut WebSocketConnection, code: u16, reason: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let reason = unsafe { Pointer::text(reason, length) }?;
            connection.close(WebSocketCloseCode(code), reason).map_err(WebSocketStatus::refused)
        })())
    }

    /// Writes whether an event is pending into `out_found`, the event into `out` and its text,
    /// data or reason into `out_bytes`.
    pub unsafe extern "C" fn umilib_protocol_websocket_websocket_connection_poll_event(connection: *mut WebSocketConnection, out_found: *mut bool, out: *mut FFIWebSocketEvent, out_bytes: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_bytes, 1)?;
            let event = connection.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (structure, bytes) = event.map(FFIWebSocketEvent::of).unwrap_or_default();
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_bytes, Buffer::from_vec(bytes)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "websocket",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_websocket_WebSocketConfig",
            documentation: " The configuration of WebSocket connections.",
            fields: &[
                Parameter { name: "maximum_message_size", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_frame_size", value: <usize as Value>::TYPE },
                Parameter { name: "deflate_level", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_events", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_websocket_WebSocketDeflateParameters",
            documentation: " The parameters of permessage-deflate; a window of 0 bits is none given.",
            fields: &[
                Parameter { name: "server_no_context_takeover", value: <bool as Value>::TYPE },
                Parameter { name: "client_no_context_takeover", value: <bool as Value>::TYPE },
                Parameter { name: "server_max_window_bits", value: <u8 as Value>::TYPE },
                Parameter { name: "has_client_max_window_bits", value: <bool as Value>::TYPE },
                Parameter { name: "client_max_window_bits", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_websocket_WebSocketEvent",
            documentation: " An event of a WebSocket connection.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "code", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_websocket_WebSocketConnection",
            documentation: " A WebSocket connection without I/O.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
