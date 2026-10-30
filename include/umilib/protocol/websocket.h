/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_WEBSOCKET_H
#define UMILIB_PROTOCOL_WEBSOCKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The configuration of WebSocket connections.
 */
typedef struct umilib_protocol_websocket_WebSocketConfig {
    size_t maximum_message_size;
    size_t maximum_frame_size;
    uint32_t deflate_level;
    size_t maximum_events;
} umilib_protocol_websocket_WebSocketConfig;

/**
 * The parameters of permessage-deflate; a window of 0 bits is none given.
 */
typedef struct umilib_protocol_websocket_WebSocketDeflateParameters {
    bool server_no_context_takeover;
    bool client_no_context_takeover;
    uint8_t server_max_window_bits;
    bool has_client_max_window_bits;
    uint8_t client_max_window_bits;
} umilib_protocol_websocket_WebSocketDeflateParameters;

/**
 * An event of a WebSocket connection.
 */
typedef struct umilib_protocol_websocket_WebSocketEvent {
    uint8_t kind;
    uint16_t code;
} umilib_protocol_websocket_WebSocketEvent;

/**
 * A WebSocket connection without I/O.
 */
typedef struct umilib_protocol_websocket_WebSocketConnection umilib_protocol_websocket_WebSocketConnection;

/**
 * Writes the default configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_config_default(umilib_protocol_websocket_WebSocketConfig* out);

/**
 * Writes the parameters a server accepts for the offer `offer` into `out` (RFC 7692 §7.1).
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_deflate_parameters_accept(const umilib_protocol_websocket_WebSocketDeflateParameters* offer, umilib_protocol_websocket_WebSocketDeflateParameters* out);

/**
 * Writes a connection into `out`: a client's if `server` is false, of `config`, with
 * permessage-deflate of the agreed `deflate` (none if null); its randomness is seeded by the
 * `seed_length` bytes at `seed` (at least 48).
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_new(bool server, umilib_protocol_websocket_WebSocketConfig config, const umilib_protocol_websocket_WebSocketDeflateParameters* deflate, const uint8_t* seed, size_t seed_length, umilib_protocol_websocket_WebSocketConnection** out);

/**
 * Releases a connection. Does nothing if `connection` is null.
 */
void umilib_protocol_websocket_websocket_connection_free(umilib_protocol_websocket_WebSocketConnection* connection);

/**
 * Takes the `length` bytes at `bytes` that arrived.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_receive(umilib_protocol_websocket_WebSocketConnection* connection, const uint8_t* bytes, size_t length);

/**
 * Takes the end of the transport.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_receive_close(umilib_protocol_websocket_WebSocketConnection* connection);

/**
 * Writes the bytes to send into `out`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_transmit(umilib_protocol_websocket_WebSocketConnection* connection, umilib_ffi_Buffer* out);

/**
 * Writes whether the transport should be closed, once what was transmitted is sent, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_wants_close(const umilib_protocol_websocket_WebSocketConnection* connection, bool* out);

/**
 * Writes whether to read more from the transport into `out`: false while events wait up to their limit.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_wants_receive(const umilib_protocol_websocket_WebSocketConnection* connection, bool* out);

/**
 * Writes the state into `out`: 0 open, 1 closing (this end sent Close), 2 closed.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_state(const umilib_protocol_websocket_WebSocketConnection* connection, uint8_t* out);

/**
 * Sends the text message of the `length` bytes of UTF-8 at `text`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_send_text(umilib_protocol_websocket_WebSocketConnection* connection, const uint8_t* text, size_t length);

/**
 * Sends the binary message of the `length` bytes at `data`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_send_binary(umilib_protocol_websocket_WebSocketConnection* connection, const uint8_t* data, size_t length);

/**
 * Sends a Ping of the `length` bytes at `data` (at most 125).
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_send_ping(umilib_protocol_websocket_WebSocketConnection* connection, const uint8_t* data, size_t length);

/**
 * Starts the closing handshake with `code` and the reason of the `length` bytes of UTF-8 at `reason`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_close(umilib_protocol_websocket_WebSocketConnection* connection, uint16_t code, const uint8_t* reason, size_t length);

/**
 * Writes whether an event is pending into `out_found`, the event into `out` and its text,
 * data or reason into `out_bytes`.
 */
const umilib_ffi_Status* umilib_protocol_websocket_websocket_connection_poll_event(umilib_protocol_websocket_WebSocketConnection* connection, bool* out_found, umilib_protocol_websocket_WebSocketEvent* out, umilib_ffi_Buffer* out_bytes);

#ifdef __cplusplus
}
#endif

#endif
