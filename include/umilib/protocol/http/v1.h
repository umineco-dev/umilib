/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_HTTP_V1_H
#define UMILIB_PROTOCOL_HTTP_V1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/http.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits of HTTP/1.1 connections; timeouts in milliseconds, 0 for none.
 */
typedef struct umilib_protocol_http_v1_H1Limits {
    umilib_protocol_http_HTTPConfig http;
    size_t maximum_pipelined;
    size_t maximum_chunk_line;
    uint64_t idle_timeout;
    uint64_t head_timeout;
    bool continue_automatically;
} umilib_protocol_http_v1_H1Limits;

/**
 * An HTTP/1.1 connection without I/O.
 */
typedef struct umilib_protocol_http_v1_H1Connection umilib_protocol_http_v1_H1Connection;

/**
 * Writes the default limits into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_limits_default(umilib_protocol_http_v1_H1Limits* out);

/**
 * Writes a client's connection of `limits`, for requests over `scheme`, opened at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_client(const umilib_protocol_http_v1_H1Limits* limits, const uint8_t* scheme, size_t length, uint64_t now, umilib_protocol_http_v1_H1Connection** out);

/**
 * Writes a server's connection of `limits`, whose requests in origin-form are of `scheme`, opened at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_server(const umilib_protocol_http_v1_H1Limits* limits, const uint8_t* scheme, size_t length, uint64_t now, umilib_protocol_http_v1_H1Connection** out);

/**
 * Releases a connection. Does nothing if `connection` is null.
 */
void umilib_protocol_http_v1_h1_connection_free(umilib_protocol_http_v1_H1Connection* connection);

/**
 * Takes the `length` bytes at `bytes` that arrived at `now`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_receive(umilib_protocol_http_v1_H1Connection* connection, const uint8_t* bytes, size_t length, uint64_t now);

/**
 * Takes the end of the byte stream from the peer, at `now`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_receive_close(umilib_protocol_http_v1_H1Connection* connection, uint64_t now);

/**
 * Writes whether the connection takes more bytes now into `out` (false while the application has not read what arrived).
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_wants_receive(const umilib_protocol_http_v1_H1Connection* connection, bool* out);

/**
 * Writes the bytes to send into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_transmit(umilib_protocol_http_v1_H1Connection* connection, umilib_ffi_Buffer* out);

/**
 * Writes whether the byte stream should be closed, once what was transmitted is sent, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_wants_close(const umilib_protocol_http_v1_H1Connection* connection, bool* out);

/**
 * Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_poll_timeout(const umilib_protocol_http_v1_H1Connection* connection, bool* out_found, uint64_t* out);

/**
 * Fires the timers due at `now`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_expire(umilib_protocol_http_v1_H1Connection* connection, uint64_t now);

/**
 * A client starts an exchange with `request`, which has no content if `end`; writes its stream into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_send_request(umilib_protocol_http_v1_H1Connection* connection, const umilib_protocol_http_HTTPRequest* request, bool end, uint64_t* out);

/**
 * A server answers `stream` with `response` (interim ones first), with no content if `end`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_send_response(umilib_protocol_http_v1_H1Connection* connection, uint64_t stream, const umilib_protocol_http_HTTPResponse* response, bool end);

/**
 * Writes the `length` bytes at `data` as content of `stream`, the last if `end`; writes how many were taken into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_send_data(umilib_protocol_http_v1_H1Connection* connection, uint64_t stream, const uint8_t* data, size_t length, bool end, size_t* out);

/**
 * Ends the message of `stream` with the trailer section `trailers`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_send_trailers(umilib_protocol_http_v1_H1Connection* connection, uint64_t stream, const umilib_protocol_http_HTTPFields* trailers);

/**
 * Reads up to `capacity` bytes of content of `stream` into `out`; writes how many into `out_count`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_read_data(umilib_protocol_http_v1_H1Connection* connection, uint64_t stream, uint8_t* out, size_t capacity, size_t* out_count);

/**
 * Abandons `stream` for `reason` (0 Cancel, 1 Refused, 2 Internal, 3 NoError).
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_reset(umilib_protocol_http_v1_H1Connection* connection, uint64_t stream, uint8_t reason);

/**
 * Writes whether an event is pending into `out_found` and the event into `out`; the request
 * of a Request, the response of a Response and the fields of Trailers into `out_request`,
 * `out_response` and `out_fields` (null otherwise), which the caller releases.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_poll_event(umilib_protocol_http_v1_H1Connection* connection, bool* out_found, umilib_protocol_http_HTTPEvent* out, umilib_protocol_http_HTTPRequest** out_request, umilib_protocol_http_HTTPResponse** out_response, umilib_protocol_http_HTTPFields** out_fields);

/**
 * Takes no new exchanges: those under way finish, then the connection closes.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_shutdown(umilib_protocol_http_v1_H1Connection* connection);

/**
 * Writes whether the connection is closed into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_is_closed(const umilib_protocol_http_v1_H1Connection* connection, bool* out);

/**
 * Writes the major and minor numbers of the connection's version into `out_major` and `out_minor`.
 */
const umilib_ffi_Status* umilib_protocol_http_v1_h1_connection_version(const umilib_protocol_http_v1_H1Connection* connection, uint8_t* out_major, uint8_t* out_minor);

#ifdef __cplusplus
}
#endif

#endif
