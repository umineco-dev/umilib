/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_HTTP_V3_H
#define UMILIB_PROTOCOL_HTTP_V3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/qpack.h"
#include "umilib/ffi.h"
#include "umilib/protocol/http.h"
#include "umilib/protocol/quic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The configuration of HTTP/3 connections.
 */
typedef struct umilib_protocol_http_v3_H3Config {
    umilib_protocol_http_HTTPConfig http;
    umilib_codec_qpack_QPACKEncoderConfig qpack_encoder;
    umilib_codec_qpack_QPACKDecoderConfig qpack_decoder;
    bool enable_connect_protocol;
    bool grease;
} umilib_protocol_http_v3_H3Config;

/**
 * The state of an HTTP/3 connection over a QUIC connection.
 */
typedef struct umilib_protocol_http_v3_H3Connection umilib_protocol_http_v3_H3Connection;

/**
 * Writes the default configuration into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_config_default(umilib_protocol_http_v3_H3Config* out);

/**
 * Writes the state of a client's connection of `config`, opened at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_client(umilib_protocol_http_v3_H3Config config, uint64_t now, umilib_protocol_http_v3_H3Connection** out);

/**
 * Writes the state of a server's connection of `config`, opened at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_server(umilib_protocol_http_v3_H3Config config, uint64_t now, umilib_protocol_http_v3_H3Connection** out);

/**
 * Releases a connection's state. Does nothing if `connection` is null.
 */
void umilib_protocol_http_v3_h3_connection_free(umilib_protocol_http_v3_H3Connection* connection);

/**
 * Handles what the QUIC connection `quic` of `endpoint` received, at `now`: call it after the endpoint takes datagrams and fires timers.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_process(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t now);

/**
 * A client starts an exchange with `request`, which has no content if `end`; writes its stream into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_send_request(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, const umilib_protocol_http_HTTPRequest* request, bool end, uint64_t* out);

/**
 * A server answers `stream` with `response` (interim ones first), with no content if `end`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_send_response(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, const umilib_protocol_http_HTTPResponse* response, bool end);

/**
 * Writes the `length` bytes at `data` as content of `stream`, the last if `end`; writes how many were taken into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_send_data(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, const uint8_t* data, size_t length, bool end, size_t* out);

/**
 * Ends the message of `stream` with the trailer section `trailers`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_send_trailers(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, const umilib_protocol_http_HTTPFields* trailers);

/**
 * Reads up to `capacity` bytes of content of `stream` into `out`; writes how many into `out_count`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_read_data(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, uint8_t* out, size_t capacity, size_t* out_count);

/**
 * Abandons `stream` for `reason` (0 Cancel, 1 Refused, 2 Internal, 3 NoError).
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_reset(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint64_t stream, uint8_t reason);

/**
 * Writes whether an event is pending into `out_found` and the event into `out`; the request
 * of a Request, the response of a Response and the fields of Trailers into `out_request`,
 * `out_response` and `out_fields` (null otherwise), which the caller releases.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_poll_event(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, bool* out_found, umilib_protocol_http_HTTPEvent* out, umilib_protocol_http_HTTPRequest** out_request, umilib_protocol_http_HTTPResponse** out_response, umilib_protocol_http_HTTPFields** out_fields);

/**
 * Takes no new exchanges: those under way finish, then the connection closes.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_shutdown(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic);

/**
 * Writes whether the connection is closed into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_is_closed(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, bool* out);

/**
 * Writes the major and minor numbers of the version (3 and 0) into `out_major` and `out_minor`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_version(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, uint8_t* out_major, uint8_t* out_minor);

/**
 * Writes whether the QUIC connection has an event HTTP/3 does not handle (a DATAGRAM, say)
 * into `out_found`, the event into `out` and its bytes into `out_bytes`.
 */
const umilib_ffi_Status* umilib_protocol_http_v3_h3_connection_poll_quic_event(umilib_protocol_http_v3_H3Connection* connection, umilib_protocol_quic_QUICEndpoint* endpoint, uint64_t quic, bool* out_found, umilib_protocol_quic_QUICEvent* out, umilib_ffi_Buffer* out_bytes);

#ifdef __cplusplus
}
#endif

#endif
