/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_HTTP_WEBSOCKET_H
#define UMILIB_PROTOCOL_HTTP_WEBSOCKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/http.h"
#include "umilib/protocol/websocket.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * What a client's WebSocket handshake offers.
 */
typedef struct umilib_protocol_http_websocket_WebSocketOffer umilib_protocol_http_websocket_WebSocketOffer;

/**
 * What the two ends of a WebSocket handshake agreed.
 */
typedef struct umilib_protocol_http_websocket_WebSocketAgreement umilib_protocol_http_websocket_WebSocketAgreement;

/**
 * Writes the Sec-WebSocket-Accept value of the key of `length` bytes at `key` into `out` (RFC 6455 §4.2.2).
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_accept(const uint8_t* key, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a client's HTTP/1.1 request for `path` of `authority` over `scheme` into `out_request`
 * and its key into `out_key` (RFC 6455 §4.1), offering the `count` subprotocols and
 * permessage-deflate of `deflate` (none if null); the key's randomness is seeded by the
 * `seed_length` bytes at `seed` (at least 48).
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_request(const uint8_t* scheme, size_t scheme_length, const uint8_t* authority, size_t authority_length, const uint8_t* path, size_t path_length, const uint8_t* const* protocols, const size_t* lengths, size_t count, const umilib_protocol_websocket_WebSocketDeflateParameters* deflate, const uint8_t* seed, size_t seed_length, umilib_protocol_http_HTTPRequest** out_request, umilib_ffi_Buffer* out_key);

/**
 * Writes a client's extended CONNECT over HTTP/2 or HTTP/3 into `out` (RFC 8441 §4, RFC 9220 §3),
 * offering the `count` subprotocols and permessage-deflate of `deflate` (none if null).
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_connect_request(const uint8_t* scheme, size_t scheme_length, const uint8_t* authority, size_t authority_length, const uint8_t* path, size_t path_length, const uint8_t* const* protocols, const size_t* lengths, size_t count, const umilib_protocol_websocket_WebSocketDeflateParameters* deflate, umilib_protocol_http_HTTPRequest** out);

/**
 * A server checks `request`, which came over HTTP `major`.`minor`: writes its offer into
 * `out_offer` and null into `out_response`, or, if it is not a handshake to accept, null and
 * the response to send (400, or 426 for another WebSocket version).
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_check_request(const umilib_protocol_http_HTTPRequest* request, uint8_t major, uint8_t minor, umilib_protocol_http_websocket_WebSocketOffer** out_offer, umilib_protocol_http_HTTPResponse** out_response);

/**
 * Writes the client's key (none over HTTP/2 and HTTP/3) into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_offer_key(const umilib_protocol_http_websocket_WebSocketOffer* offer, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the number of subprotocols offered into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_offer_protocol_count(const umilib_protocol_http_websocket_WebSocketOffer* offer, size_t* out);

/**
 * Writes the subprotocol `index`, in the client's order of preference, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_offer_protocol(const umilib_protocol_http_websocket_WebSocketOffer* offer, size_t index, umilib_ffi_Buffer* out);

/**
 * Writes the number of valid offers of permessage-deflate into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_offer_deflate_count(const umilib_protocol_http_websocket_WebSocketOffer* offer, size_t* out);

/**
 * Writes the offer of permessage-deflate `index`, in the client's order, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_offer_deflate(const umilib_protocol_http_websocket_WebSocketOffer* offer, size_t index, umilib_protocol_websocket_WebSocketDeflateParameters* out);

/**
 * Releases an offer. Does nothing if `offer` is null.
 */
void umilib_protocol_http_websocket_websocket_offer_free(umilib_protocol_http_websocket_WebSocketOffer* offer);

/**
 * Writes the agreement of a server into `out`: the first of the `count` subprotocols it
 * supports that the client offered, and the client's first offer of permessage-deflate if `deflate`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_agree(const umilib_protocol_http_websocket_WebSocketOffer* offer, const uint8_t* const* protocols, const size_t* lengths, size_t count, bool deflate, umilib_protocol_http_websocket_WebSocketAgreement** out);

/**
 * Writes the response that accepts `offer` with `agreement` into `out`: 101 over HTTP/1.1, 200 otherwise.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_response(const umilib_protocol_http_websocket_WebSocketOffer* offer, const umilib_protocol_http_websocket_WebSocketAgreement* agreement, umilib_protocol_http_HTTPResponse** out);

/**
 * A client checks `response` against its key (null over HTTP/2 and HTTP/3), the `count`
 * subprotocols and the permessage-deflate (null for none) it offered; writes the agreement into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_handshake_check_response(const umilib_protocol_http_HTTPResponse* response, const uint8_t* key, size_t key_length, const uint8_t* const* protocols, const size_t* lengths, size_t count, const umilib_protocol_websocket_WebSocketDeflateParameters* deflate, umilib_protocol_http_websocket_WebSocketAgreement** out);

/**
 * Writes the subprotocol agreed into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_agreement_protocol(const umilib_protocol_http_websocket_WebSocketAgreement* agreement, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the parameters of permessage-deflate agreed into `out` and whether there are any into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_websocket_websocket_agreement_deflate(const umilib_protocol_http_websocket_WebSocketAgreement* agreement, bool* out_found, umilib_protocol_websocket_WebSocketDeflateParameters* out);

/**
 * Releases an agreement. Does nothing if `agreement` is null.
 */
void umilib_protocol_http_websocket_websocket_agreement_free(umilib_protocol_http_websocket_WebSocketAgreement* agreement);

#ifdef __cplusplus
}
#endif

#endif
