/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_TCP_H
#define UMILIB_PROTOCOL_DNS_TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/protocol/dns.h"
#include "umilib/protocol/ip.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The framing of DNS messages on a stream.
 */
typedef struct umilib_protocol_dns_tcp_DNSTCPFramer umilib_protocol_dns_tcp_DNSTCPFramer;

/**
 * A server's connection over TCP.
 */
typedef struct umilib_protocol_dns_tcp_DNSTCPServer umilib_protocol_dns_tcp_DNSTCPServer;

/**
 * Writes the `length` bytes at `message` after their length in two bytes (RFC 1035 §4.2.2) into
 * `out`; fails with TooLarge above 65535 bytes.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_framer_frame(const uint8_t* message, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes a framer of nothing received into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_framer_new(umilib_protocol_dns_tcp_DNSTCPFramer** out);

/**
 * Releases a framer. Does nothing if `framer` is null.
 */
void umilib_protocol_dns_tcp_dns_tcp_framer_free(umilib_protocol_dns_tcp_DNSTCPFramer* framer);

/**
 * Takes the `length` bytes at `bytes` of the stream.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_framer_receive(umilib_protocol_dns_tcp_DNSTCPFramer* framer, const uint8_t* bytes, size_t length);

/**
 * Writes whether a whole message is received into `out_found` and the message into `out`; fails
 * with Malformed for a length of 0.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_framer_next_message(umilib_protocol_dns_tcp_DNSTCPFramer* framer, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes a server's connection with `peer`, idle after `idle_timeout` milliseconds and after
 * `read_timeout` with a query partly received, opened at `now`, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_server_new(umilib_protocol_ip_IPEndpoint peer, uint32_t idle_timeout, uint32_t read_timeout, uint64_t now, umilib_protocol_dns_tcp_DNSTCPServer** out);

/**
 * Releases a server's connection. Does nothing if `server` is null.
 */
void umilib_protocol_dns_tcp_dns_tcp_server_free(umilib_protocol_dns_tcp_DNSTCPServer* server);

/**
 * Takes the `length` bytes at `bytes` of the stream and answers each whole query with
 * `authority` at `now` and `time`; fails with Malformed for a length of 0, which ends the connection.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_server_receive(umilib_protocol_dns_tcp_DNSTCPServer* server, const uint8_t* bytes, size_t length, const umilib_protocol_dns_DNSAuthority* authority, uint64_t now, uint32_t time);

/**
 * Writes the bytes to send into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_server_transmit(umilib_protocol_dns_tcp_DNSTCPServer* server, umilib_ffi_Buffer* out);

/**
 * Writes whether the connection should be closed at `now` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_dns_tcp_dns_tcp_server_is_idle(const umilib_protocol_dns_tcp_DNSTCPServer* server, uint64_t now, bool* out);

#ifdef __cplusplus
}
#endif

#endif
