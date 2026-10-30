/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_DNS_HTTPS_H
#define UMILIB_PROTOCOL_DNS_HTTPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the path of the GET request of the query of the `length` bytes at `query` to the path
 * of the text at `path` ("/dns-query"), the message in its "dns" variable as base64url without
 * padding (RFC 8484 §4.1), into `out`; fails with Malformed for bytes that are not a message.
 */
const umilib_ffi_Status* umilib_protocol_dns_https_dns_https_get_path(const uint8_t* query, size_t length, const uint8_t* path, size_t path_length, umilib_ffi_Buffer* out);

/**
 * Writes the query of a request of the method of the text at `method`, the path of `path`, the
 * Content-Type of `content_type` (none if its length is 0) and the `length` bytes of content at
 * `content` into `out`, and into `out_status` 0, or the status to answer with (405, 415, 413,
 * 414 or 400, RFC 8484 §4.1).
 */
const umilib_ffi_Status* umilib_protocol_dns_https_dns_https_query(const uint8_t* method, size_t method_length, const uint8_t* path, size_t path_length, const uint8_t* content_type, size_t content_type_length, const uint8_t* content, size_t length, uint16_t* out_status, umilib_ffi_Buffer* out);

/**
 * Writes the Cache-Control value of the 200 response of the DNS response of the `length` bytes
 * at `message` (its least TTL, RFC 8484 §5.1) into `out`; fails with Malformed.
 */
const umilib_ffi_Status* umilib_protocol_dns_https_dns_https_cache_control(const uint8_t* message, size_t length, umilib_ffi_Buffer* out);

/**
 * Checks the HTTP response of `status`, the Content-Type of `content_type` and the content of the
 * `length` bytes at `content` (RFC 8484 §4.2.1: a 2xx of "application/dns-message"); fails with Malformed.
 */
const umilib_ffi_Status* umilib_protocol_dns_https_dns_https_check_response(uint16_t status, const uint8_t* content_type, size_t content_type_length, const uint8_t* content, size_t length);

#ifdef __cplusplus
}
#endif

#endif
