/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_HTTP_H
#define UMILIB_PROTOCOL_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits every version of HTTP keeps on what a peer sends.
 */
typedef struct umilib_protocol_http_HTTPConfig {
    size_t maximum_field_section_size;
    size_t maximum_target_length;
    size_t maximum_buffered_content;
    size_t maximum_events;
} umilib_protocol_http_HTTPConfig;

/**
 * An event of an HTTP connection.
 */
typedef struct umilib_protocol_http_HTTPEvent {
    uint8_t kind;
    uint64_t stream;
    bool end;
    uint64_t code;
    uint8_t error;
} umilib_protocol_http_HTTPEvent;

/**
 * A header or trailer section.
 */
typedef struct umilib_protocol_http_HTTPFields umilib_protocol_http_HTTPFields;

/**
 * The head of an HTTP request.
 */
typedef struct umilib_protocol_http_HTTPRequest umilib_protocol_http_HTTPRequest;

/**
 * The head of an HTTP response.
 */
typedef struct umilib_protocol_http_HTTPResponse umilib_protocol_http_HTTPResponse;

/**
 * A rule that routes HTTP requests.
 */
typedef struct umilib_protocol_http_HTTPRule umilib_protocol_http_HTTPRule;

/**
 * Writes the default limits into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_config_default(umilib_protocol_http_HTTPConfig* out);

/**
 * Writes the reason phrase of the status code `status` into `out` (empty if it has none).
 */
const umilib_ffi_Status* umilib_protocol_http_http_status_reason(uint16_t status, umilib_ffi_Buffer* out);

/**
 * Writes an empty field section into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_new(umilib_protocol_http_HTTPFields** out);

/**
 * Appends the field of `name` (lowercased) and `value`; fails with Malformed if either is not valid (RFC 9110 §5).
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_append(umilib_protocol_http_HTTPFields* fields, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Replaces the fields of `name` with one of `value`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_set(umilib_protocol_http_HTTPFields* fields, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Removes the fields of `name`; writes whether there were any into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_remove(umilib_protocol_http_HTTPFields* fields, const uint8_t* name, size_t length, bool* out);

/**
 * Writes the values of the fields of `name`, joined by ", " (RFC 9110 §5.3), into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_get(const umilib_protocol_http_HTTPFields* fields, const uint8_t* name, size_t length, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the number of field lines into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_count(const umilib_protocol_http_HTTPFields* fields, size_t* out);

/**
 * Writes the name and value of the field line `index` into `out_name` and `out_value`, and
 * whether it is sensitive into `out_sensitive`; fails with NoSuchField past the end.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_line(const umilib_protocol_http_HTTPFields* fields, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value, bool* out_sensitive);

/**
 * Marks the field line `index` sensitive or not: a sensitive one is never indexed by HPACK or QPACK.
 */
const umilib_ffi_Status* umilib_protocol_http_http_fields_set_sensitive(umilib_protocol_http_HTTPFields* fields, size_t index, bool sensitive);

/**
 * Releases a field section. Does nothing if `fields` is null.
 */
void umilib_protocol_http_http_fields_free(umilib_protocol_http_HTTPFields* fields);

/**
 * Writes a request of `method` for `path` of `authority` over `scheme` into `out`, without fields;
 * fails with Malformed for a method that is not a token.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_new(const uint8_t* method, size_t method_length, const uint8_t* scheme, size_t scheme_length, const uint8_t* authority, size_t authority_length, const uint8_t* path, size_t path_length, umilib_protocol_http_HTTPRequest** out);

/**
 * Writes a CONNECT request for a tunnel to `authority` into `out` (RFC 9110 §9.3.6).
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_connect(const uint8_t* authority, size_t length, umilib_protocol_http_HTTPRequest** out);

/**
 * Writes the method into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_method(const umilib_protocol_http_HTTPRequest* request, umilib_ffi_Buffer* out);

/**
 * Writes the scheme into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_scheme(const umilib_protocol_http_HTTPRequest* request, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the authority (of the target, else of the Host field) into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_host(const umilib_protocol_http_HTTPRequest* request, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Writes the path and query (empty for CONNECT) into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_path(const umilib_protocol_http_HTTPRequest* request, umilib_ffi_Buffer* out);

/**
 * Writes the protocol of an extended CONNECT (RFC 8441 §4) into `out` and whether there is one into `out_found`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_protocol(const umilib_protocol_http_HTTPRequest* request, bool* out_found, umilib_ffi_Buffer* out);

/**
 * Sets the protocol of an extended CONNECT to the `length` bytes at `protocol`, or none if it is null.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_set_protocol(umilib_protocol_http_HTTPRequest* request, const uint8_t* protocol, size_t length);

/**
 * Writes a copy of the request's header fields into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_fields(const umilib_protocol_http_HTTPRequest* request, umilib_protocol_http_HTTPFields** out);

/**
 * Sets the request's header fields to a copy of `fields`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_set_fields(umilib_protocol_http_HTTPRequest* request, const umilib_protocol_http_HTTPFields* fields);

/**
 * Checks the rules of the head every version shares (RFC 9110 §7.1, §9.3.6, RFC 8441 §4).
 */
const umilib_ffi_Status* umilib_protocol_http_http_request_check(const umilib_protocol_http_HTTPRequest* request);

/**
 * Releases a request. Does nothing if `request` is null.
 */
void umilib_protocol_http_http_request_free(umilib_protocol_http_HTTPRequest* request);

/**
 * Writes a response of `status` (100 to 599) into `out`, without fields.
 */
const umilib_ffi_Status* umilib_protocol_http_http_response_new(uint16_t status, umilib_protocol_http_HTTPResponse** out);

/**
 * Writes the status code into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_response_status(const umilib_protocol_http_HTTPResponse* response, uint16_t* out);

/**
 * Writes a copy of the response's header fields into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_response_fields(const umilib_protocol_http_HTTPResponse* response, umilib_protocol_http_HTTPFields** out);

/**
 * Sets the response's header fields to a copy of `fields`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_response_set_fields(umilib_protocol_http_HTTPResponse* response, const umilib_protocol_http_HTTPFields* fields);

/**
 * Releases a response. Does nothing if `response` is null.
 */
void umilib_protocol_http_http_response_free(umilib_protocol_http_HTTPResponse* response);

/**
 * Writes the rule of the requests whose host (without case) and path match the patterns of
 * the texts `host` and `path` into `out`; fails with InvalidPattern.
 */
const umilib_ffi_Status* umilib_protocol_http_http_rule_new(const uint8_t* host, size_t host_length, const uint8_t* path, size_t path_length, umilib_protocol_http_HTTPRule** out);

/**
 * Makes the rule match requests of `method` only.
 */
const umilib_ffi_Status* umilib_protocol_http_http_rule_set_method(umilib_protocol_http_HTTPRule* rule, const uint8_t* method, size_t length);

/**
 * Makes the rule match requests with a field `name` whose value matches the pattern of the text `value`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_rule_add_field(umilib_protocol_http_HTTPRule* rule, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Writes whether `request` matches the rule into `out`.
 */
const umilib_ffi_Status* umilib_protocol_http_http_rule_matches(const umilib_protocol_http_HTTPRule* rule, const umilib_protocol_http_HTTPRequest* request, bool* out);

/**
 * Releases a rule. Does nothing if `rule` is null.
 */
void umilib_protocol_http_http_rule_free(umilib_protocol_http_HTTPRule* rule);

#ifdef __cplusplus
}
#endif

#endif
