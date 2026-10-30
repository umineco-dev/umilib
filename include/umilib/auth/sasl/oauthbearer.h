/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_OAUTHBEARER_H
#define UMILIB_AUTH_SASL_OAUTHBEARER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/auth/sasl.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The initial client response of OAUTHBEARER (RFC 7628).
 */
typedef struct umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage;

/**
 * The error result of a failed OAUTHBEARER exchange (RFC 7628).
 */
typedef struct umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult;

/**
 * Writes the response of the bearer token at `token`, with the authorization identity at
 * `authzid` and the host at `host` (null for none) and `port` (if `has_port`), into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_new(const uint8_t* authzid, size_t authzid_length, const uint8_t* token, size_t token_length, const uint8_t* host, size_t host_length, uint16_t port, bool has_port, umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage** out);

/**
 * Writes the response of the `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_decode(const uint8_t* data, size_t length, umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage** out);

/**
 * Writes the bytes of the response into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_encode(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes whether the `length` bytes at `data` are the dummy response into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_is_dummy(const uint8_t* data, size_t length, bool* out);

/**
 * Writes a copy of the GS2 header into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_header(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, umilib_auth_sasl_GS2Header** out);

/**
 * Writes the value of the key named by the UTF-8 text at `key`, if present, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_get(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, const uint8_t* key, size_t key_length, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the number of key/value pairs into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_pair_count(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, size_t* out);

/**
 * Writes the key of the pair at `index` into `out_key` and its value into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_pair(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, size_t index, umilib_ffi_Buffer* out_key, umilib_ffi_Buffer* out);

/**
 * Writes the port, if present and valid, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_port(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, bool* out_has, uint16_t* out);

/**
 * Writes the bearer token of `auth`, if it is one, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_message_bearer_token(const umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Releases a response. Does nothing if `message` is null.
 */
void umilib_auth_sasl_oauthbearer_oauthbearer_message_free(umilib_auth_sasl_oauthbearer_OAUTHBEARERMessage* message);

/**
 * Writes the error result of the status at `status`, with the scope at `scope` and the OpenID
 * configuration URL at `configuration` (null for none), into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_error_result_new(const uint8_t* status, size_t status_length, const uint8_t* scope, size_t scope_length, const uint8_t* configuration, size_t configuration_length, umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult** out);

/**
 * Writes the error result of the JSON at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_error_result_decode(const uint8_t* data, size_t length, umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult** out);

/**
 * Writes the JSON of the error result into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_error_result_encode(const umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult* result, umilib_ffi_Buffer* out);

/**
 * Writes the status into `out_status`, the scope (if any) into `out_has_scope` and `out_scope`,
 * and the OpenID configuration URL (if any) into `out_has_configuration` and `out_configuration`.
 */
const umilib_ffi_Status* umilib_auth_sasl_oauthbearer_oauthbearer_error_result_parts(const umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult* result, umilib_ffi_Buffer* out_status, bool* out_has_scope, umilib_ffi_Buffer* out_scope, bool* out_has_configuration, umilib_ffi_Buffer* out_configuration);

/**
 * Releases an error result. Does nothing if `result` is null.
 */
void umilib_auth_sasl_oauthbearer_oauthbearer_error_result_free(umilib_auth_sasl_oauthbearer_OAUTHBEARERErrorResult* result);

#ifdef __cplusplus
}
#endif

#endif
