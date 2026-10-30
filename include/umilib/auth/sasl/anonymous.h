/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_ANONYMOUS_H
#define UMILIB_AUTH_SASL_ANONYMOUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The message of ANONYMOUS (RFC 4505).
 */
typedef struct umilib_auth_sasl_anonymous_ANONYMOUSMessage umilib_auth_sasl_anonymous_ANONYMOUSMessage;

/**
 * Writes the message of the trace information at `trace` (null for none) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_anonymous_anonymous_message_new(const uint8_t* trace, size_t length, umilib_auth_sasl_anonymous_ANONYMOUSMessage** out);

/**
 * Writes the message of the `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_anonymous_anonymous_message_decode(const uint8_t* data, size_t length, umilib_auth_sasl_anonymous_ANONYMOUSMessage** out);

/**
 * Writes the bytes of the message into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_anonymous_anonymous_message_encode(const umilib_auth_sasl_anonymous_ANONYMOUSMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes the trace information, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_anonymous_anonymous_message_trace(const umilib_auth_sasl_anonymous_ANONYMOUSMessage* message, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes whether the trace information has the form of an email address (it holds `@`) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_anonymous_anonymous_message_is_email(const umilib_auth_sasl_anonymous_ANONYMOUSMessage* message, bool* out);

/**
 * Releases a message. Does nothing if `message` is null.
 */
void umilib_auth_sasl_anonymous_anonymous_message_free(umilib_auth_sasl_anonymous_ANONYMOUSMessage* message);

#ifdef __cplusplus
}
#endif

#endif
