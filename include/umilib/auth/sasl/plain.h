/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_PLAIN_H
#define UMILIB_AUTH_SASL_PLAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The message of PLAIN (RFC 4616).
 */
typedef struct umilib_auth_sasl_plain_PLAINMessage umilib_auth_sasl_plain_PLAINMessage;

/**
 * Writes the message of the authorization identity at `authzid` (null for none), the
 * authentication identity at `authcid` and the password at `password` (UTF-8) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_new(const uint8_t* authzid, size_t authzid_length, const uint8_t* authcid, size_t authcid_length, const uint8_t* password, size_t password_length, umilib_auth_sasl_plain_PLAINMessage** out);

/**
 * Writes the message of the `length` bytes at `data` (RFC 4616 §2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_decode(const uint8_t* data, size_t length, umilib_auth_sasl_plain_PLAINMessage** out);

/**
 * Writes the bytes of the message, which hold the password, into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_encode(const umilib_auth_sasl_plain_PLAINMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes the authorization identity, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_authzid(const umilib_auth_sasl_plain_PLAINMessage* message, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the authentication identity into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_authcid(const umilib_auth_sasl_plain_PLAINMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes the password into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_password(const umilib_auth_sasl_plain_PLAINMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes the authentication identity prepared with SASLprep as a query into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_prepared_authcid(const umilib_auth_sasl_plain_PLAINMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes whether the password matches the stored password at `stored` (both prepared with
 * SASLprep, compared in constant time) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_verify_password(const umilib_auth_sasl_plain_PLAINMessage* message, const uint8_t* stored, size_t length, bool* out);

/**
 * Writes the UTF-8 text at `text` prepared with SASLprep (`unassigned`: 0 for a query, 1 for a
 * stored string) into `out`; fails with Length for an empty result.
 */
const umilib_ffi_Status* umilib_auth_sasl_plain_plain_message_prepare(const uint8_t* text, size_t length, uint8_t unassigned, umilib_ffi_Buffer* out);

/**
 * Releases a message, zeroizing its password. Does nothing if `message` is null.
 */
void umilib_auth_sasl_plain_plain_message_free(umilib_auth_sasl_plain_PLAINMessage* message);

#ifdef __cplusplus
}
#endif

#endif
