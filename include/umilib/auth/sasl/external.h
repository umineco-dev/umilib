/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_EXTERNAL_H
#define UMILIB_AUTH_SASL_EXTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The message of EXTERNAL (RFC 4422 appendix A).
 */
typedef struct umilib_auth_sasl_external_EXTERNALMessage umilib_auth_sasl_external_EXTERNALMessage;

/**
 * Writes the message of the authorization identity at `authzid` (null for none) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_external_external_message_new(const uint8_t* authzid, size_t length, umilib_auth_sasl_external_EXTERNALMessage** out);

/**
 * Writes the message of the `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_external_external_message_decode(const uint8_t* data, size_t length, umilib_auth_sasl_external_EXTERNALMessage** out);

/**
 * Writes the bytes of the message into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_external_external_message_encode(const umilib_auth_sasl_external_EXTERNALMessage* message, umilib_ffi_Buffer* out);

/**
 * Writes the authorization identity, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_external_external_message_authzid(const umilib_auth_sasl_external_EXTERNALMessage* message, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Releases a message. Does nothing if `message` is null.
 */
void umilib_auth_sasl_external_external_message_free(umilib_auth_sasl_external_EXTERNALMessage* message);

#ifdef __cplusplus
}
#endif

#endif
