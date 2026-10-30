/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_SASL_H
#define UMILIB_AUTH_SASL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A GS2 header (RFC 5801 §4).
 */
typedef struct umilib_auth_sasl_GS2Header umilib_auth_sasl_GS2Header;

/**
 * Writes the registered name of the mechanism at `index` into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_sasl_mechanism_name(uint8_t index, umilib_ffi_Buffer* out);

/**
 * Writes whether the UTF-8 text at `name` names a mechanism this library implements into
 * `out_found` and, if so, its index into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_sasl_mechanism_from_name(const uint8_t* name, size_t length, bool* out_found, uint8_t* out);

/**
 * Writes whether the UTF-8 text at `name` has the syntax of a mechanism name (RFC 4422 §3.1) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_sasl_mechanism_is_name(const uint8_t* name, size_t length, bool* out);

/**
 * Writes the GS2 header of the channel binding flag `kind` (with the type's name at `name`
 * for `p`, null otherwise), the non-standard flag `nonstandard` and the authorization identity
 * at `authzid` (null for none) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_new(uint8_t kind, const uint8_t* name, size_t name_length, bool nonstandard, const uint8_t* authzid, size_t authzid_length, umilib_auth_sasl_GS2Header** out);

/**
 * Writes the length of the header at the start of the UTF-8 text at `text` (where the rest
 * begins) into `out_length` and the header into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_decode(const uint8_t* text, size_t length, size_t* out_length, umilib_auth_sasl_GS2Header** out);

/**
 * Writes the text of the header into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_encode(const umilib_auth_sasl_GS2Header* header, umilib_ffi_Buffer* out);

/**
 * Writes the channel binding flag (0, 1 or 2) into `out_kind` and the type's name (empty unless
 * 2) into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_channel_binding(const umilib_auth_sasl_GS2Header* header, uint8_t* out_kind, umilib_ffi_Buffer* out);

/**
 * Writes the non-standard flag into `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_nonstandard(const umilib_auth_sasl_GS2Header* header, bool* out);

/**
 * Writes the authorization identity, if any, into `out_has` and `out`.
 */
const umilib_ffi_Status* umilib_auth_sasl_gs2_header_authzid(const umilib_auth_sasl_GS2Header* header, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Releases a header. Does nothing if `header` is null.
 */
void umilib_auth_sasl_gs2_header_free(umilib_auth_sasl_GS2Header* header);

#ifdef __cplusplus
}
#endif

#endif
