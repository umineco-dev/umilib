/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_POLY1305_H
#define UMILIB_CRYPTO_POLY1305_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Poly1305 (RFC 8439 section 2.5): a one-time MAC; a key must authenticate one message only.
 */
typedef struct umilib_crypto_poly1305_Poly1305 umilib_crypto_poly1305_Poly1305;

/**
 * Creates Poly1305 with the one-time key of 32 bytes (r, then s) at `key`.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_new(const uint8_t* key, size_t key_length, umilib_crypto_poly1305_Poly1305** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_poly1305_poly1305_free(umilib_crypto_poly1305_Poly1305* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_clone(const umilib_crypto_poly1305_Poly1305* state, umilib_crypto_poly1305_Poly1305** out);

/**
 * Writes the output size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_output_size(const umilib_crypto_poly1305_Poly1305* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the message.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_update(umilib_crypto_poly1305_Poly1305* state, const uint8_t* data, size_t length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_finalize(umilib_crypto_poly1305_Poly1305* state, uint8_t* out, size_t out_length);

/**
 * Returns to the state after the key.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_reset(umilib_crypto_poly1305_Poly1305* state);

/**
 * Writes into `out` whether the `tag_length` bytes at `tag` are the tag of the message,
 * compared in constant time, and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_verify(umilib_crypto_poly1305_Poly1305* state, const uint8_t* tag, size_t tag_length, bool* out);

/**
 * Writes the 16-byte tag of the `length` bytes at `data` with the one-time key of 32 bytes at `key`
 * into the `out_length` bytes at `out`, which must be 16 and must not overlap the inputs.
 */
const umilib_ffi_Status* umilib_crypto_poly1305_poly1305_mac(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
