/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_HKDF_H
#define UMILIB_CRYPTO_HKDF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HKDF (RFC 5869) over a hash function chosen by name, keyed with a pseudorandom key.
 */
typedef struct umilib_crypto_hkdf_HKDF umilib_crypto_hkdf_HKDF;

/**
 * Creates HKDF with the pseudorandom key of at least HashLen bytes at `prk` over the hash function
 * whose C type is named by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with
 * InvalidArgument if that hash function is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_new(const uint8_t* hash, size_t hash_length, const uint8_t* prk, size_t prk_length, umilib_crypto_hkdf_HKDF** out);

/**
 * Creates HKDF with the PRK extracted from the salt and the input keying material (an empty salt is
 * HashLen zeros) over the hash function named by `hash`.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_from_secret(const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, const uint8_t* ikm, size_t ikm_length, umilib_crypto_hkdf_HKDF** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_hkdf_hkdf_free(umilib_crypto_hkdf_HKDF* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_clone(const umilib_crypto_hkdf_HKDF* state, umilib_crypto_hkdf_HKDF** out);

/**
 * HKDF-Expand: fills the `length` bytes at `okm` (at most 255 × HashLen) from the PRK and the info
 * string, which must not overlap `okm`.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_expand(const umilib_crypto_hkdf_HKDF* state, const uint8_t* info, size_t info_length, uint8_t* okm, size_t length);

/**
 * Writes the longest output, 255 × HashLen bytes, into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_maximum_output(const umilib_crypto_hkdf_HKDF* state, size_t* out);

/**
 * HKDF-Extract: writes the PRK of the salt and the input keying material into the `out_length`
 * bytes at `out`, which must be the output size of the hash function named by `hash` and must not
 * overlap the inputs.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_extract(const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, const uint8_t* ikm, size_t ikm_length, uint8_t* out, size_t out_length);

/**
 * Extract and Expand: fills the `length` bytes at `okm` from the salt, the input keying material
 * and the info string with the hash function named by `hash`; the inputs must not overlap `okm`.
 */
const umilib_ffi_Status* umilib_crypto_hkdf_hkdf_derive(const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, const uint8_t* ikm, size_t ikm_length, const uint8_t* info, size_t info_length, uint8_t* okm, size_t length);

#ifdef __cplusplus
}
#endif

#endif
