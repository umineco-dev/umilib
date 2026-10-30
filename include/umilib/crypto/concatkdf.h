/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_CONCATKDF_H
#define UMILIB_CRYPTO_CONCATKDF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The one-step KDF of SP 800-56C Rev. 2 over a hash function or HMAC.
 */
typedef struct umilib_crypto_concatkdf_ConcatKDF umilib_crypto_concatkdf_ConcatKDF;

/**
 * Creates the one-step KDF over the auxiliary function whose C type is named by the UTF-8 text at
 * `function` (`umilib_crypto_concatkdf_HashFunction` or `umilib_crypto_hmac_HMAC`), over the hash
 * function whose C type is named by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`;
 * HMAC is keyed with the `salt_length` bytes at `salt`, which must be empty for a hash function.
 * Fails with InvalidArgument if the function or the hash function is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_concatkdf_concat_kdf_new(const uint8_t* function, size_t function_length, const uint8_t* hash, size_t hash_length, const uint8_t* salt, size_t salt_length, umilib_crypto_concatkdf_ConcatKDF** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_concatkdf_concat_kdf_free(umilib_crypto_concatkdf_ConcatKDF* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_concatkdf_concat_kdf_clone(const umilib_crypto_concatkdf_ConcatKDF* state, umilib_crypto_concatkdf_ConcatKDF** out);

/**
 * Fills the `length` bytes at `out` with K(1) || K(2) || ..., K(i) = H(\[i\]_32 || Z || FixedInfo),
 * from the shared secret at `z` and the fixed information at `fixed_info`, which must not overlap
 * `out`.
 */
const umilib_ffi_Status* umilib_crypto_concatkdf_concat_kdf_derive(const umilib_crypto_concatkdf_ConcatKDF* state, const uint8_t* z, size_t z_length, const uint8_t* fixed_info, size_t fixed_info_length, uint8_t* out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
