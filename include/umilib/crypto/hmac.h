/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_HMAC_H
#define UMILIB_CRYPTO_HMAC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC (RFC 2104) over a hash function chosen when it is created.
 */
typedef struct umilib_crypto_hmac_HMAC umilib_crypto_hmac_HMAC;

/**
 * Creates HMAC with the `key_length` bytes at `key` over the hash function whose C type is named
 * by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with InvalidArgument
 * if that hash function is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_new(const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, umilib_crypto_hmac_HMAC** out);

/**
 * Writes the tag of the `length` bytes at `data` under the key into the `out_length` bytes at
 * `out`, which must be the output size of the hash function named as in `umilib_crypto_hmac_hmac_new`
 * and must not overlap the other arguments.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_mac(const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_hmac_hmac_free(umilib_crypto_hmac_HMAC* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_clone(const umilib_crypto_hmac_HMAC* state, umilib_crypto_hmac_HMAC** out);

/**
 * Adds the `length` bytes at `data` to the message.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_update(umilib_crypto_hmac_HMAC* state, const uint8_t* data, size_t length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and releases
 * the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_finalize(umilib_crypto_hmac_HMAC* state, uint8_t* out, size_t out_length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and returns
 * the state to the key.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_finalize_reset(umilib_crypto_hmac_HMAC* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to the key.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_reset(umilib_crypto_hmac_HMAC* state);

/**
 * Writes into `out` whether the `length` bytes at `tag` are the tag of the message, compared in
 * constant time, and releases the state.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_verify(umilib_crypto_hmac_HMAC* state, const uint8_t* tag, size_t length, bool* out);

/**
 * Like `umilib_crypto_hmac_hmac_verify` for a tag truncated to its leftmost bytes, of at least the
 * minimum truncated length.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_verify_truncated(umilib_crypto_hmac_HMAC* state, const uint8_t* tag, size_t length, bool* out);

/**
 * Writes the output size of the hash function into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_output_size(const umilib_crypto_hmac_HMAC* state, size_t* out);

/**
 * Writes the shortest truncated tag that verification accepts (half of the output and at least
 * 80 bits) into `out`.
 */
const umilib_ffi_Status* umilib_crypto_hmac_hmac_minimum_truncated_length(const umilib_crypto_hmac_HMAC* state, size_t* out);

#ifdef __cplusplus
}
#endif

#endif
