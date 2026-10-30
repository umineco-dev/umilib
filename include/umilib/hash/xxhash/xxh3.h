/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_XXHASH_XXH3_H
#define UMILIB_HASH_XXHASH_XXH3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XXH3 with 64 bits of output, keyed by a seed or a secret.
 */
typedef struct umilib_hash_xxhash_xxh3_XXH3_64 umilib_hash_xxhash_xxh3_XXH3_64;

/**
 * XXH3 with 128 bits of output (XXH128), keyed by a seed or a secret.
 */
typedef struct umilib_hash_xxhash_xxh3_XXH3_128 umilib_hash_xxhash_xxh3_XXH3_128;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_new(umilib_hash_xxhash_xxh3_XXH3_64** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_xxhash_xxh3_xxh3_64_free(umilib_hash_xxhash_xxh3_XXH3_64* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_clone(const umilib_hash_xxhash_xxh3_XXH3_64* state, umilib_hash_xxhash_xxh3_XXH3_64** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_update(umilib_hash_xxhash_xxh3_XXH3_64* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_finalize(umilib_hash_xxhash_xxh3_XXH3_64* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_finalize_reset(umilib_hash_xxhash_xxh3_XXH3_64* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_reset(umilib_hash_xxhash_xxh3_XXH3_64* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_xxhash_xxh3_xxh3_64_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_xxhash_xxh3_xxh3_64_block_size(void);

/**
 * Creates the function of the empty input with `seed`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_with_seed(uint64_t seed, umilib_hash_xxhash_xxh3_XXH3_64** out);

/**
 * Creates the function of the empty input with a copy of the secret at `secret`, of at
 * least 136 bytes.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_with_secret(const uint8_t* secret, size_t length, umilib_hash_xxhash_xxh3_XXH3_64** out);

/**
 * Writes the hash of the `length` bytes at `data` with `seed` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_hash(uint64_t seed, const uint8_t* data, size_t length, uint64_t* out);

/**
 * Writes the hash of the input so far into `out`, without changing the state.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_64_value(const umilib_hash_xxhash_xxh3_XXH3_64* state, uint64_t* out);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_new(umilib_hash_xxhash_xxh3_XXH3_128** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_xxhash_xxh3_xxh3_128_free(umilib_hash_xxhash_xxh3_XXH3_128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_clone(const umilib_hash_xxhash_xxh3_XXH3_128* state, umilib_hash_xxhash_xxh3_XXH3_128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_update(umilib_hash_xxhash_xxh3_XXH3_128* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_finalize(umilib_hash_xxhash_xxh3_XXH3_128* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_finalize_reset(umilib_hash_xxhash_xxh3_XXH3_128* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_reset(umilib_hash_xxhash_xxh3_XXH3_128* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_xxhash_xxh3_xxh3_128_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_xxhash_xxh3_xxh3_128_block_size(void);

/**
 * Creates the function of the empty input with `seed`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_with_seed(uint64_t seed, umilib_hash_xxhash_xxh3_XXH3_128** out);

/**
 * Creates the function of the empty input with a copy of the secret at `secret`, of at
 * least 136 bytes.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_with_secret(const uint8_t* secret, size_t length, umilib_hash_xxhash_xxh3_XXH3_128** out);

/**
 * Writes the hash of the `length` bytes at `data` with `seed` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_hash(uint64_t seed, const uint8_t* data, size_t length, umilib_ffi_U128* out);

/**
 * Writes the hash of the input so far into `out`, without changing the state.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh3_xxh3_128_value(const umilib_hash_xxhash_xxh3_XXH3_128* state, umilib_ffi_U128* out);

#ifdef __cplusplus
}
#endif

#endif
