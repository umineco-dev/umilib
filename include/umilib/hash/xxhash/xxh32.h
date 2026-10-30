/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_XXHASH_XXH32_H
#define UMILIB_HASH_XXHASH_XXH32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XXH32 with a 32-bit seed.
 */
typedef struct umilib_hash_xxhash_xxh32_XXH32 umilib_hash_xxhash_xxh32_XXH32;

/**
 * Creates XXH32 of the empty input with the seed 0.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_new(umilib_hash_xxhash_xxh32_XXH32** out);

/**
 * Creates XXH32 of the empty input with `seed`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_with_seed(uint32_t seed, umilib_hash_xxhash_xxh32_XXH32** out);

/**
 * Writes the hash of the `length` bytes at `data` with the seed 0, in its canonical big-endian
 * form, into the `out_length` bytes at `out`, which must be 4 and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_xxhash_xxh32_xxh32_free(umilib_hash_xxhash_xxh32_XXH32* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_clone(const umilib_hash_xxhash_xxh32_XXH32* state, umilib_hash_xxhash_xxh32_XXH32** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_update(umilib_hash_xxhash_xxh32_XXH32* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_finalize(umilib_hash_xxhash_xxh32_XXH32* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_finalize_reset(umilib_hash_xxhash_xxh32_XXH32* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_reset(umilib_hash_xxhash_xxh32_XXH32* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_xxhash_xxh32_xxh32_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_xxhash_xxh32_xxh32_block_size(void);

/**
 * Writes the hash of the `length` bytes at `data` with `seed` into `out`.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_hash(uint32_t seed, const uint8_t* data, size_t length, uint32_t* out);

/**
 * Writes the hash of the input so far into `out`, without changing the state.
 */
const umilib_ffi_Status* umilib_hash_xxhash_xxh32_xxh32_value(const umilib_hash_xxhash_xxh32_XXH32* state, uint32_t* out);

#ifdef __cplusplus
}
#endif

#endif
