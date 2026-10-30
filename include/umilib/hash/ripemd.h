/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_RIPEMD_H
#define UMILIB_HASH_RIPEMD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RIPEMD-128.
 */
typedef struct umilib_hash_ripemd_RIPEMD128 umilib_hash_ripemd_RIPEMD128;

/**
 * RIPEMD-160.
 */
typedef struct umilib_hash_ripemd_RIPEMD160 umilib_hash_ripemd_RIPEMD160;

/**
 * RIPEMD-256.
 */
typedef struct umilib_hash_ripemd_RIPEMD256 umilib_hash_ripemd_RIPEMD256;

/**
 * RIPEMD-320.
 */
typedef struct umilib_hash_ripemd_RIPEMD320 umilib_hash_ripemd_RIPEMD320;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_new(umilib_hash_ripemd_RIPEMD128** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ripemd_ripemd128_free(umilib_hash_ripemd_RIPEMD128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_clone(const umilib_hash_ripemd_RIPEMD128* state, umilib_hash_ripemd_RIPEMD128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_update(umilib_hash_ripemd_RIPEMD128* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_finalize(umilib_hash_ripemd_RIPEMD128* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_finalize_reset(umilib_hash_ripemd_RIPEMD128* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd128_reset(umilib_hash_ripemd_RIPEMD128* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_ripemd_ripemd128_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ripemd_ripemd128_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_new(umilib_hash_ripemd_RIPEMD160** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ripemd_ripemd160_free(umilib_hash_ripemd_RIPEMD160* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_clone(const umilib_hash_ripemd_RIPEMD160* state, umilib_hash_ripemd_RIPEMD160** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_update(umilib_hash_ripemd_RIPEMD160* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_finalize(umilib_hash_ripemd_RIPEMD160* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_finalize_reset(umilib_hash_ripemd_RIPEMD160* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd160_reset(umilib_hash_ripemd_RIPEMD160* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_ripemd_ripemd160_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ripemd_ripemd160_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_new(umilib_hash_ripemd_RIPEMD256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ripemd_ripemd256_free(umilib_hash_ripemd_RIPEMD256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_clone(const umilib_hash_ripemd_RIPEMD256* state, umilib_hash_ripemd_RIPEMD256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_update(umilib_hash_ripemd_RIPEMD256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_finalize(umilib_hash_ripemd_RIPEMD256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_finalize_reset(umilib_hash_ripemd_RIPEMD256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd256_reset(umilib_hash_ripemd_RIPEMD256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_ripemd_ripemd256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ripemd_ripemd256_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_new(umilib_hash_ripemd_RIPEMD320** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ripemd_ripemd320_free(umilib_hash_ripemd_RIPEMD320* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_clone(const umilib_hash_ripemd_RIPEMD320* state, umilib_hash_ripemd_RIPEMD320** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_update(umilib_hash_ripemd_RIPEMD320* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_finalize(umilib_hash_ripemd_RIPEMD320* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_finalize_reset(umilib_hash_ripemd_RIPEMD320* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ripemd_ripemd320_reset(umilib_hash_ripemd_RIPEMD320* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_ripemd_ripemd320_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ripemd_ripemd320_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
