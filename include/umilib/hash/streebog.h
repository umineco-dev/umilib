/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_STREEBOG_H
#define UMILIB_HASH_STREEBOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Streebog with 256 bits of output (GOST R 34.11-2012, RFC 6986).
 */
typedef struct umilib_hash_streebog_Streebog256 umilib_hash_streebog_Streebog256;

/**
 * Streebog with 512 bits of output (GOST R 34.11-2012, RFC 6986).
 */
typedef struct umilib_hash_streebog_Streebog512 umilib_hash_streebog_Streebog512;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_new(umilib_hash_streebog_Streebog256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_streebog_streebog256_free(umilib_hash_streebog_Streebog256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_clone(const umilib_hash_streebog_Streebog256* state, umilib_hash_streebog_Streebog256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_update(umilib_hash_streebog_Streebog256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_finalize(umilib_hash_streebog_Streebog256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_finalize_reset(umilib_hash_streebog_Streebog256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog256_reset(umilib_hash_streebog_Streebog256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_streebog_streebog256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_streebog_streebog256_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_new(umilib_hash_streebog_Streebog512** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_streebog_streebog512_free(umilib_hash_streebog_Streebog512* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_clone(const umilib_hash_streebog_Streebog512* state, umilib_hash_streebog_Streebog512** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_update(umilib_hash_streebog_Streebog512* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_finalize(umilib_hash_streebog_Streebog512* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_finalize_reset(umilib_hash_streebog_Streebog512* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_streebog_streebog512_reset(umilib_hash_streebog_Streebog512* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_streebog_streebog512_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_streebog_streebog512_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
