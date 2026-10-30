/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_MD_V5_H
#define UMILIB_HASH_MD_V5_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MD5 (RFC 1321), broken: for compatibility only.
 */
typedef struct umilib_hash_md_v5_MD5 umilib_hash_md_v5_MD5;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_new(umilib_hash_md_v5_MD5** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_md_v5_md5_free(umilib_hash_md_v5_MD5* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_clone(const umilib_hash_md_v5_MD5* state, umilib_hash_md_v5_MD5** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_update(umilib_hash_md_v5_MD5* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_finalize(umilib_hash_md_v5_MD5* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_finalize_reset(umilib_hash_md_v5_MD5* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_md_v5_md5_reset(umilib_hash_md_v5_MD5* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_md_v5_md5_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_md_v5_md5_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
