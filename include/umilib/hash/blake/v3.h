/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_BLAKE_V3_H
#define UMILIB_HASH_BLAKE_V3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BLAKE3 in the hash, keyed hash or key derivation mode.
 */
typedef struct umilib_hash_blake_v3_BLAKE3 umilib_hash_blake_v3_BLAKE3;

/**
 * The output of BLAKE3, read in order from any position up to 2^64 bytes.
 */
typedef struct umilib_hash_blake_v3_BLAKE3Reader umilib_hash_blake_v3_BLAKE3Reader;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_new(umilib_hash_blake_v3_BLAKE3** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v3_blake3_free(umilib_hash_blake_v3_BLAKE3* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_clone(const umilib_hash_blake_v3_BLAKE3* state, umilib_hash_blake_v3_BLAKE3** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_update(umilib_hash_blake_v3_BLAKE3* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_finalize(umilib_hash_blake_v3_BLAKE3* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_finalize_reset(umilib_hash_blake_v3_BLAKE3* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_reset(umilib_hash_blake_v3_BLAKE3* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v3_blake3_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v3_blake3_block_size(void);

/**
 * Creates the keyed hash mode with the 32-byte key at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v3_BLAKE3** out);

/**
 * Creates the key derivation mode for the context string at `context`; the input is the key
 * material.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_with_context(const uint8_t* context, size_t length, umilib_hash_blake_v3_BLAKE3** out);

/**
 * Writes the 32-byte keyed hash of the `length` bytes at `data` under the 32-byte key into `out`,
 * which must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_keyed_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Writes the 32-byte key derived from the `material_length` bytes at `material` for the context
 * string into `out`, which must not overlap the context or the material.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_derive_key(const uint8_t* context, size_t context_length, const uint8_t* material, size_t material_length, uint8_t* out, size_t out_length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the state is
 * not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_finalize_xof(umilib_hash_blake_v3_BLAKE3* state, umilib_hash_blake_v3_BLAKE3Reader** out);

/**
 * Writes the first `out_length` output bytes of the hash mode for the `length` bytes at `data`
 * into `out`, which must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_digest_xof(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Writes the number of bytes read so far into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_reader_position(const umilib_hash_blake_v3_BLAKE3Reader* reader, uint64_t* out);

/**
 * Moves the reader to byte `position` of the output.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_reader_set_position(umilib_hash_blake_v3_BLAKE3Reader* reader, uint64_t position);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_blake_v3_blake3_reader_free(umilib_hash_blake_v3_BLAKE3Reader* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_reader_clone(const umilib_hash_blake_v3_BLAKE3Reader* reader, umilib_hash_blake_v3_BLAKE3Reader** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v3_blake3_reader_read(umilib_hash_blake_v3_BLAKE3Reader* reader, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
