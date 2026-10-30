/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_ASCON_H
#define UMILIB_HASH_ASCON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Ascon-Hash256 (SP 800-232).
 */
typedef struct umilib_hash_ascon_AsconHash256 umilib_hash_ascon_AsconHash256;

/**
 * The output of Ascon-XOF128 or Ascon-CXOF128.
 */
typedef struct umilib_hash_ascon_AsconReader umilib_hash_ascon_AsconReader;

/**
 * Ascon-XOF128 (SP 800-232).
 */
typedef struct umilib_hash_ascon_AsconXOF128 umilib_hash_ascon_AsconXOF128;

/**
 * Ascon-CXOF128 (SP 800-232): Ascon-XOF128 with a customization string.
 */
typedef struct umilib_hash_ascon_AsconCXOF128 umilib_hash_ascon_AsconCXOF128;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_new(umilib_hash_ascon_AsconHash256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ascon_ascon_hash256_free(umilib_hash_ascon_AsconHash256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_clone(const umilib_hash_ascon_AsconHash256* state, umilib_hash_ascon_AsconHash256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_update(umilib_hash_ascon_AsconHash256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_finalize(umilib_hash_ascon_AsconHash256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_finalize_reset(umilib_hash_ascon_AsconHash256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_hash256_reset(umilib_hash_ascon_AsconHash256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_ascon_ascon_hash256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ascon_ascon_hash256_block_size(void);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_ascon_ascon_reader_free(umilib_hash_ascon_AsconReader* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_reader_clone(const umilib_hash_ascon_AsconReader* reader, umilib_hash_ascon_AsconReader** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_reader_read(umilib_hash_ascon_AsconReader* reader, uint8_t* out, size_t out_length);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_new(umilib_hash_ascon_AsconXOF128** out);

/**
 * Writes the first `out_length` output bytes for the `length` bytes at `data` into `out`,
 * which must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_digest_xof(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ascon_ascon_xof128_free(umilib_hash_ascon_AsconXOF128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_clone(const umilib_hash_ascon_AsconXOF128* state, umilib_hash_ascon_AsconXOF128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_update(umilib_hash_ascon_AsconXOF128* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_finalize_xof(umilib_hash_ascon_AsconXOF128* state, umilib_hash_ascon_AsconReader** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_xof128_reset(umilib_hash_ascon_AsconXOF128* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ascon_ascon_xof128_block_size(void);

/**
 * Creates Ascon-CXOF128 with the customization string of `length` bytes (at most 256) at
 * `customization`; fails with InvalidParameter if it is longer.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_cxof128_new(const uint8_t* customization, size_t length, umilib_hash_ascon_AsconCXOF128** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_ascon_ascon_cxof128_free(umilib_hash_ascon_AsconCXOF128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_cxof128_clone(const umilib_hash_ascon_AsconCXOF128* state, umilib_hash_ascon_AsconCXOF128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_cxof128_update(umilib_hash_ascon_AsconCXOF128* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_cxof128_finalize_xof(umilib_hash_ascon_AsconCXOF128* state, umilib_hash_ascon_AsconReader** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_cxof128_reset(umilib_hash_ascon_AsconCXOF128* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_ascon_ascon_cxof128_block_size(void);

/**
 * Applies Ascon-p\[`rounds`\] (1 to 16 rounds) to the 5 words at `state` (S0 to S4); fails with
 * InvalidArgument for another number of rounds.
 */
const umilib_ffi_Status* umilib_hash_ascon_ascon_permutation_permute(uint64_t* state, size_t rounds);

#ifdef __cplusplus
}
#endif

#endif
