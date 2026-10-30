/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_SHA_V3_H
#define UMILIB_HASH_SHA_V3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SHA3-224 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHA3_224 umilib_hash_sha_v3_SHA3_224;

/**
 * SHA3-256 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHA3_256 umilib_hash_sha_v3_SHA3_256;

/**
 * SHA3-384 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHA3_384 umilib_hash_sha_v3_SHA3_384;

/**
 * SHA3-512 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHA3_512 umilib_hash_sha_v3_SHA3_512;

/**
 * Keccak-224, with the padding of the Keccak submission.
 */
typedef struct umilib_hash_sha_v3_Keccak224 umilib_hash_sha_v3_Keccak224;

/**
 * Keccak-256, with the padding of the Keccak submission.
 */
typedef struct umilib_hash_sha_v3_Keccak256 umilib_hash_sha_v3_Keccak256;

/**
 * Keccak-384, with the padding of the Keccak submission.
 */
typedef struct umilib_hash_sha_v3_Keccak384 umilib_hash_sha_v3_Keccak384;

/**
 * Keccak-512, with the padding of the Keccak submission.
 */
typedef struct umilib_hash_sha_v3_Keccak512 umilib_hash_sha_v3_Keccak512;

/**
 * The output of a function with the rate of SHAKE128 (Sponge<168>).
 */
typedef struct umilib_hash_sha_v3_Sponge168 umilib_hash_sha_v3_Sponge168;

/**
 * The output of a function with the rate of SHAKE256 (Sponge<136>).
 */
typedef struct umilib_hash_sha_v3_Sponge136 umilib_hash_sha_v3_Sponge136;

/**
 * SHAKE128 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHAKE128 umilib_hash_sha_v3_SHAKE128;

/**
 * SHAKE256 (FIPS 202).
 */
typedef struct umilib_hash_sha_v3_SHAKE256 umilib_hash_sha_v3_SHAKE256;

/**
 * cSHAKE128 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_CSHAKE128 umilib_hash_sha_v3_CSHAKE128;

/**
 * cSHAKE256 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_CSHAKE256 umilib_hash_sha_v3_CSHAKE256;

/**
 * TupleHash128 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_TupleHash128 umilib_hash_sha_v3_TupleHash128;

/**
 * TupleHash256 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_TupleHash256 umilib_hash_sha_v3_TupleHash256;

/**
 * ParallelHash128 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_ParallelHash128 umilib_hash_sha_v3_ParallelHash128;

/**
 * ParallelHash256 (SP 800-185).
 */
typedef struct umilib_hash_sha_v3_ParallelHash256 umilib_hash_sha_v3_ParallelHash256;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_new(umilib_hash_sha_v3_SHA3_224** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_sha3_224_free(umilib_hash_sha_v3_SHA3_224* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_clone(const umilib_hash_sha_v3_SHA3_224* state, umilib_hash_sha_v3_SHA3_224** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_update(umilib_hash_sha_v3_SHA3_224* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_finalize(umilib_hash_sha_v3_SHA3_224* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_finalize_reset(umilib_hash_sha_v3_SHA3_224* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_224_reset(umilib_hash_sha_v3_SHA3_224* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_224_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_224_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_new(umilib_hash_sha_v3_SHA3_256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_sha3_256_free(umilib_hash_sha_v3_SHA3_256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_clone(const umilib_hash_sha_v3_SHA3_256* state, umilib_hash_sha_v3_SHA3_256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_update(umilib_hash_sha_v3_SHA3_256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_finalize(umilib_hash_sha_v3_SHA3_256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_finalize_reset(umilib_hash_sha_v3_SHA3_256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_256_reset(umilib_hash_sha_v3_SHA3_256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_256_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_new(umilib_hash_sha_v3_SHA3_384** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_sha3_384_free(umilib_hash_sha_v3_SHA3_384* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_clone(const umilib_hash_sha_v3_SHA3_384* state, umilib_hash_sha_v3_SHA3_384** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_update(umilib_hash_sha_v3_SHA3_384* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_finalize(umilib_hash_sha_v3_SHA3_384* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_finalize_reset(umilib_hash_sha_v3_SHA3_384* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_384_reset(umilib_hash_sha_v3_SHA3_384* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_384_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_384_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_new(umilib_hash_sha_v3_SHA3_512** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_sha3_512_free(umilib_hash_sha_v3_SHA3_512* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_clone(const umilib_hash_sha_v3_SHA3_512* state, umilib_hash_sha_v3_SHA3_512** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_update(umilib_hash_sha_v3_SHA3_512* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_finalize(umilib_hash_sha_v3_SHA3_512* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_finalize_reset(umilib_hash_sha_v3_SHA3_512* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sha3_512_reset(umilib_hash_sha_v3_SHA3_512* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_512_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_sha3_512_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_new(umilib_hash_sha_v3_Keccak224** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_keccak224_free(umilib_hash_sha_v3_Keccak224* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_clone(const umilib_hash_sha_v3_Keccak224* state, umilib_hash_sha_v3_Keccak224** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_update(umilib_hash_sha_v3_Keccak224* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_finalize(umilib_hash_sha_v3_Keccak224* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_finalize_reset(umilib_hash_sha_v3_Keccak224* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak224_reset(umilib_hash_sha_v3_Keccak224* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_keccak224_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_keccak224_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_new(umilib_hash_sha_v3_Keccak256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_keccak256_free(umilib_hash_sha_v3_Keccak256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_clone(const umilib_hash_sha_v3_Keccak256* state, umilib_hash_sha_v3_Keccak256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_update(umilib_hash_sha_v3_Keccak256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_finalize(umilib_hash_sha_v3_Keccak256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_finalize_reset(umilib_hash_sha_v3_Keccak256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak256_reset(umilib_hash_sha_v3_Keccak256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_keccak256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_keccak256_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_new(umilib_hash_sha_v3_Keccak384** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_keccak384_free(umilib_hash_sha_v3_Keccak384* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_clone(const umilib_hash_sha_v3_Keccak384* state, umilib_hash_sha_v3_Keccak384** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_update(umilib_hash_sha_v3_Keccak384* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_finalize(umilib_hash_sha_v3_Keccak384* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_finalize_reset(umilib_hash_sha_v3_Keccak384* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak384_reset(umilib_hash_sha_v3_Keccak384* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_keccak384_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_keccak384_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_new(umilib_hash_sha_v3_Keccak512** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_keccak512_free(umilib_hash_sha_v3_Keccak512* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_clone(const umilib_hash_sha_v3_Keccak512* state, umilib_hash_sha_v3_Keccak512** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_update(umilib_hash_sha_v3_Keccak512* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_finalize(umilib_hash_sha_v3_Keccak512* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_finalize_reset(umilib_hash_sha_v3_Keccak512* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak512_reset(umilib_hash_sha_v3_Keccak512* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v3_keccak512_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_keccak512_block_size(void);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_sha_v3_sponge168_free(umilib_hash_sha_v3_Sponge168* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sponge168_clone(const umilib_hash_sha_v3_Sponge168* reader, umilib_hash_sha_v3_Sponge168** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sponge168_read(umilib_hash_sha_v3_Sponge168* reader, uint8_t* out, size_t out_length);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_sha_v3_sponge136_free(umilib_hash_sha_v3_Sponge136* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sponge136_clone(const umilib_hash_sha_v3_Sponge136* reader, umilib_hash_sha_v3_Sponge136** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_sponge136_read(umilib_hash_sha_v3_Sponge136* reader, uint8_t* out, size_t out_length);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_new(umilib_hash_sha_v3_SHAKE128** out);

/**
 * Writes the first `out_length` output bytes for the `length` bytes at `data` into `out`,
 * which must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_digest_xof(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_shake128_free(umilib_hash_sha_v3_SHAKE128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_clone(const umilib_hash_sha_v3_SHAKE128* state, umilib_hash_sha_v3_SHAKE128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_update(umilib_hash_sha_v3_SHAKE128* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_finalize_xof(umilib_hash_sha_v3_SHAKE128* state, umilib_hash_sha_v3_Sponge168** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake128_reset(umilib_hash_sha_v3_SHAKE128* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_shake128_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_new(umilib_hash_sha_v3_SHAKE256** out);

/**
 * Writes the first `out_length` output bytes for the `length` bytes at `data` into `out`,
 * which must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_digest_xof(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_shake256_free(umilib_hash_sha_v3_SHAKE256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_clone(const umilib_hash_sha_v3_SHAKE256* state, umilib_hash_sha_v3_SHAKE256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_update(umilib_hash_sha_v3_SHAKE256* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_finalize_xof(umilib_hash_sha_v3_SHAKE256* state, umilib_hash_sha_v3_Sponge136** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_shake256_reset(umilib_hash_sha_v3_SHAKE256* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_shake256_block_size(void);

/**
 * Creates cSHAKE with the function name and the customization string, each a byte range;
 * with both empty it is SHAKE.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake128_new(const uint8_t* name, size_t name_length, const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_CSHAKE128** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_cshake128_free(umilib_hash_sha_v3_CSHAKE128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake128_clone(const umilib_hash_sha_v3_CSHAKE128* state, umilib_hash_sha_v3_CSHAKE128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake128_update(umilib_hash_sha_v3_CSHAKE128* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake128_finalize_xof(umilib_hash_sha_v3_CSHAKE128* state, umilib_hash_sha_v3_Sponge168** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake128_reset(umilib_hash_sha_v3_CSHAKE128* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_cshake128_block_size(void);

/**
 * Creates cSHAKE with the function name and the customization string, each a byte range;
 * with both empty it is SHAKE.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake256_new(const uint8_t* name, size_t name_length, const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_CSHAKE256** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_cshake256_free(umilib_hash_sha_v3_CSHAKE256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake256_clone(const umilib_hash_sha_v3_CSHAKE256* state, umilib_hash_sha_v3_CSHAKE256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake256_update(umilib_hash_sha_v3_CSHAKE256* state, const uint8_t* data, size_t length);

/**
 * Writes the reader of the output into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake256_finalize_xof(umilib_hash_sha_v3_CSHAKE256* state, umilib_hash_sha_v3_Sponge136** out);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_cshake256_reset(umilib_hash_sha_v3_CSHAKE256* state);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v3_cshake256_block_size(void);

/**
 * Creates TupleHash of the empty tuple with the customization string.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_new(const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_TupleHash128** out);

/**
 * Adds the `length` bytes at `element` as the next string of the tuple.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_push(umilib_hash_sha_v3_TupleHash128* state, const uint8_t* element, size_t length);

/**
 * Returns to the empty tuple.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_reset(umilib_hash_sha_v3_TupleHash128* state);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_tuple_hash128_free(umilib_hash_sha_v3_TupleHash128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_clone(const umilib_hash_sha_v3_TupleHash128* state, umilib_hash_sha_v3_TupleHash128** out);

/**
 * Writes `out_length` bytes of output, a length that is part of the input, into `out` and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_finalize(umilib_hash_sha_v3_TupleHash128* state, uint8_t* out, size_t out_length);

/**
 * Writes the reader of the XOF variant into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash128_finalize_xof(umilib_hash_sha_v3_TupleHash128* state, umilib_hash_sha_v3_Sponge168** out);

/**
 * Creates TupleHash of the empty tuple with the customization string.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_new(const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_TupleHash256** out);

/**
 * Adds the `length` bytes at `element` as the next string of the tuple.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_push(umilib_hash_sha_v3_TupleHash256* state, const uint8_t* element, size_t length);

/**
 * Returns to the empty tuple.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_reset(umilib_hash_sha_v3_TupleHash256* state);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_tuple_hash256_free(umilib_hash_sha_v3_TupleHash256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_clone(const umilib_hash_sha_v3_TupleHash256* state, umilib_hash_sha_v3_TupleHash256** out);

/**
 * Writes `out_length` bytes of output, a length that is part of the input, into `out` and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_finalize(umilib_hash_sha_v3_TupleHash256* state, uint8_t* out, size_t out_length);

/**
 * Writes the reader of the XOF variant into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_tuple_hash256_finalize_xof(umilib_hash_sha_v3_TupleHash256* state, umilib_hash_sha_v3_Sponge136** out);

/**
 * Creates ParallelHash with blocks of `block_size` bytes (not 0) and the customization string.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_new(size_t block_size, const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_ParallelHash128** out);

/**
 * Writes the block size in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_block_size(const umilib_hash_sha_v3_ParallelHash128* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_update(umilib_hash_sha_v3_ParallelHash128* state, const uint8_t* data, size_t length);

/**
 * Returns to the empty input with the same block size and customization.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_reset(umilib_hash_sha_v3_ParallelHash128* state);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_parallel_hash128_free(umilib_hash_sha_v3_ParallelHash128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_clone(const umilib_hash_sha_v3_ParallelHash128* state, umilib_hash_sha_v3_ParallelHash128** out);

/**
 * Writes `out_length` bytes of output, a length that is part of the input, into `out` and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_finalize(umilib_hash_sha_v3_ParallelHash128* state, uint8_t* out, size_t out_length);

/**
 * Writes the reader of the XOF variant into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash128_finalize_xof(umilib_hash_sha_v3_ParallelHash128* state, umilib_hash_sha_v3_Sponge168** out);

/**
 * Creates ParallelHash with blocks of `block_size` bytes (not 0) and the customization string.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_new(size_t block_size, const uint8_t* customization, size_t customization_length, umilib_hash_sha_v3_ParallelHash256** out);

/**
 * Writes the block size in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_block_size(const umilib_hash_sha_v3_ParallelHash256* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_update(umilib_hash_sha_v3_ParallelHash256* state, const uint8_t* data, size_t length);

/**
 * Returns to the empty input with the same block size and customization.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_reset(umilib_hash_sha_v3_ParallelHash256* state);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v3_parallel_hash256_free(umilib_hash_sha_v3_ParallelHash256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_clone(const umilib_hash_sha_v3_ParallelHash256* state, umilib_hash_sha_v3_ParallelHash256** out);

/**
 * Writes `out_length` bytes of output, a length that is part of the input, into `out` and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_finalize(umilib_hash_sha_v3_ParallelHash256* state, uint8_t* out, size_t out_length);

/**
 * Writes the reader of the XOF variant into `out` and releases the state. On failure the
 * state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v3_parallel_hash256_finalize_xof(umilib_hash_sha_v3_ParallelHash256* state, umilib_hash_sha_v3_Sponge136** out);

/**
 * Applies Keccak-f\[1600\] to the 25 lanes at `state` (lane x + 5y at index x + 5y).
 */
const umilib_ffi_Status* umilib_hash_sha_v3_keccak_f1600_permute(uint64_t* state);

#ifdef __cplusplus
}
#endif

#endif
