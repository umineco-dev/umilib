/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_SHA_V2_H
#define UMILIB_HASH_SHA_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SHA-224 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA224 umilib_hash_sha_v2_SHA224;

/**
 * SHA-256 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA256 umilib_hash_sha_v2_SHA256;

/**
 * SHA-384 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA384 umilib_hash_sha_v2_SHA384;

/**
 * SHA-512 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA512 umilib_hash_sha_v2_SHA512;

/**
 * SHA-512/224 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA512_224 umilib_hash_sha_v2_SHA512_224;

/**
 * SHA-512/256 (FIPS 180-4).
 */
typedef struct umilib_hash_sha_v2_SHA512_256 umilib_hash_sha_v2_SHA512_256;

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_new(umilib_hash_sha_v2_SHA224** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha224_free(umilib_hash_sha_v2_SHA224* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_clone(const umilib_hash_sha_v2_SHA224* state, umilib_hash_sha_v2_SHA224** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_update(umilib_hash_sha_v2_SHA224* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_finalize(umilib_hash_sha_v2_SHA224* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_finalize_reset(umilib_hash_sha_v2_SHA224* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha224_reset(umilib_hash_sha_v2_SHA224* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha224_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha224_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_new(umilib_hash_sha_v2_SHA256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha256_free(umilib_hash_sha_v2_SHA256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_clone(const umilib_hash_sha_v2_SHA256* state, umilib_hash_sha_v2_SHA256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_update(umilib_hash_sha_v2_SHA256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_finalize(umilib_hash_sha_v2_SHA256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_finalize_reset(umilib_hash_sha_v2_SHA256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha256_reset(umilib_hash_sha_v2_SHA256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha256_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_new(umilib_hash_sha_v2_SHA384** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha384_free(umilib_hash_sha_v2_SHA384* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_clone(const umilib_hash_sha_v2_SHA384* state, umilib_hash_sha_v2_SHA384** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_update(umilib_hash_sha_v2_SHA384* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_finalize(umilib_hash_sha_v2_SHA384* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_finalize_reset(umilib_hash_sha_v2_SHA384* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha384_reset(umilib_hash_sha_v2_SHA384* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha384_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha384_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_new(umilib_hash_sha_v2_SHA512** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha512_free(umilib_hash_sha_v2_SHA512* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_clone(const umilib_hash_sha_v2_SHA512* state, umilib_hash_sha_v2_SHA512** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_update(umilib_hash_sha_v2_SHA512* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_finalize(umilib_hash_sha_v2_SHA512* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_finalize_reset(umilib_hash_sha_v2_SHA512* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_reset(umilib_hash_sha_v2_SHA512* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_new(umilib_hash_sha_v2_SHA512_224** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha512_224_free(umilib_hash_sha_v2_SHA512_224* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_clone(const umilib_hash_sha_v2_SHA512_224* state, umilib_hash_sha_v2_SHA512_224** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_update(umilib_hash_sha_v2_SHA512_224* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_finalize(umilib_hash_sha_v2_SHA512_224* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_finalize_reset(umilib_hash_sha_v2_SHA512_224* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_224_reset(umilib_hash_sha_v2_SHA512_224* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_224_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_224_block_size(void);

/**
 * Creates the state of the empty input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_new(umilib_hash_sha_v2_SHA512_256** out);

/**
 * Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
 * which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_sha_v2_sha512_256_free(umilib_hash_sha_v2_SHA512_256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_clone(const umilib_hash_sha_v2_SHA512_256* state, umilib_hash_sha_v2_SHA512_256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_update(umilib_hash_sha_v2_SHA512_256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_finalize(umilib_hash_sha_v2_SHA512_256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_finalize_reset(umilib_hash_sha_v2_SHA512_256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_sha_v2_sha512_256_reset(umilib_hash_sha_v2_SHA512_256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_sha_v2_sha512_256_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
