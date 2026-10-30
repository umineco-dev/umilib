/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_SIPHASH_H
#define UMILIB_HASH_SIPHASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SipHash-2-4 with 64 bits of output and a 128-bit key.
 */
typedef struct umilib_hash_siphash_SipHash24 umilib_hash_siphash_SipHash24;

/**
 * SipHash-1-3 with 64 bits of output and a 128-bit key.
 */
typedef struct umilib_hash_siphash_SipHash13 umilib_hash_siphash_SipHash13;

/**
 * SipHash-2-4 with 128 bits of output and a 128-bit key.
 */
typedef struct umilib_hash_siphash_SipHash128_24 umilib_hash_siphash_SipHash128_24;

/**
 * SipHash-1-3 with 128 bits of output and a 128-bit key.
 */
typedef struct umilib_hash_siphash_SipHash128_13 umilib_hash_siphash_SipHash128_13;

/**
 * HalfSipHash-2-4 with 32 bits of output and a 64-bit key.
 */
typedef struct umilib_hash_siphash_HalfSipHash24 umilib_hash_siphash_HalfSipHash24;

/**
 * HalfSipHash-1-3 with 32 bits of output and a 64-bit key.
 */
typedef struct umilib_hash_siphash_HalfSipHash13 umilib_hash_siphash_HalfSipHash13;

/**
 * HalfSipHash-2-4 with 64 bits of output and a 64-bit key.
 */
typedef struct umilib_hash_siphash_HalfSipHash64_24 umilib_hash_siphash_HalfSipHash64_24;

/**
 * HalfSipHash-1-3 with 64 bits of output and a 64-bit key.
 */
typedef struct umilib_hash_siphash_HalfSipHash64_13 umilib_hash_siphash_HalfSipHash64_13;

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_SipHash24** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_sip_hash24_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_sip_hash24_free(umilib_hash_siphash_SipHash24* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_clone(const umilib_hash_siphash_SipHash24* state, umilib_hash_siphash_SipHash24** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_update(umilib_hash_siphash_SipHash24* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_finalize(umilib_hash_siphash_SipHash24* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_finalize_reset(umilib_hash_siphash_SipHash24* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash24_reset(umilib_hash_siphash_SipHash24* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_sip_hash24_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_sip_hash24_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_SipHash13** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_sip_hash13_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_sip_hash13_free(umilib_hash_siphash_SipHash13* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_clone(const umilib_hash_siphash_SipHash13* state, umilib_hash_siphash_SipHash13** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_update(umilib_hash_siphash_SipHash13* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_finalize(umilib_hash_siphash_SipHash13* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_finalize_reset(umilib_hash_siphash_SipHash13* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash13_reset(umilib_hash_siphash_SipHash13* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_sip_hash13_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_sip_hash13_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_SipHash128_24** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_24_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_sip_hash128_24_free(umilib_hash_siphash_SipHash128_24* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_clone(const umilib_hash_siphash_SipHash128_24* state, umilib_hash_siphash_SipHash128_24** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_update(umilib_hash_siphash_SipHash128_24* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_finalize(umilib_hash_siphash_SipHash128_24* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_finalize_reset(umilib_hash_siphash_SipHash128_24* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_24_reset(umilib_hash_siphash_SipHash128_24* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_24_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_24_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_SipHash128_13** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_13_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_sip_hash128_13_free(umilib_hash_siphash_SipHash128_13* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_clone(const umilib_hash_siphash_SipHash128_13* state, umilib_hash_siphash_SipHash128_13** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_update(umilib_hash_siphash_SipHash128_13* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_finalize(umilib_hash_siphash_SipHash128_13* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_finalize_reset(umilib_hash_siphash_SipHash128_13* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_sip_hash128_13_reset(umilib_hash_siphash_SipHash128_13* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_13_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_sip_hash128_13_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_HalfSipHash24** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash24_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_half_sip_hash24_free(umilib_hash_siphash_HalfSipHash24* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_clone(const umilib_hash_siphash_HalfSipHash24* state, umilib_hash_siphash_HalfSipHash24** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_update(umilib_hash_siphash_HalfSipHash24* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_finalize(umilib_hash_siphash_HalfSipHash24* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_finalize_reset(umilib_hash_siphash_HalfSipHash24* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash24_reset(umilib_hash_siphash_HalfSipHash24* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash24_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash24_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_HalfSipHash13** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash13_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_half_sip_hash13_free(umilib_hash_siphash_HalfSipHash13* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_clone(const umilib_hash_siphash_HalfSipHash13* state, umilib_hash_siphash_HalfSipHash13** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_update(umilib_hash_siphash_HalfSipHash13* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_finalize(umilib_hash_siphash_HalfSipHash13* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_finalize_reset(umilib_hash_siphash_HalfSipHash13* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash13_reset(umilib_hash_siphash_HalfSipHash13* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash13_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash13_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_HalfSipHash64_24** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_24_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_half_sip_hash64_24_free(umilib_hash_siphash_HalfSipHash64_24* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_clone(const umilib_hash_siphash_HalfSipHash64_24* state, umilib_hash_siphash_HalfSipHash64_24** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_update(umilib_hash_siphash_HalfSipHash64_24* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_finalize(umilib_hash_siphash_HalfSipHash64_24* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_finalize_reset(umilib_hash_siphash_HalfSipHash64_24* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_24_reset(umilib_hash_siphash_HalfSipHash64_24* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_24_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_24_block_size(void);

/**
 * Creates the function with the key at `key`, which must have the key size.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_new(const uint8_t* key, size_t key_length, umilib_hash_siphash_HalfSipHash64_13** out);

/**
 * Writes the output for the `length` bytes at `data` under the key into the `out_length`
 * bytes at `out`, which must be the output size and must not overlap the key or the data.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_hash(const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Returns the key size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_13_key_size(void);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_siphash_half_sip_hash64_13_free(umilib_hash_siphash_HalfSipHash64_13* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_clone(const umilib_hash_siphash_HalfSipHash64_13* state, umilib_hash_siphash_HalfSipHash64_13** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_update(umilib_hash_siphash_HalfSipHash64_13* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_finalize(umilib_hash_siphash_HalfSipHash64_13* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_finalize_reset(umilib_hash_siphash_HalfSipHash64_13* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_siphash_half_sip_hash64_13_reset(umilib_hash_siphash_HalfSipHash64_13* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_13_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_siphash_half_sip_hash64_13_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
