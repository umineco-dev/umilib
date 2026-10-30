/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_HASH_BLAKE_V2_H
#define UMILIB_HASH_BLAKE_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The parameters of BLAKE2b (RFC 7693 section 2.8), in the fields of their block.
 */
typedef struct umilib_hash_blake_v2_BLAKE2bParameters {
    uint8_t digest_length;
    uint8_t key_length;
    uint8_t fanout;
    uint8_t depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint32_t xof_length;
    uint8_t node_depth;
    uint8_t inner_length;
    uint8_t salt[16];
    uint8_t personal[16];
} umilib_hash_blake_v2_BLAKE2bParameters;

/**
 * The parameters of BLAKE2s (RFC 7693 section 2.8), in the fields of their block.
 */
typedef struct umilib_hash_blake_v2_BLAKE2sParameters {
    uint8_t digest_length;
    uint8_t key_length;
    uint8_t fanout;
    uint8_t depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint16_t xof_length;
    uint8_t node_depth;
    uint8_t inner_length;
    uint8_t salt[8];
    uint8_t personal[8];
} umilib_hash_blake_v2_BLAKE2sParameters;

/**
 * BLAKE2b with any output length of 1 to 64 bytes and any parameters (RFC 7693).
 */
typedef struct umilib_hash_blake_v2_BLAKE2b umilib_hash_blake_v2_BLAKE2b;

/**
 * BLAKE2s with any output length of 1 to 32 bytes and any parameters (RFC 7693).
 */
typedef struct umilib_hash_blake_v2_BLAKE2s umilib_hash_blake_v2_BLAKE2s;

/**
 * BLAKE2bp: BLAKE2b over 4 interleaved leaves.
 */
typedef struct umilib_hash_blake_v2_BLAKE2bp umilib_hash_blake_v2_BLAKE2bp;

/**
 * BLAKE2sp: BLAKE2s over 8 interleaved leaves.
 */
typedef struct umilib_hash_blake_v2_BLAKE2sp umilib_hash_blake_v2_BLAKE2sp;

/**
 * BLAKE2Xb: outputs of up to 2^32 - 2 bytes over BLAKE2b; the output length 2^32 - 1 leaves it open.
 */
typedef struct umilib_hash_blake_v2_BLAKE2Xb umilib_hash_blake_v2_BLAKE2Xb;

/**
 * BLAKE2Xs: outputs of up to 2^16 - 2 bytes over BLAKE2s; the output length 2^16 - 1 leaves it open.
 */
typedef struct umilib_hash_blake_v2_BLAKE2Xs umilib_hash_blake_v2_BLAKE2Xs;

/**
 * The output of BLAKE2Xb, computed node by node; reading past its length is an error.
 */
typedef struct umilib_hash_blake_v2_BLAKE2XbReader umilib_hash_blake_v2_BLAKE2XbReader;

/**
 * The output of BLAKE2Xs, computed node by node; reading past its length is an error.
 */
typedef struct umilib_hash_blake_v2_BLAKE2XsReader umilib_hash_blake_v2_BLAKE2XsReader;

/**
 * BLAKE2b with 160 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2b160 umilib_hash_blake_v2_BLAKE2b160;

/**
 * BLAKE2b with 256 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2b256 umilib_hash_blake_v2_BLAKE2b256;

/**
 * BLAKE2b with 384 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2b384 umilib_hash_blake_v2_BLAKE2b384;

/**
 * BLAKE2b with 512 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2b512 umilib_hash_blake_v2_BLAKE2b512;

/**
 * BLAKE2s with 128 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2s128 umilib_hash_blake_v2_BLAKE2s128;

/**
 * BLAKE2s with 160 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2s160 umilib_hash_blake_v2_BLAKE2s160;

/**
 * BLAKE2s with 224 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2s224 umilib_hash_blake_v2_BLAKE2s224;

/**
 * BLAKE2s with 256 bits of output.
 */
typedef struct umilib_hash_blake_v2_BLAKE2s256 umilib_hash_blake_v2_BLAKE2s256;

/**
 * Returns the sequential mode (fanout and depth 1) with `digest_length` bytes of output.
 */
umilib_hash_blake_v2_BLAKE2bParameters umilib_hash_blake_v2_blake2b_parameters_new(uint8_t digest_length);

/**
 * Writes the 64-byte parameter block of `parameters` into `out`, which must not overlap them.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_parameters_to_bytes(const umilib_hash_blake_v2_BLAKE2bParameters* parameters, uint8_t* out, size_t out_length);

/**
 * Writes the parameters of the 64-byte block at `data` into `out`; fails if its reserved bytes
 * are not zero.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_parameters_from_bytes(const uint8_t* data, size_t length, umilib_hash_blake_v2_BLAKE2bParameters* out);

/**
 * Returns the sequential mode (fanout and depth 1) with `digest_length` bytes of output.
 */
umilib_hash_blake_v2_BLAKE2sParameters umilib_hash_blake_v2_blake2s_parameters_new(uint8_t digest_length);

/**
 * Writes the 32-byte parameter block of `parameters` into `out`, which must not overlap them.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_parameters_to_bytes(const umilib_hash_blake_v2_BLAKE2sParameters* parameters, uint8_t* out, size_t out_length);

/**
 * Writes the parameters of the 32-byte block at `data` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_parameters_from_bytes(const uint8_t* data, size_t length, umilib_hash_blake_v2_BLAKE2sParameters* out);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_new(size_t output_length, umilib_hash_blake_v2_BLAKE2b** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_with_key(const uint8_t* key, size_t key_length, size_t output_length, umilib_hash_blake_v2_BLAKE2b** out);

/**
 * Creates the function with every parameter given; `parameters->key_length` must be the
 * length of the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_with_parameters(const umilib_hash_blake_v2_BLAKE2bParameters* parameters, const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2b** out);

/**
 * Creates the function with the parameter block and no key block, as the root of the
 * parallel modes.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_without_key_block(const umilib_hash_blake_v2_BLAKE2bParameters* parameters, umilib_hash_blake_v2_BLAKE2b** out);

/**
 * Marks the state as the last node of its tree level, or not.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_set_last_node(umilib_hash_blake_v2_BLAKE2b* state, bool last_node);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2b_free(umilib_hash_blake_v2_BLAKE2b* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_clone(const umilib_hash_blake_v2_BLAKE2b* state, umilib_hash_blake_v2_BLAKE2b** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_update(umilib_hash_blake_v2_BLAKE2b* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_finalize_into(umilib_hash_blake_v2_BLAKE2b* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_reset(umilib_hash_blake_v2_BLAKE2b* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b_output_length(const umilib_hash_blake_v2_BLAKE2b* state, size_t* out);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_new(size_t output_length, umilib_hash_blake_v2_BLAKE2s** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_with_key(const uint8_t* key, size_t key_length, size_t output_length, umilib_hash_blake_v2_BLAKE2s** out);

/**
 * Creates the function with every parameter given; `parameters->key_length` must be the
 * length of the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_with_parameters(const umilib_hash_blake_v2_BLAKE2sParameters* parameters, const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2s** out);

/**
 * Creates the function with the parameter block and no key block, as the root of the
 * parallel modes.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_without_key_block(const umilib_hash_blake_v2_BLAKE2sParameters* parameters, umilib_hash_blake_v2_BLAKE2s** out);

/**
 * Marks the state as the last node of its tree level, or not.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_set_last_node(umilib_hash_blake_v2_BLAKE2s* state, bool last_node);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2s_free(umilib_hash_blake_v2_BLAKE2s* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_clone(const umilib_hash_blake_v2_BLAKE2s* state, umilib_hash_blake_v2_BLAKE2s** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_update(umilib_hash_blake_v2_BLAKE2s* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_finalize_into(umilib_hash_blake_v2_BLAKE2s* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_reset(umilib_hash_blake_v2_BLAKE2s* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s_output_length(const umilib_hash_blake_v2_BLAKE2s* state, size_t* out);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_new(size_t output_length, umilib_hash_blake_v2_BLAKE2bp** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_with_key(const uint8_t* key, size_t key_length, size_t output_length, umilib_hash_blake_v2_BLAKE2bp** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2bp_free(umilib_hash_blake_v2_BLAKE2bp* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_clone(const umilib_hash_blake_v2_BLAKE2bp* state, umilib_hash_blake_v2_BLAKE2bp** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_update(umilib_hash_blake_v2_BLAKE2bp* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_finalize_into(umilib_hash_blake_v2_BLAKE2bp* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_reset(umilib_hash_blake_v2_BLAKE2bp* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2bp_output_length(const umilib_hash_blake_v2_BLAKE2bp* state, size_t* out);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_new(size_t output_length, umilib_hash_blake_v2_BLAKE2sp** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_with_key(const uint8_t* key, size_t key_length, size_t output_length, umilib_hash_blake_v2_BLAKE2sp** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2sp_free(umilib_hash_blake_v2_BLAKE2sp* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_clone(const umilib_hash_blake_v2_BLAKE2sp* state, umilib_hash_blake_v2_BLAKE2sp** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_update(umilib_hash_blake_v2_BLAKE2sp* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_finalize_into(umilib_hash_blake_v2_BLAKE2sp* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_reset(umilib_hash_blake_v2_BLAKE2sp* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2sp_output_length(const umilib_hash_blake_v2_BLAKE2sp* state, size_t* out);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_new(uint32_t output_length, umilib_hash_blake_v2_BLAKE2Xb** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_with_key(const uint8_t* key, size_t key_length, uint32_t output_length, umilib_hash_blake_v2_BLAKE2Xb** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2xb_free(umilib_hash_blake_v2_BLAKE2Xb* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_clone(const umilib_hash_blake_v2_BLAKE2Xb* state, umilib_hash_blake_v2_BLAKE2Xb** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_update(umilib_hash_blake_v2_BLAKE2Xb* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_finalize_into(umilib_hash_blake_v2_BLAKE2Xb* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_reset(umilib_hash_blake_v2_BLAKE2Xb* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_output_length(const umilib_hash_blake_v2_BLAKE2Xb* state, size_t* out);

/**
 * Creates BLAKE2X with every parameter of the root given; the digest length must be the
 * node size, `parameters->key_length` the length of the key and `xof_length` not 0.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_with_parameters(const umilib_hash_blake_v2_BLAKE2bParameters* parameters, const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2Xb** out);

/**
 * Writes the reader of the output, which computes each output node when it is read, into
 * `out` and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_finalize_xof(umilib_hash_blake_v2_BLAKE2Xb* state, umilib_hash_blake_v2_BLAKE2XbReader** out);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_blake_v2_blake2xb_reader_free(umilib_hash_blake_v2_BLAKE2XbReader* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_reader_clone(const umilib_hash_blake_v2_BLAKE2XbReader* reader, umilib_hash_blake_v2_BLAKE2XbReader** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xb_reader_read(umilib_hash_blake_v2_BLAKE2XbReader* reader, uint8_t* out, size_t out_length);

/**
 * Creates the unkeyed function with `output_length` bytes of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_new(uint16_t output_length, umilib_hash_blake_v2_BLAKE2Xs** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
 * of output.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_with_key(const uint8_t* key, size_t key_length, uint16_t output_length, umilib_hash_blake_v2_BLAKE2Xs** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2xs_free(umilib_hash_blake_v2_BLAKE2Xs* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_clone(const umilib_hash_blake_v2_BLAKE2Xs* state, umilib_hash_blake_v2_BLAKE2Xs** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_update(umilib_hash_blake_v2_BLAKE2Xs* state, const uint8_t* data, size_t length);

/**
 * Writes the output into the `out_length` bytes at `out`, which must be the output length,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_finalize_into(umilib_hash_blake_v2_BLAKE2Xs* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start, after the parameters and the key.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_reset(umilib_hash_blake_v2_BLAKE2Xs* state);

/**
 * Writes the output length in bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_output_length(const umilib_hash_blake_v2_BLAKE2Xs* state, size_t* out);

/**
 * Creates BLAKE2X with every parameter of the root given; the digest length must be the
 * node size, `parameters->key_length` the length of the key and `xof_length` not 0.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_with_parameters(const umilib_hash_blake_v2_BLAKE2sParameters* parameters, const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2Xs** out);

/**
 * Writes the reader of the output, which computes each output node when it is read, into
 * `out` and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_finalize_xof(umilib_hash_blake_v2_BLAKE2Xs* state, umilib_hash_blake_v2_BLAKE2XsReader** out);

/**
 * Releases the reader, zeroizing it. Does nothing if `reader` is null.
 */
void umilib_hash_blake_v2_blake2xs_reader_free(umilib_hash_blake_v2_BLAKE2XsReader* reader);

/**
 * Writes a copy of `reader`, at the same position, into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_reader_clone(const umilib_hash_blake_v2_BLAKE2XsReader* reader, umilib_hash_blake_v2_BLAKE2XsReader** out);

/**
 * Writes the next `out_length` output bytes into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2xs_reader_read(umilib_hash_blake_v2_BLAKE2XsReader* reader, uint8_t* out, size_t out_length);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_new(umilib_hash_blake_v2_BLAKE2b160** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2b160** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2b160_free(umilib_hash_blake_v2_BLAKE2b160* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_clone(const umilib_hash_blake_v2_BLAKE2b160* state, umilib_hash_blake_v2_BLAKE2b160** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_update(umilib_hash_blake_v2_BLAKE2b160* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_finalize(umilib_hash_blake_v2_BLAKE2b160* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_finalize_reset(umilib_hash_blake_v2_BLAKE2b160* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b160_reset(umilib_hash_blake_v2_BLAKE2b160* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b160_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b160_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_new(umilib_hash_blake_v2_BLAKE2b256** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2b256** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2b256_free(umilib_hash_blake_v2_BLAKE2b256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_clone(const umilib_hash_blake_v2_BLAKE2b256* state, umilib_hash_blake_v2_BLAKE2b256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_update(umilib_hash_blake_v2_BLAKE2b256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_finalize(umilib_hash_blake_v2_BLAKE2b256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_finalize_reset(umilib_hash_blake_v2_BLAKE2b256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b256_reset(umilib_hash_blake_v2_BLAKE2b256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b256_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_new(umilib_hash_blake_v2_BLAKE2b384** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2b384** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2b384_free(umilib_hash_blake_v2_BLAKE2b384* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_clone(const umilib_hash_blake_v2_BLAKE2b384* state, umilib_hash_blake_v2_BLAKE2b384** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_update(umilib_hash_blake_v2_BLAKE2b384* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_finalize(umilib_hash_blake_v2_BLAKE2b384* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_finalize_reset(umilib_hash_blake_v2_BLAKE2b384* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b384_reset(umilib_hash_blake_v2_BLAKE2b384* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b384_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b384_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_new(umilib_hash_blake_v2_BLAKE2b512** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2b512** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2b512_free(umilib_hash_blake_v2_BLAKE2b512* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_clone(const umilib_hash_blake_v2_BLAKE2b512* state, umilib_hash_blake_v2_BLAKE2b512** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_update(umilib_hash_blake_v2_BLAKE2b512* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_finalize(umilib_hash_blake_v2_BLAKE2b512* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_finalize_reset(umilib_hash_blake_v2_BLAKE2b512* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2b512_reset(umilib_hash_blake_v2_BLAKE2b512* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b512_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2b512_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_new(umilib_hash_blake_v2_BLAKE2s128** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2s128** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2s128_free(umilib_hash_blake_v2_BLAKE2s128* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_clone(const umilib_hash_blake_v2_BLAKE2s128* state, umilib_hash_blake_v2_BLAKE2s128** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_update(umilib_hash_blake_v2_BLAKE2s128* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_finalize(umilib_hash_blake_v2_BLAKE2s128* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_finalize_reset(umilib_hash_blake_v2_BLAKE2s128* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s128_reset(umilib_hash_blake_v2_BLAKE2s128* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s128_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s128_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_new(umilib_hash_blake_v2_BLAKE2s160** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2s160** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2s160_free(umilib_hash_blake_v2_BLAKE2s160* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_clone(const umilib_hash_blake_v2_BLAKE2s160* state, umilib_hash_blake_v2_BLAKE2s160** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_update(umilib_hash_blake_v2_BLAKE2s160* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_finalize(umilib_hash_blake_v2_BLAKE2s160* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_finalize_reset(umilib_hash_blake_v2_BLAKE2s160* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s160_reset(umilib_hash_blake_v2_BLAKE2s160* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s160_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s160_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_new(umilib_hash_blake_v2_BLAKE2s224** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2s224** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2s224_free(umilib_hash_blake_v2_BLAKE2s224* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_clone(const umilib_hash_blake_v2_BLAKE2s224* state, umilib_hash_blake_v2_BLAKE2s224** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_update(umilib_hash_blake_v2_BLAKE2s224* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_finalize(umilib_hash_blake_v2_BLAKE2s224* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_finalize_reset(umilib_hash_blake_v2_BLAKE2s224* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s224_reset(umilib_hash_blake_v2_BLAKE2s224* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s224_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s224_block_size(void);

/**
 * Creates the unkeyed function.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_new(umilib_hash_blake_v2_BLAKE2s256** out);

/**
 * Creates the keyed function with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_with_key(const uint8_t* key, size_t key_length, umilib_hash_blake_v2_BLAKE2s256** out);

/**
 * Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
 * `out`, which must be the output size and must not overlap `data`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_digest(const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_hash_blake_v2_blake2s256_free(umilib_hash_blake_v2_BLAKE2s256* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_clone(const umilib_hash_blake_v2_BLAKE2s256* state, umilib_hash_blake_v2_BLAKE2s256** out);

/**
 * Adds the `length` bytes at `data` to the input.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_update(umilib_hash_blake_v2_BLAKE2s256* state, const uint8_t* data, size_t length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_finalize(umilib_hash_blake_v2_BLAKE2s256* state, uint8_t* out, size_t out_length);

/**
 * Writes the hash into the `out_length` bytes at `out`, which must be the output size,
 * and returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_finalize_reset(umilib_hash_blake_v2_BLAKE2s256* state, uint8_t* out, size_t out_length);

/**
 * Returns the state to its start.
 */
const umilib_ffi_Status* umilib_hash_blake_v2_blake2s256_reset(umilib_hash_blake_v2_BLAKE2s256* state);

/**
 * Returns the output size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s256_output_size(void);

/**
 * Returns the block size in bytes.
 */
size_t umilib_hash_blake_v2_blake2s256_block_size(void);

#ifdef __cplusplus
}
#endif

#endif
