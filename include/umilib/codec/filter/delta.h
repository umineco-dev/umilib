/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_FILTER_DELTA_H
#define UMILIB_CODEC_FILTER_DELTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The Delta filter (.xz format specification, section 5.3.3).
 */
typedef struct umilib_codec_filter_delta_DeltaFilter umilib_codec_filter_delta_DeltaFilter;

/**
 * Writes a new Delta filter of `distance` (1 to 256) bytes into `out`.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_new(size_t distance, umilib_codec_filter_delta_DeltaFilter** out);

/**
 * Releases the filter. Does nothing if `state` is null.
 */
void umilib_codec_filter_delta_delta_filter_free(umilib_codec_filter_delta_DeltaFilter* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_clone(const umilib_codec_filter_delta_DeltaFilter* state, umilib_codec_filter_delta_DeltaFilter** out);

/**
 * Starts a new stream with the same parameters.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_reset(umilib_codec_filter_delta_DeltaFilter* state);

/**
 * Writes into `out` the most bytes at the end of a piece the filter may leave unconverted.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_lookahead(const umilib_codec_filter_delta_DeltaFilter* state, size_t* out);

/**
 * Encodes in place the bytes it can of the `length` bytes at `data` (the stream after
 * what it converted before) and writes how many into `converted`.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_encode(umilib_codec_filter_delta_DeltaFilter* state, uint8_t* data, size_t length, size_t* converted);

/**
 * Decodes in place the bytes it can of the `length` bytes at `data` and writes how many into `converted`.
 */
const umilib_ffi_Status* umilib_codec_filter_delta_delta_filter_decode(umilib_codec_filter_delta_DeltaFilter* state, uint8_t* data, size_t length, size_t* converted);

#ifdef __cplusplus
}
#endif

#endif
