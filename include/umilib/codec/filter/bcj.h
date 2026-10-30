/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_FILTER_BCJ_H
#define UMILIB_CODEC_FILTER_BCJ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A branch/call/jump filter of one architecture (.xz format specification, section 5.3.2).
 */
typedef struct umilib_codec_filter_bcj_BCJFilter umilib_codec_filter_bcj_BCJFilter;

/**
 * Writes a new BCJ filter of `architecture` (0 x86, 1 PowerPC, 2 IA-64, 3 ARM, 4 ARM Thumb,
 * 5 SPARC, 6 ARM64, 7 RISC-V) whose first byte is at `start_offset` (a multiple of the
 * architecture's alignment) into `out`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_new(uint8_t architecture, uint32_t start_offset, umilib_codec_filter_bcj_BCJFilter** out);

/**
 * Writes the alignment of `architecture` (as for `_bcj_filter_new`) into `out`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_architecture_alignment(uint8_t architecture, uint32_t* out);

/**
 * Writes the architecture and the start offset of `state` into `architecture` and `start_offset`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_parameters(const umilib_codec_filter_bcj_BCJFilter* state, uint8_t* architecture, uint32_t* start_offset);

/**
 * Releases the filter. Does nothing if `state` is null.
 */
void umilib_codec_filter_bcj_bcj_filter_free(umilib_codec_filter_bcj_BCJFilter* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_clone(const umilib_codec_filter_bcj_BCJFilter* state, umilib_codec_filter_bcj_BCJFilter** out);

/**
 * Starts a new stream with the same parameters.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_reset(umilib_codec_filter_bcj_BCJFilter* state);

/**
 * Writes into `out` the most bytes at the end of a piece the filter may leave unconverted.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_lookahead(const umilib_codec_filter_bcj_BCJFilter* state, size_t* out);

/**
 * Encodes in place the bytes it can of the `length` bytes at `data` (the stream after
 * what it converted before) and writes how many into `converted`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_encode(umilib_codec_filter_bcj_BCJFilter* state, uint8_t* data, size_t length, size_t* converted);

/**
 * Decodes in place the bytes it can of the `length` bytes at `data` and writes how many into `converted`.
 */
const umilib_ffi_Status* umilib_codec_filter_bcj_bcj_filter_decode(umilib_codec_filter_bcj_BCJFilter* state, uint8_t* data, size_t length, size_t* converted);

#ifdef __cplusplus
}
#endif

#endif
