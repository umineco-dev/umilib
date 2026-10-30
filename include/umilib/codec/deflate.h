/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_DEFLATE_H
#define UMILIB_CODEC_DEFLATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of raw Deflate streams (RFC 1951).
 */
typedef struct umilib_codec_deflate_DeflateCompressor umilib_codec_deflate_DeflateCompressor;

/**
 * A decompressor of raw Deflate streams (RFC 1951).
 */
typedef struct umilib_codec_deflate_DeflateDecompressor umilib_codec_deflate_DeflateDecompressor;

/**
 * Writes a new compressor of `level` (0 to 9) and a window of 2^`window_bits` bytes (8 to 15) into `out`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_new(uint32_t level, uint32_t window_bits, umilib_codec_deflate_DeflateCompressor** out);

/**
 * Makes the `length` bytes at `dictionary` the history before the data, before the first compression.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_set_dictionary(umilib_codec_deflate_DeflateCompressor* state, const uint8_t* dictionary, size_t length);

/**
 * Writes the default level and window bits into `level` and `window_bits`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_config_default(uint32_t* level, uint32_t* window_bits);

/**
 * Writes a new decompressor keeping a window of 2^`window_bits` bytes (8 to 15) into `out`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_new(uint32_t window_bits, umilib_codec_deflate_DeflateDecompressor** out);

/**
 * Makes the `length` bytes at `dictionary` the history before the data, before the first decompression.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_set_dictionary(umilib_codec_deflate_DeflateDecompressor* state, const uint8_t* dictionary, size_t length);

/**
 * After the last block, goes on with the blocks that follow at the next byte, the history kept.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_resume(umilib_codec_deflate_DeflateDecompressor* state);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_deflate_deflate_compressor_free(umilib_codec_deflate_DeflateCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_clone(const umilib_codec_deflate_DeflateCompressor* state, umilib_codec_deflate_DeflateCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_reset(umilib_codec_deflate_DeflateCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_compress(umilib_codec_deflate_DeflateCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_compressor_compress_to_vec(umilib_codec_deflate_DeflateCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_deflate_deflate_decompressor_free(umilib_codec_deflate_DeflateDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_clone(const umilib_codec_deflate_DeflateDecompressor* state, umilib_codec_deflate_DeflateDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_reset(umilib_codec_deflate_DeflateDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_decompress(umilib_codec_deflate_DeflateDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_finish(umilib_codec_deflate_DeflateDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_deflate_deflate_decompressor_decompress_to_vec(umilib_codec_deflate_DeflateDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
