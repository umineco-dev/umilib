/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BROTLI_H
#define UMILIB_CODEC_BROTLI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of Brotli streams (RFC 7932).
 */
typedef struct umilib_codec_brotli_BrotliCompressor umilib_codec_brotli_BrotliCompressor;

/**
 * A decompressor of Brotli streams (RFC 7932).
 */
typedef struct umilib_codec_brotli_BrotliDecompressor umilib_codec_brotli_BrotliDecompressor;

/**
 * Writes a new compressor of `level` (0 to 11) and WBITS `window_bits` (10 to 24) into `out`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_compressor_new(uint32_t level, uint32_t window_bits, umilib_codec_brotli_BrotliCompressor** out);

/**
 * Writes the default level and window bits of a compressor into `level` and `window_bits`, and
 * the default limit of a decompressor into `maximum_window_bits`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_config_defaults(uint32_t* level, uint32_t* window_bits, uint32_t* maximum_window_bits);

/**
 * Writes a new decompressor of streams of WBITS up to `maximum_window_bits` (10 to 24) into `out`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_new(uint32_t maximum_window_bits, umilib_codec_brotli_BrotliDecompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_brotli_brotli_compressor_free(umilib_codec_brotli_BrotliCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_compressor_clone(const umilib_codec_brotli_BrotliCompressor* state, umilib_codec_brotli_BrotliCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_compressor_reset(umilib_codec_brotli_BrotliCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_compressor_compress(umilib_codec_brotli_BrotliCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_compressor_compress_to_vec(umilib_codec_brotli_BrotliCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_brotli_brotli_decompressor_free(umilib_codec_brotli_BrotliDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_clone(const umilib_codec_brotli_BrotliDecompressor* state, umilib_codec_brotli_BrotliDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_reset(umilib_codec_brotli_BrotliDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_decompress(umilib_codec_brotli_BrotliDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_finish(umilib_codec_brotli_BrotliDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_brotli_brotli_decompressor_decompress_to_vec(umilib_codec_brotli_BrotliDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
