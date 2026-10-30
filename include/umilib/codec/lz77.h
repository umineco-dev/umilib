/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_LZ77_H
#define UMILIB_CODEC_LZ77_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of the LZ77 format of umilib.
 */
typedef struct umilib_codec_lz77_LZ77Compressor umilib_codec_lz77_LZ77Compressor;

/**
 * A decompressor of the LZ77 format of umilib.
 */
typedef struct umilib_codec_lz77_LZ77Decompressor umilib_codec_lz77_LZ77Decompressor;

/**
 * Writes a new compressor examining at most `chain_limit` candidates per match (1 or more) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_compressor_new(size_t chain_limit, umilib_codec_lz77_LZ77Compressor** out);

/**
 * Writes the default chain limit into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_config_default_chain_limit(size_t* out);

/**
 * Writes a new decompressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_new(umilib_codec_lz77_LZ77Decompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_lz77_lz77_compressor_free(umilib_codec_lz77_LZ77Compressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_compressor_clone(const umilib_codec_lz77_LZ77Compressor* state, umilib_codec_lz77_LZ77Compressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_compressor_reset(umilib_codec_lz77_LZ77Compressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_compressor_compress(umilib_codec_lz77_LZ77Compressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_compressor_compress_to_vec(umilib_codec_lz77_LZ77Compressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_lz77_lz77_decompressor_free(umilib_codec_lz77_LZ77Decompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_clone(const umilib_codec_lz77_LZ77Decompressor* state, umilib_codec_lz77_LZ77Decompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_reset(umilib_codec_lz77_LZ77Decompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_decompress(umilib_codec_lz77_LZ77Decompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_finish(umilib_codec_lz77_LZ77Decompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_lz77_lz77_decompressor_decompress_to_vec(umilib_codec_lz77_LZ77Decompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
