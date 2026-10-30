/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_RLE_H
#define UMILIB_CODEC_RLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A PackBits compressor.
 */
typedef struct umilib_codec_rle_PackBitsCompressor umilib_codec_rle_PackBitsCompressor;

/**
 * A PackBits decompressor.
 */
typedef struct umilib_codec_rle_PackBitsDecompressor umilib_codec_rle_PackBitsDecompressor;

/**
 * Writes a new PackBits compressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_compressor_new(umilib_codec_rle_PackBitsCompressor** out);

/**
 * Writes a new PackBits decompressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_new(umilib_codec_rle_PackBitsDecompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_rle_pack_bits_compressor_free(umilib_codec_rle_PackBitsCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_compressor_clone(const umilib_codec_rle_PackBitsCompressor* state, umilib_codec_rle_PackBitsCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_compressor_reset(umilib_codec_rle_PackBitsCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_compressor_compress(umilib_codec_rle_PackBitsCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_compressor_compress_to_vec(umilib_codec_rle_PackBitsCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_rle_pack_bits_decompressor_free(umilib_codec_rle_PackBitsDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_clone(const umilib_codec_rle_PackBitsDecompressor* state, umilib_codec_rle_PackBitsDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_reset(umilib_codec_rle_PackBitsDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_decompress(umilib_codec_rle_PackBitsDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_finish(umilib_codec_rle_PackBitsDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_rle_pack_bits_decompressor_decompress_to_vec(umilib_codec_rle_PackBitsDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
