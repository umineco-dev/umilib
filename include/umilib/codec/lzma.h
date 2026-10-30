/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_LZMA_H
#define UMILIB_CODEC_LZMA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of .lzma files.
 */
typedef struct umilib_codec_lzma_LZMACompressor umilib_codec_lzma_LZMACompressor;

/**
 * A decompressor of .lzma files.
 */
typedef struct umilib_codec_lzma_LZMADecompressor umilib_codec_lzma_LZMADecompressor;

/**
 * A compressor of raw LZMA2 streams.
 */
typedef struct umilib_codec_lzma_LZMA2Compressor umilib_codec_lzma_LZMA2Compressor;

/**
 * A decompressor of raw LZMA2 streams.
 */
typedef struct umilib_codec_lzma_LZMA2Decompressor umilib_codec_lzma_LZMA2Decompressor;

/**
 * Writes a new compressor of .lzma files into `out`: `level` 0 to 9, the properties lc, lp
 * and pb, the dictionary size if `has_dictionary_size` (otherwise the level's), and the size of
 * the data if `has_uncompressed_size` (otherwise an end marker).
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_compressor_new(uint32_t level, uint32_t lc, uint32_t lp, uint32_t pb, bool has_dictionary_size, size_t dictionary_size, bool has_uncompressed_size, uint64_t uncompressed_size, umilib_codec_lzma_LZMACompressor** out);

/**
 * Writes a new decompressor of .lzma files accepting dictionaries of at most `maximum_dictionary_size` bytes into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_new(size_t maximum_dictionary_size, umilib_codec_lzma_LZMADecompressor** out);

/**
 * Writes a new compressor of raw LZMA2 streams into `out` (as for .lzma files, with lc + lp at most 4).
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_new(uint32_t level, uint32_t lc, uint32_t lp, uint32_t pb, bool has_dictionary_size, size_t dictionary_size, umilib_codec_lzma_LZMA2Compressor** out);

/**
 * Writes the dictionary size the decompressor of the streams of `state` needs into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_dictionary_size(const umilib_codec_lzma_LZMA2Compressor* state, size_t* out);

/**
 * Writes a new decompressor of raw LZMA2 streams of a dictionary of `dictionary_size` bytes into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_new(size_t dictionary_size, umilib_codec_lzma_LZMA2Decompressor** out);

/**
 * Writes the dictionary size of the LZMA2 properties byte `byte` (0 to 40) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_format_lzma2_dictionary_size(uint8_t byte, uint64_t* out);

/**
 * Writes the defaults: the level and lc, lp, pb of the compressors, and the maximum dictionary
 * of a .lzma decompressor and the dictionary of an LZMA2 decompressor.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_config_defaults(uint32_t* level, uint32_t* lc, uint32_t* lp, uint32_t* pb, size_t* maximum_dictionary_size, size_t* lzma2_dictionary_size);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_lzma_lzma_compressor_free(umilib_codec_lzma_LZMACompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_compressor_clone(const umilib_codec_lzma_LZMACompressor* state, umilib_codec_lzma_LZMACompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_compressor_reset(umilib_codec_lzma_LZMACompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_compressor_compress(umilib_codec_lzma_LZMACompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_compressor_compress_to_vec(umilib_codec_lzma_LZMACompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_lzma_lzma_decompressor_free(umilib_codec_lzma_LZMADecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_clone(const umilib_codec_lzma_LZMADecompressor* state, umilib_codec_lzma_LZMADecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_reset(umilib_codec_lzma_LZMADecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_decompress(umilib_codec_lzma_LZMADecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_finish(umilib_codec_lzma_LZMADecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma_decompressor_decompress_to_vec(umilib_codec_lzma_LZMADecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_lzma_lzma2_compressor_free(umilib_codec_lzma_LZMA2Compressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_clone(const umilib_codec_lzma_LZMA2Compressor* state, umilib_codec_lzma_LZMA2Compressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_reset(umilib_codec_lzma_LZMA2Compressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_compress(umilib_codec_lzma_LZMA2Compressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_compressor_compress_to_vec(umilib_codec_lzma_LZMA2Compressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_lzma_lzma2_decompressor_free(umilib_codec_lzma_LZMA2Decompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_clone(const umilib_codec_lzma_LZMA2Decompressor* state, umilib_codec_lzma_LZMA2Decompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_reset(umilib_codec_lzma_LZMA2Decompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_decompress(umilib_codec_lzma_LZMA2Decompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_finish(umilib_codec_lzma_LZMA2Decompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_lzma_lzma2_decompressor_decompress_to_vec(umilib_codec_lzma_LZMA2Decompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
