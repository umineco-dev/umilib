/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_LZ4_H
#define UMILIB_CODEC_LZ4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of LZ4 frames.
 */
typedef struct umilib_codec_lz4_LZ4Compressor umilib_codec_lz4_LZ4Compressor;

/**
 * A decompressor of LZ4 frames.
 */
typedef struct umilib_codec_lz4_LZ4Decompressor umilib_codec_lz4_LZ4Decompressor;

/**
 * Writes the block of the `length` bytes at `data`, with no history, encoded at `level` (0 to 12), into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_block_compress(const uint8_t* data, size_t length, uint32_t level, umilib_ffi_Buffer* out);

/**
 * Writes the data of the whole block of `length` bytes at `block`, of at most `limit` bytes, into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_block_decompress(const uint8_t* block, size_t length, size_t limit, umilib_ffi_Buffer* out);

/**
 * Writes a new frame compressor into `out`: `level` 0 to 12, the block size code 4 to 7, the
 * flags of the frame, the content size if `has_content_size`, and the dictionary of
 * `dictionary_length` bytes at `dictionary` (none if null) with its identifier if `has_dictionary_identifier`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_compressor_new(uint32_t level, uint8_t block_size, bool independent_blocks, bool block_checksum, bool content_checksum, bool has_content_size, uint64_t content_size, const uint8_t* dictionary, size_t dictionary_length, bool has_dictionary_identifier, uint32_t dictionary_identifier, umilib_codec_lz4_LZ4Compressor** out);

/**
 * Writes a new frame decompressor into `out`: blocks of at most `maximum_block_size` bytes,
 * a series of frames if `multiple_frames`, and the dictionary of `dictionary_length` bytes at
 * `dictionary` (none if null) that frames naming the identifier (if `has_dictionary_identifier`) get.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_new(size_t maximum_block_size, bool multiple_frames, const uint8_t* dictionary, size_t dictionary_length, bool has_dictionary_identifier, uint32_t dictionary_identifier, umilib_codec_lz4_LZ4Decompressor** out);

/**
 * Writes the defaults: the level, the block size code, independent blocks, block and content
 * checksums of a compressor, and the maximum block size and multiple frames of a decompressor.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_config_defaults(uint32_t* level, uint8_t* block_size, bool* independent_blocks, bool* block_checksum, bool* content_checksum, size_t* maximum_block_size, bool* multiple_frames);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_lz4_lz4_compressor_free(umilib_codec_lz4_LZ4Compressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_compressor_clone(const umilib_codec_lz4_LZ4Compressor* state, umilib_codec_lz4_LZ4Compressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_compressor_reset(umilib_codec_lz4_LZ4Compressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_compressor_compress(umilib_codec_lz4_LZ4Compressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_compressor_compress_to_vec(umilib_codec_lz4_LZ4Compressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_lz4_lz4_decompressor_free(umilib_codec_lz4_LZ4Decompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_clone(const umilib_codec_lz4_LZ4Decompressor* state, umilib_codec_lz4_LZ4Decompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_reset(umilib_codec_lz4_LZ4Decompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_decompress(umilib_codec_lz4_LZ4Decompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_finish(umilib_codec_lz4_LZ4Decompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_lz4_lz4_decompressor_decompress_to_vec(umilib_codec_lz4_LZ4Decompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
