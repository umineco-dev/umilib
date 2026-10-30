/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_XZ_H
#define UMILIB_CODEC_XZ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A filter of a .xz chain: its Filter ID (0x03 Delta, 0x04 to 0x0B BCJ, 0x21 LZMA2) and
 * its value (the distance of Delta, the start offset of BCJ, the dictionary size of LZMA2).
 */
typedef struct umilib_codec_xz_XZFilterFlags {
    uint64_t id;
    uint64_t value;
} umilib_codec_xz_XZFilterFlags;

/**
 * A compressor of .xz Streams.
 */
typedef struct umilib_codec_xz_XZCompressor umilib_codec_xz_XZCompressor;

/**
 * A decompressor of .xz files and Streams.
 */
typedef struct umilib_codec_xz_XZDecompressor umilib_codec_xz_XZDecompressor;

/**
 * Writes a new compressor into `out`: LZMA2 of `level` (0 to 9) and `dictionary_size` (0 for
 * the level's), the Check `check` (its ID), Blocks of `block_size` bytes (0 for one Block) and
 * the `filter_count` filters at `filters` before LZMA2 (null if none).
 */
const umilib_ffi_Status* umilib_codec_xz_xz_compressor_new(uint32_t level, uint64_t dictionary_size, uint8_t check, uint64_t block_size, const umilib_codec_xz_XZFilterFlags* filters, size_t filter_count, umilib_codec_xz_XZCompressor** out);

/**
 * Writes a new decompressor into `out`: LZMA2 dictionaries of at most `maximum_dictionary_size`
 * bytes, and a file of Streams if `multiple_streams` (otherwise one Stream).
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_new(uint64_t maximum_dictionary_size, bool multiple_streams, umilib_codec_xz_XZDecompressor** out);

/**
 * Writes the defaults: the level and the Check ID of a compressor, the maximum dictionary and
 * multiple Streams of a decompressor.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_config_defaults(uint32_t* level, uint8_t* check, uint64_t* maximum_dictionary_size, bool* multiple_streams);

/**
 * Writes the Streams `state` has read completely into `streams` and the Check ID of its current
 * (or last) Stream into `check`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_streams(const umilib_codec_xz_XZDecompressor* state, uint64_t* streams, uint8_t* check);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_xz_xz_compressor_free(umilib_codec_xz_XZCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_compressor_clone(const umilib_codec_xz_XZCompressor* state, umilib_codec_xz_XZCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_compressor_reset(umilib_codec_xz_XZCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_compressor_compress(umilib_codec_xz_XZCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_compressor_compress_to_vec(umilib_codec_xz_XZCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_xz_xz_decompressor_free(umilib_codec_xz_XZDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_clone(const umilib_codec_xz_XZDecompressor* state, umilib_codec_xz_XZDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_reset(umilib_codec_xz_XZDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_decompress(umilib_codec_xz_XZDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_finish(umilib_codec_xz_XZDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_xz_xz_decompressor_decompress_to_vec(umilib_codec_xz_XZDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
