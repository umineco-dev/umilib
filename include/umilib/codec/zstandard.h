/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_ZSTANDARD_H
#define UMILIB_CODEC_ZSTANDARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Zstandard dictionary.
 */
typedef struct umilib_codec_zstandard_ZstandardDictionary umilib_codec_zstandard_ZstandardDictionary;

/**
 * A compressor of Zstandard frames.
 */
typedef struct umilib_codec_zstandard_ZstandardCompressor umilib_codec_zstandard_ZstandardCompressor;

/**
 * A decompressor of Zstandard frames.
 */
typedef struct umilib_codec_zstandard_ZstandardDecompressor umilib_codec_zstandard_ZstandardDecompressor;

/**
 * Writes a new dictionary of the `length` bytes at `data` (formatted, or raw content) into `out`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_dictionary_new(const uint8_t* data, size_t length, umilib_codec_zstandard_ZstandardDictionary** out);

/**
 * Releases a dictionary. Does nothing if `dictionary` is null.
 */
void umilib_codec_zstandard_zstandard_dictionary_free(umilib_codec_zstandard_ZstandardDictionary* dictionary);

/**
 * Writes the identifier of `dictionary` (0 for raw content) into `out`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_dictionary_identifier(const umilib_codec_zstandard_ZstandardDictionary* dictionary, uint32_t* out);

/**
 * Writes a new compressor into `out`: `level` 1 to 19, the window log if `has_window_log`,
 * the content checksum, the content size if `has_content_size`, and a copy of `dictionary` unless it is null.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_compressor_new(uint32_t level, bool has_window_log, uint32_t window_log, bool content_checksum, bool has_content_size, uint64_t content_size, const umilib_codec_zstandard_ZstandardDictionary* dictionary, umilib_codec_zstandard_ZstandardCompressor** out);

/**
 * Writes a new decompressor into `out`: windows of at most `maximum_window` bytes, a series of
 * frames if `multiple_frames`, and a copy of `dictionary` unless it is null.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_new(uint64_t maximum_window, bool multiple_frames, const umilib_codec_zstandard_ZstandardDictionary* dictionary, umilib_codec_zstandard_ZstandardDecompressor** out);

/**
 * Writes the defaults: the level and the content checksum of a compressor, the maximum window
 * and multiple frames of a decompressor.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_config_defaults(uint32_t* level, bool* content_checksum, uint64_t* maximum_window, bool* multiple_frames);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_zstandard_zstandard_compressor_free(umilib_codec_zstandard_ZstandardCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_compressor_clone(const umilib_codec_zstandard_ZstandardCompressor* state, umilib_codec_zstandard_ZstandardCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_compressor_reset(umilib_codec_zstandard_ZstandardCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_compressor_compress(umilib_codec_zstandard_ZstandardCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_compressor_compress_to_vec(umilib_codec_zstandard_ZstandardCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_zstandard_zstandard_decompressor_free(umilib_codec_zstandard_ZstandardDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_clone(const umilib_codec_zstandard_ZstandardDecompressor* state, umilib_codec_zstandard_ZstandardDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_reset(umilib_codec_zstandard_ZstandardDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_decompress(umilib_codec_zstandard_ZstandardDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_finish(umilib_codec_zstandard_ZstandardDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_zstandard_zstandard_decompressor_decompress_to_vec(umilib_codec_zstandard_ZstandardDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
