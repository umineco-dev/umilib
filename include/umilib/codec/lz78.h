/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_LZ78_H
#define UMILIB_CODEC_LZ78_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of the LZ78 format of umilib.
 */
typedef struct umilib_codec_lz78_LZ78Compressor umilib_codec_lz78_LZ78Compressor;

/**
 * A decompressor of the LZ78 format of umilib.
 */
typedef struct umilib_codec_lz78_LZ78Decompressor umilib_codec_lz78_LZ78Decompressor;

/**
 * Writes a new compressor of dictionaries of at most 2^`dictionary_bits` phrases (1 to 24) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_compressor_new(uint32_t dictionary_bits, umilib_codec_lz78_LZ78Compressor** out);

/**
 * Writes the default dictionary bits of the compressor and the default limit of the
 * decompressor into `dictionary_bits` and `maximum_dictionary_bits`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_config_defaults(uint32_t* dictionary_bits, uint32_t* maximum_dictionary_bits);

/**
 * Writes a new decompressor accepting dictionaries of at most 2^`maximum_dictionary_bits` phrases into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_new(uint32_t maximum_dictionary_bits, umilib_codec_lz78_LZ78Decompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_lz78_lz78_compressor_free(umilib_codec_lz78_LZ78Compressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_compressor_clone(const umilib_codec_lz78_LZ78Compressor* state, umilib_codec_lz78_LZ78Compressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_compressor_reset(umilib_codec_lz78_LZ78Compressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_compressor_compress(umilib_codec_lz78_LZ78Compressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_compressor_compress_to_vec(umilib_codec_lz78_LZ78Compressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_lz78_lz78_decompressor_free(umilib_codec_lz78_LZ78Decompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_clone(const umilib_codec_lz78_LZ78Decompressor* state, umilib_codec_lz78_LZ78Decompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_reset(umilib_codec_lz78_LZ78Decompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_decompress(umilib_codec_lz78_LZ78Decompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_finish(umilib_codec_lz78_LZ78Decompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_lz78_lz78_decompressor_decompress_to_vec(umilib_codec_lz78_LZ78Decompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
