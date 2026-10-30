/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_GZIP_H
#define UMILIB_CODEC_GZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A compressor of gzip members (RFC 1952).
 */
typedef struct umilib_codec_gzip_GzipCompressor umilib_codec_gzip_GzipCompressor;

/**
 * A decompressor of gzip files (RFC 1952).
 */
typedef struct umilib_codec_gzip_GzipDecompressor umilib_codec_gzip_GzipDecompressor;

/**
 * Writes a new compressor of a member of `level` (0 to 9) whose header has the modification
 * time `modification_time`, the operating system `operating_system`, the flags `text` and
 * `header_checksum`, and the extra field, name and comment given (or none, for null pointers),
 * into `out`. Names and comments may not hold zero bytes.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_compressor_new(uint32_t level, uint32_t modification_time, uint8_t operating_system, bool text, bool header_checksum, const uint8_t* extra, size_t extra_length, const uint8_t* name, size_t name_length, const uint8_t* comment, size_t comment_length, umilib_codec_gzip_GzipCompressor** out);

/**
 * Writes a new decompressor into `out`: of a file of any number of members if
 * `multiple_members`, otherwise of one member; names, comments and extra fields longer than
 * `maximum_field` bytes fail with `LimitExceeded`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_new(bool multiple_members, size_t maximum_field, umilib_codec_gzip_GzipDecompressor** out);

/**
 * Writes the default `multiple_members` and `maximum_field` of a decompressor.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_config_default(bool* multiple_members, size_t* maximum_field);

/**
 * Writes the fixed fields of the header of the member being read (or of the last one) and the
 * number of members read completely.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_header(const umilib_codec_gzip_GzipDecompressor* state, bool* text, uint32_t* modification_time, uint8_t* extra_flags, uint8_t* operating_system, bool* header_checksum, size_t* members);

/**
 * Writes whether the header has the field `field` (0 extra, 1 name, 2 comment) into
 * `has_value`, and its bytes into `out`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_header_field(const umilib_codec_gzip_GzipDecompressor* state, uint8_t field, bool* has_value, umilib_ffi_Buffer* out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_gzip_gzip_compressor_free(umilib_codec_gzip_GzipCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_compressor_clone(const umilib_codec_gzip_GzipCompressor* state, umilib_codec_gzip_GzipCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_compressor_reset(umilib_codec_gzip_GzipCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_compressor_compress(umilib_codec_gzip_GzipCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_compressor_compress_to_vec(umilib_codec_gzip_GzipCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_gzip_gzip_decompressor_free(umilib_codec_gzip_GzipDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_clone(const umilib_codec_gzip_GzipDecompressor* state, umilib_codec_gzip_GzipDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_reset(umilib_codec_gzip_GzipDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_decompress(umilib_codec_gzip_GzipDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_finish(umilib_codec_gzip_GzipDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_gzip_gzip_decompressor_decompress_to_vec(umilib_codec_gzip_GzipDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
