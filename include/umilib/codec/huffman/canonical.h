/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_HUFFMAN_CANONICAL_H
#define UMILIB_CODEC_HUFFMAN_CANONICAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A canonical prefix code.
 */
typedef struct umilib_codec_huffman_canonical_HuffmanCode umilib_codec_huffman_canonical_HuffmanCode;

/**
 * A table that decodes a canonical prefix code.
 */
typedef struct umilib_codec_huffman_canonical_HuffmanTable umilib_codec_huffman_canonical_HuffmanTable;

/**
 * A compressor of the block format of canonical Huffman codes of umilib.
 */
typedef struct umilib_codec_huffman_canonical_CanonicalHuffmanCompressor umilib_codec_huffman_canonical_CanonicalHuffmanCompressor;

/**
 * A decompressor of the block format of canonical Huffman codes of umilib.
 */
typedef struct umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor;

/**
 * Writes a new code of the `count` code lengths at `lengths` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_from_lengths(const uint8_t* lengths, size_t count, umilib_codec_huffman_canonical_HuffmanCode** out);

/**
 * Writes a new optimal code of the `count` frequencies at `frequencies`, of lengths at most
 * `maximum_length`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_from_frequencies(const uint32_t* frequencies, size_t count, uint32_t maximum_length, umilib_codec_huffman_canonical_HuffmanCode** out);

/**
 * Writes the code lengths `from_frequencies` assigns, one byte each, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_lengths_from_frequencies(const uint32_t* frequencies, size_t count, uint32_t maximum_length, umilib_ffi_Buffer* out);

/**
 * Releases a code. Does nothing if `code` is null.
 */
void umilib_codec_huffman_canonical_huffman_code_free(umilib_codec_huffman_canonical_HuffmanCode* code);

/**
 * Writes the number of symbols of the alphabet of `code` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_symbols(const umilib_codec_huffman_canonical_HuffmanCode* code, size_t* out);

/**
 * Writes the code lengths of `code`, one byte per symbol, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_lengths(const umilib_codec_huffman_canonical_HuffmanCode* code, umilib_ffi_Buffer* out);

/**
 * Writes the length of the code of `symbol` (0 if it has none) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_length(const umilib_codec_huffman_canonical_HuffmanCode* code, size_t symbol, uint32_t* out);

/**
 * Writes the code of `symbol`, its first bit the most significant of its length, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_code(const umilib_codec_huffman_canonical_HuffmanCode* code, size_t symbol, uint32_t* out);

/**
 * Writes the code of `symbol` with its bits reversed, its first bit the least significant, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_reversed_code(const umilib_codec_huffman_canonical_HuffmanCode* code, size_t symbol, uint32_t* out);

/**
 * Writes the length of the longest code into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_maximum_length(const umilib_codec_huffman_canonical_HuffmanCode* code, uint32_t* out);

/**
 * Writes whether the codes use every sequence of bits into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_code_is_complete(const umilib_codec_huffman_canonical_HuffmanCode* code, bool* out);

/**
 * Writes a new decoding table of `code` for streams of bit order `order` (0 first bit least
 * significant, 1 most significant) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_table_new(const umilib_codec_huffman_canonical_HuffmanCode* code, uint8_t order, umilib_codec_huffman_canonical_HuffmanTable** out);

/**
 * Releases a table. Does nothing if `table` is null.
 */
void umilib_codec_huffman_canonical_huffman_table_free(umilib_codec_huffman_canonical_HuffmanTable* table);

/**
 * Writes the number of bits to peek before decoding (the longest code) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_table_peek_bits(const umilib_codec_huffman_canonical_HuffmanTable* table, uint32_t* out);

/**
 * Decodes the code at the start of `bits`, the next peek_bits bits of a stream in the
 * order of the table, writing its symbol into `symbol` and its length into `length`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_huffman_table_decode(const umilib_codec_huffman_canonical_HuffmanTable* table, uint64_t bits, uint16_t* symbol, uint32_t* length);

/**
 * Writes a new compressor of blocks of at most `block_size` bytes (at least 1) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_compressor_new(size_t block_size, umilib_codec_huffman_canonical_CanonicalHuffmanCompressor** out);

/**
 * Writes the default block size into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_config_default_block_size(size_t* out);

/**
 * Writes a new decompressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_new(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_huffman_canonical_canonical_huffman_compressor_free(umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_compressor_clone(const umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* state, umilib_codec_huffman_canonical_CanonicalHuffmanCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_compressor_reset(umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_compressor_compress(umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_compressor_compress_to_vec(umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_huffman_canonical_canonical_huffman_decompressor_free(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_clone(const umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state, umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_reset(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_decompress(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_finish(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_huffman_canonical_canonical_huffman_decompressor_decompress_to_vec(umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
