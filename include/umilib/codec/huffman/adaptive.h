/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_HUFFMAN_ADAPTIVE_H
#define UMILIB_CODEC_HUFFMAN_ADAPTIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The code tree of adaptive Huffman coding by Vitter's algorithm.
 */
typedef struct umilib_codec_huffman_adaptive_AdaptiveHuffmanTree umilib_codec_huffman_adaptive_AdaptiveHuffmanTree;

/**
 * A compressor of the adaptive Huffman format of umilib.
 */
typedef struct umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor;

/**
 * A decompressor of the adaptive Huffman format of umilib.
 */
typedef struct umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor;

/**
 * Writes a new tree of an alphabet of `symbols` symbols, before any occurred, into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_tree_new(size_t symbols, umilib_codec_huffman_adaptive_AdaptiveHuffmanTree** out);

/**
 * Releases a tree. Does nothing if `tree` is null.
 */
void umilib_codec_huffman_adaptive_adaptive_huffman_tree_free(umilib_codec_huffman_adaptive_AdaptiveHuffmanTree* tree);

/**
 * Writes a copy of `tree` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_tree_clone(const umilib_codec_huffman_adaptive_AdaptiveHuffmanTree* tree, umilib_codec_huffman_adaptive_AdaptiveHuffmanTree** out);

/**
 * Writes the number of symbols of the alphabet of `tree` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_tree_symbols(const umilib_codec_huffman_adaptive_AdaptiveHuffmanTree* tree, size_t* out);

/**
 * Writes the code of `symbol` in the current tree (with the index of an unseen symbol) into
 * `bits`, its first bit the least significant, and its number of bits into `length`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_tree_code(const umilib_codec_huffman_adaptive_AdaptiveHuffmanTree* tree, size_t symbol, umilib_ffi_U128* bits, uint32_t* length);

/**
 * Counts an occurrence of `symbol` and updates the tree.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_tree_update(umilib_codec_huffman_adaptive_AdaptiveHuffmanTree* tree, size_t symbol);

/**
 * Writes a new compressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_compressor_new(umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor** out);

/**
 * Writes a new decompressor into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_new(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor** out);

/**
 * Releases the compressor. Does nothing if `state` is null.
 */
void umilib_codec_huffman_adaptive_adaptive_huffman_compressor_free(umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_compressor_clone(const umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor* state, umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor** out);

/**
 * Returns the compressor to the state of a new stream, keeping its parameters.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_compressor_reset(umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor* state);

/**
 * Compresses from the `input_length` bytes at `input` into the `output_length` bytes at
 * `output` (which must not overlap), as `flush` (0 none, 1 sync, 2 finish) asks, and
 * writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_compressor_compress(umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, uint8_t flush, umilib_codec_Progress* progress);

/**
 * Writes the whole stream of the `input_length` bytes at `input` (compressed and finished) into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_compressor_compress_to_vec(umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor* state, const uint8_t* input, size_t input_length, umilib_ffi_Buffer* out);

/**
 * Releases the decompressor. Does nothing if `state` is null.
 */
void umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_free(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_clone(const umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state, umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor** out);

/**
 * Returns the decompressor to the state of a new stream, keeping its configuration.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_reset(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state);

/**
 * Decompresses from the `input_length` bytes at `input` into the `output_length` bytes
 * at `output` (which must not overlap) and writes what the call did into `progress`.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_decompress(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state, const uint8_t* input, size_t input_length, uint8_t* output, size_t output_length, umilib_codec_Progress* progress);

/**
 * Tells the decompressor that the input ended with the bytes it consumed; fails with
 * `UnexpectedEnd` unless the stream may end there.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_finish(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state);

/**
 * Writes the data of the stream in the `input_length` bytes at `input`, which must hold
 * all of it, into `out`; fails with `LimitExceeded` beyond `limit` bytes.
 */
const umilib_ffi_Status* umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_decompress_to_vec(umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor* state, const uint8_t* input, size_t input_length, size_t limit, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
