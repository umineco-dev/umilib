/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BASE_H
#define UMILIB_CODEC_BASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The characters of an encoding; alphabets are static and never freed.
 */
typedef struct umilib_codec_base_Alphabet umilib_codec_base_Alphabet;

/**
 * A run of `count` consecutive characters from `first`, encoding values from `value`;
 * only used for decoding unless `canonical`.
 */
typedef struct umilib_codec_base_AlphabetRange {
    uint8_t first;
    uint8_t count;
    uint8_t value;
    bool canonical;
} umilib_codec_base_AlphabetRange;

/**
 * An encoding of a fixed number of bits per character.
 */
typedef struct umilib_codec_base_BitEncoding umilib_codec_base_BitEncoding;

/**
 * Writes the number of values `alphabet` encodes into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_alphabet_size(const umilib_codec_base_Alphabet* alphabet, size_t* out);

/**
 * Writes the character encoding `value`, which must be smaller than the alphabet size, into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_alphabet_encode(const umilib_codec_base_Alphabet* alphabet, uint8_t value, uint8_t* out);

/**
 * Writes whether `character` is part of `alphabet` into `out_valid` and its value into `out_value`.
 */
const umilib_ffi_Status* umilib_codec_base_alphabet_decode(const umilib_codec_base_Alphabet* alphabet, uint8_t character, bool* out_valid, uint8_t* out_value);

/**
 * Returns `0xFF` if `value` is in `start..start + count` and `0` otherwise, without branching.
 */
uint8_t umilib_codec_base_alphabet_mask_in(uint8_t value, uint8_t start, uint8_t count);

/**
 * Writes the number of runs of `alphabet` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_alphabet_range_count(const umilib_codec_base_Alphabet* alphabet, size_t* out);

/**
 * Writes the run of `alphabet` at `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_alphabet_ranges(const umilib_codec_base_Alphabet* alphabet, size_t index, umilib_codec_base_AlphabetRange* out);

/**
 * Creates a bit encoding: `bits` (1 to 7) bits per character of the static `alphabet`, which
 * must encode `2^bits` values, with `padding` and a `padding_character` outside the alphabet.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_new(const umilib_codec_base_Alphabet* alphabet, uint32_t bits, uint8_t padding, uint8_t padding_character, umilib_codec_base_BitEncoding** out);

/**
 * Releases a bit encoding. Does nothing if `encoding` is null.
 */
void umilib_codec_base_bit_encoding_free(umilib_codec_base_BitEncoding* encoding);

/**
 * Writes the bits per character, the padding and the padding character of `encoding`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_parameters(const umilib_codec_base_BitEncoding* encoding, uint32_t* out_bits, uint8_t* out_padding, uint8_t* out_padding_character);

/**
 * Writes a pointer to a static copy of the alphabet of `encoding`, valid until the encoding is released, into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_alphabet(const umilib_codec_base_BitEncoding* encoding, const umilib_codec_base_Alphabet** out);

/**
 * Writes the number of characters in a group into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_group_characters(const umilib_codec_base_BitEncoding* encoding, size_t* out);

/**
 * Writes the number of bytes in a group into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_group_bytes(const umilib_codec_base_BitEncoding* encoding, size_t* out);

/**
 * Writes whether `remainder` characters can end the text after the last full group into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_is_valid_remainder(const umilib_codec_base_BitEncoding* encoding, size_t remainder, bool* out);

/**
 * Writes whether the fields of `encoding` form an encoding (1 to 7 bits, an alphabet of
 * `2^bits` characters, a padding character outside it) into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_is_valid(const umilib_codec_base_BitEncoding* encoding, bool* out);

/**
 * Writes whether the largest encoded length of `length` bytes fits in `size_t` into
 * `out_has_length`, and the length into `out_length`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_maximum_encoded_length(const umilib_codec_base_BitEncoding* encoding, size_t length, bool* out_has_length, size_t* out_length);

/**
 * Writes the largest number of bytes decoding `length` characters can produce into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_maximum_decoded_length(const umilib_codec_base_BitEncoding* encoding, size_t length, size_t* out);

/**
 * Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of characters into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_encode_to_slice(const umilib_codec_base_BitEncoding* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Decodes `length` characters at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of bytes into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_decode_to_slice(const umilib_codec_base_BitEncoding* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_try_encode(const umilib_codec_base_BitEncoding* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_encode(const umilib_codec_base_BitEncoding* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Decodes `length` characters at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_bit_encoding_decode(const umilib_codec_base_BitEncoding* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
