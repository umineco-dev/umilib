/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BASE_BASE85_H
#define UMILIB_CODEC_BASE_BASE85_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/base.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Base85 encoding.
 */
typedef struct umilib_codec_base_base85_Base85 umilib_codec_base_base85_Base85;

/**
 * A new handle holding `Base85::ASCII85`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_ascii85(umilib_codec_base_base85_Base85** out);

/**
 * A new handle holding `Base85::ASCII85_ADOBE`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_ascii85_adobe(umilib_codec_base_base85_Base85** out);

/**
 * A new handle holding `Base85::Z85`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_z85(umilib_codec_base_base85_Base85** out);

/**
 * A new handle holding `Base85::RFC1924`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_rfc1924(umilib_codec_base_base85_Base85** out);

/**
 * Releases an encoding. Does nothing if `encoding` is null.
 */
void umilib_codec_base_base85_base85_free(umilib_codec_base_base85_Base85* encoding);

/**
 * Returns the static alphabet `Base85::ASCII85_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base85_base85_ascii85_alphabet(void);

/**
 * Returns the static alphabet `Base85::Z85_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base85_base85_z85_alphabet(void);

/**
 * Returns the static alphabet `Base85::RFC1924_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base85_base85_rfc1924_alphabet(void);

/**
 * Writes the delimiter lengths of `encoding`, before and after, into `out_start` and `out_end`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_delimiter_lengths(const umilib_codec_base_base85_Base85* encoding, size_t* out_start, size_t* out_end);

/**
 * Writes whether `encoding` has delimiters into `out_has_delimiters`, and copies of the
 * delimiters before and after the text into `out_start` and `out_end`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_delimiters(const umilib_codec_base_base85_Base85* encoding, bool* out_has_delimiters, umilib_ffi_Buffer* out_start, umilib_ffi_Buffer* out_end);

/**
 * Writes the five digits of `value`, most significant first, into the 5 bytes at `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_encode_group(const umilib_codec_base_base85_Base85* encoding, uint32_t value, uint8_t* out);

/**
 * Writes the settings of `encoding`: whether it has a zero-group character and which,
 * whether partial groups are allowed and whether white space is ignored.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_settings(const umilib_codec_base_base85_Base85* encoding, bool* out_has_zero_group, uint8_t* out_zero_group, bool* out_partial_groups, bool* out_ignore_whitespace);

/**
 * Writes whether the largest encoded length of `length` bytes fits in `size_t` into
 * `out_has_length`, and the length into `out_length`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_maximum_encoded_length(const umilib_codec_base_base85_Base85* encoding, size_t length, bool* out_has_length, size_t* out_length);

/**
 * Writes the largest number of bytes decoding `length` characters can produce into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_maximum_decoded_length(const umilib_codec_base_base85_Base85* encoding, size_t length, size_t* out);

/**
 * Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of characters into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_encode_to_slice(const umilib_codec_base_base85_Base85* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Decodes `length` characters at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of bytes into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_decode_to_slice(const umilib_codec_base_base85_Base85* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_try_encode(const umilib_codec_base_base85_Base85* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_encode(const umilib_codec_base_base85_Base85* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Decodes `length` characters at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base85_base85_decode(const umilib_codec_base_base85_Base85* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
