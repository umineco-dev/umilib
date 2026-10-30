/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BASE_BASE16_H
#define UMILIB_CODEC_BASE_BASE16_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/base.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Base16 encoding.
 */
typedef struct umilib_codec_base_base16_Base16 umilib_codec_base_base16_Base16;

/**
 * A new handle holding `Base16::UPPER`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_upper(umilib_codec_base_base16_Base16** out);

/**
 * A new handle holding `Base16::LOWER`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_lower(umilib_codec_base_base16_Base16** out);

/**
 * Releases an encoding. Does nothing if `encoding` is null.
 */
void umilib_codec_base_base16_base16_free(umilib_codec_base_base16_Base16* encoding);

/**
 * Creates a Base16 encoding with the static `alphabet`, which must encode 16 values.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_new(const umilib_codec_base_Alphabet* alphabet, umilib_codec_base_base16_Base16** out);

/**
 * Writes a new handle holding a copy of the bit encoding of `encoding` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_encoding(const umilib_codec_base_base16_Base16* encoding, umilib_codec_base_BitEncoding** out);

/**
 * Writes whether the largest encoded length of `length` bytes fits in `size_t` into
 * `out_has_length`, and the length into `out_length`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_maximum_encoded_length(const umilib_codec_base_base16_Base16* encoding, size_t length, bool* out_has_length, size_t* out_length);

/**
 * Writes the largest number of bytes decoding `length` characters can produce into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_maximum_decoded_length(const umilib_codec_base_base16_Base16* encoding, size_t length, size_t* out);

/**
 * Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of characters into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_encode_to_slice(const umilib_codec_base_base16_Base16* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Decodes `length` characters at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of bytes into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_decode_to_slice(const umilib_codec_base_base16_Base16* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_try_encode(const umilib_codec_base_base16_Base16* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_encode(const umilib_codec_base_base16_Base16* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Decodes `length` characters at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base16_base16_decode(const umilib_codec_base_base16_Base16* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
