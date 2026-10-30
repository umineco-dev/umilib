/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BASE_BASE64_H
#define UMILIB_CODEC_BASE_BASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/base.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Base64 encoding.
 */
typedef struct umilib_codec_base_base64_Base64 umilib_codec_base_base64_Base64;

/**
 * A new handle holding `Base64::STANDARD`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_standard(umilib_codec_base_base64_Base64** out);

/**
 * A new handle holding `Base64::STANDARD_NO_PADDING`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_standard_no_padding(umilib_codec_base_base64_Base64** out);

/**
 * A new handle holding `Base64::URL_SAFE`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_url_safe(umilib_codec_base_base64_Base64** out);

/**
 * A new handle holding `Base64::URL_SAFE_NO_PADDING`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_url_safe_no_padding(umilib_codec_base_base64_Base64** out);

/**
 * Releases an encoding. Does nothing if `encoding` is null.
 */
void umilib_codec_base_base64_base64_free(umilib_codec_base_base64_Base64* encoding);

/**
 * Returns the static alphabet `Base64::STANDARD_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base64_base64_standard_alphabet(void);

/**
 * Returns the static alphabet `Base64::URL_SAFE_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base64_base64_url_safe_alphabet(void);

/**
 * Creates an encoding with the static `alphabet`, which must encode 64 values, and `padding`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_new(const umilib_codec_base_Alphabet* alphabet, uint8_t padding, umilib_codec_base_base64_Base64** out);

/**
 * Writes a new handle holding a copy of the bit encoding of `encoding` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_encoding(const umilib_codec_base_base64_Base64* encoding, umilib_codec_base_BitEncoding** out);

/**
 * Writes whether the largest encoded length of `length` bytes fits in `size_t` into
 * `out_has_length`, and the length into `out_length`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_maximum_encoded_length(const umilib_codec_base_base64_Base64* encoding, size_t length, bool* out_has_length, size_t* out_length);

/**
 * Writes the largest number of bytes decoding `length` characters can produce into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_maximum_decoded_length(const umilib_codec_base_base64_Base64* encoding, size_t length, size_t* out);

/**
 * Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of characters into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_encode_to_slice(const umilib_codec_base_base64_Base64* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Decodes `length` characters at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of bytes into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_decode_to_slice(const umilib_codec_base_base64_Base64* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_try_encode(const umilib_codec_base_base64_Base64* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_encode(const umilib_codec_base_base64_Base64* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Decodes `length` characters at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base64_base64_decode(const umilib_codec_base_base64_Base64* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
