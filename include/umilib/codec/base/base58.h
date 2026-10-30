/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_BASE_BASE58_H
#define UMILIB_CODEC_BASE_BASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/base.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A Base58 encoding.
 */
typedef struct umilib_codec_base_base58_Base58 umilib_codec_base_base58_Base58;

/**
 * A new handle holding `Base58::BITCOIN`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_bitcoin(umilib_codec_base_base58_Base58** out);

/**
 * A new handle holding `Base58::FLICKR`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_flickr(umilib_codec_base_base58_Base58** out);

/**
 * A new handle holding `Base58::RIPPLE`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_ripple(umilib_codec_base_base58_Base58** out);

/**
 * Releases an encoding. Does nothing if `encoding` is null.
 */
void umilib_codec_base_base58_base58_free(umilib_codec_base_base58_Base58* encoding);

/**
 * Returns the static alphabet `Base58::BITCOIN_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base58_base58_bitcoin_alphabet(void);

/**
 * Returns the static alphabet `Base58::FLICKR_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base58_base58_flickr_alphabet(void);

/**
 * Returns the static alphabet `Base58::RIPPLE_ALPHABET`.
 */
const umilib_codec_base_Alphabet* umilib_codec_base_base58_base58_ripple_alphabet(void);

/**
 * Creates a Base58 encoding with the static `alphabet`, which must encode 58 values.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_new(const umilib_codec_base_Alphabet* alphabet, umilib_codec_base_base58_Base58** out);

/**
 * Writes a new handle holding `encoding` with another length limit into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_with_maximum_length(const umilib_codec_base_base58_Base58* encoding, size_t maximum_length, umilib_codec_base_base58_Base58** out);

/**
 * Writes the length limit of `encoding` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_maximum_length(const umilib_codec_base_base58_Base58* encoding, size_t* out);

/**
 * Fails with `InputTooLong` if `length` exceeds the limit of `encoding`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_check_length(const umilib_codec_base_base58_Base58* encoding, size_t length);

/**
 * Writes whether the largest encoded length of `length` bytes fits in `size_t` into
 * `out_has_length`, and the length into `out_length`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_maximum_encoded_length(const umilib_codec_base_base58_Base58* encoding, size_t length, bool* out_has_length, size_t* out_length);

/**
 * Writes the largest number of bytes decoding `length` characters can produce into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_maximum_decoded_length(const umilib_codec_base_base58_Base58* encoding, size_t length, size_t* out);

/**
 * Encodes `length` bytes at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of characters into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_encode_to_slice(const umilib_codec_base_base58_Base58* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Decodes `length` characters at `data` into the `output_length` bytes at `output`,
 * which must not overlap them, and writes the number of bytes into `out_written`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_decode_to_slice(const umilib_codec_base_base58_Base58* encoding, const uint8_t* data, size_t length, uint8_t* output, size_t output_length, size_t* out_written);

/**
 * Encodes `length` bytes at `data` into `out`; fails only if memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_try_encode(const umilib_codec_base_base58_Base58* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Like the `try_encode` function: in C, encoding reports allocation failure instead of aborting.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_encode(const umilib_codec_base_base58_Base58* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Decodes `length` characters at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_base_base58_base58_decode(const umilib_codec_base_base58_Base58* encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
