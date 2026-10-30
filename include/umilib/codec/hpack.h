/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_HPACK_H
#define UMILIB_CODEC_HPACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The configuration of an HPACK encoder.
 */
typedef struct umilib_codec_hpack_HPACKEncoderConfig {
    size_t maximum_table_size;
    bool huffman;
    size_t maximum_indexed_size;
} umilib_codec_hpack_HPACKEncoderConfig;

/**
 * The configuration of an HPACK decoder.
 */
typedef struct umilib_codec_hpack_HPACKDecoderConfig {
    size_t maximum_table_size;
    size_t maximum_string_length;
    size_t maximum_field_list_size;
} umilib_codec_hpack_HPACKDecoderConfig;

/**
 * A list of HPACK fields.
 */
typedef struct umilib_codec_hpack_HPACKFields umilib_codec_hpack_HPACKFields;

/**
 * An HPACK encoder and its table.
 */
typedef struct umilib_codec_hpack_HPACKEncoder umilib_codec_hpack_HPACKEncoder;

/**
 * An HPACK decoder and its table.
 */
typedef struct umilib_codec_hpack_HPACKDecoder umilib_codec_hpack_HPACKDecoder;

/**
 * Writes the default configuration of an encoder into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_encoder_config_default(umilib_codec_hpack_HPACKEncoderConfig* out);

/**
 * Writes the default configuration of a decoder into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_decoder_config_default(umilib_codec_hpack_HPACKDecoderConfig* out);

/**
 * Writes an empty list of fields into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_fields_new(umilib_codec_hpack_HPACKFields** out);

/**
 * Appends the field of the `name_length` bytes at `name` and the `value_length` bytes at
 * `value`, never indexed if `sensitive`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_fields_push(umilib_codec_hpack_HPACKFields* fields, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length, bool sensitive);

/**
 * Writes the number of fields of the list into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_fields_count(const umilib_codec_hpack_HPACKFields* fields, size_t* out);

/**
 * Writes the name of the field `index` into `out_name`, its value into `out_value` and
 * whether it is sensitive into `out_sensitive`; fails with NoSuchField past the end.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_fields_get(const umilib_codec_hpack_HPACKFields* fields, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value, bool* out_sensitive);

/**
 * Releases a list of fields. Does nothing if `fields` is null.
 */
void umilib_codec_hpack_hpack_fields_free(umilib_codec_hpack_HPACKFields* fields);

/**
 * Writes an encoder of `config` for a decoder whose table is limited to `limit` bytes into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_encoder_new(umilib_codec_hpack_HPACKEncoderConfig config, size_t limit, umilib_codec_hpack_HPACKEncoder** out);

/**
 * Takes the decoder's new limit of the table (SETTINGS_HEADER_TABLE_SIZE); the next block
 * starts with the size updates it calls for.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_encoder_set_limit(umilib_codec_hpack_HPACKEncoder* encoder, size_t limit);

/**
 * Resizes the table to `size` bytes, within the limit; the next block says so.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_encoder_resize(umilib_codec_hpack_HPACKEncoder* encoder, size_t size);

/**
 * Writes the field block of `fields` into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_encoder_encode(umilib_codec_hpack_HPACKEncoder* encoder, const umilib_codec_hpack_HPACKFields* fields, umilib_ffi_Buffer* out);

/**
 * Releases an encoder. Does nothing if `encoder` is null.
 */
void umilib_codec_hpack_hpack_encoder_free(umilib_codec_hpack_HPACKEncoder* encoder);

/**
 * Writes a decoder of `config` into `out`.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_decoder_new(umilib_codec_hpack_HPACKDecoderConfig config, umilib_codec_hpack_HPACKDecoder** out);

/**
 * Sets the limit of the table this end advertised; a lower one must be confirmed by the
 * encoder's next block (RFC 7541 §4.2).
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_decoder_set_limit(umilib_codec_hpack_HPACKDecoder* decoder, size_t limit);

/**
 * Decodes the field block of `length` bytes at `block` and writes its fields into `out`;
 * after FieldListTooLarge the table is still in step and nothing is written.
 */
const umilib_ffi_Status* umilib_codec_hpack_hpack_decoder_decode(umilib_codec_hpack_HPACKDecoder* decoder, const uint8_t* block, size_t length, umilib_codec_hpack_HPACKFields** out);

/**
 * Releases a decoder. Does nothing if `decoder` is null.
 */
void umilib_codec_hpack_hpack_decoder_free(umilib_codec_hpack_HPACKDecoder* decoder);

#ifdef __cplusplus
}
#endif

#endif
