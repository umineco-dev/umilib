/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_QPACK_H
#define UMILIB_CODEC_QPACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/hpack.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The configuration of a QPACK encoder.
 */
typedef struct umilib_codec_qpack_QPACKEncoderConfig {
    size_t maximum_table_capacity;
    bool huffman;
    size_t maximum_indexed_size;
    bool blocking;
} umilib_codec_qpack_QPACKEncoderConfig;

/**
 * The configuration of a QPACK decoder.
 */
typedef struct umilib_codec_qpack_QPACKDecoderConfig {
    size_t maximum_table_capacity;
    size_t blocked_streams;
    size_t maximum_string_length;
    size_t maximum_field_list_size;
} umilib_codec_qpack_QPACKDecoderConfig;

/**
 * A QPACK encoder and its table.
 */
typedef struct umilib_codec_qpack_QPACKEncoder umilib_codec_qpack_QPACKEncoder;

/**
 * A QPACK decoder and its table.
 */
typedef struct umilib_codec_qpack_QPACKDecoder umilib_codec_qpack_QPACKDecoder;

/**
 * Writes the default configuration of an encoder into `out`.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_config_default(umilib_codec_qpack_QPACKEncoderConfig* out);

/**
 * Writes the default configuration of a decoder into `out`.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_config_default(umilib_codec_qpack_QPACKDecoderConfig* out);

/**
 * Writes an encoder of `config` into `out`; it uses no dynamic table until the peer's settings arrive.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_new(umilib_codec_qpack_QPACKEncoderConfig config, umilib_codec_qpack_QPACKEncoder** out);

/**
 * Takes the decoder's SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_set_peer_settings(umilib_codec_qpack_QPACKEncoder* encoder, size_t maximum_table_capacity, size_t blocked_streams);

/**
 * Writes the encoded field section of `fields` on `stream` into `out`, after writing the
 * inserts it uses to the encoder stream's instructions.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_encode(umilib_codec_qpack_QPACKEncoder* encoder, uint64_t stream, const umilib_codec_hpack_HPACKFields* fields, umilib_ffi_Buffer* out);

/**
 * Takes the `length` bytes at `bytes` of the decoder stream.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_receive_decoder_stream(umilib_codec_qpack_QPACKEncoder* encoder, const uint8_t* bytes, size_t length);

/**
 * Writes the encoder stream's instructions to send into `out`.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_encoder_take_instructions(umilib_codec_qpack_QPACKEncoder* encoder, umilib_ffi_Buffer* out);

/**
 * Releases an encoder. Does nothing if `encoder` is null.
 */
void umilib_codec_qpack_qpack_encoder_free(umilib_codec_qpack_QPACKEncoder* encoder);

/**
 * Writes a decoder of `config` into `out`.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_new(umilib_codec_qpack_QPACKDecoderConfig config, umilib_codec_qpack_QPACKDecoder** out);

/**
 * Takes the `length` bytes at `bytes` of the encoder stream.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_receive_encoder_stream(umilib_codec_qpack_QPACKDecoder* decoder, const uint8_t* bytes, size_t length);

/**
 * Decodes the field section of `length` bytes at `section` on `stream`: writes whether it
 * waits for inserts not received yet into `out_blocked` (decode it again once they arrive),
 * else its fields into `out` (null if blocked).
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_decode(umilib_codec_qpack_QPACKDecoder* decoder, uint64_t stream, const uint8_t* section, size_t length, bool* out_blocked, umilib_codec_hpack_HPACKFields** out);

/**
 * Abandons `stream`: its blocked section, if any, and a Stream Cancellation for the encoder.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_cancel_stream(umilib_codec_qpack_QPACKDecoder* decoder, uint64_t stream);

/**
 * Writes the decoder stream's instructions to send into `out`.
 */
const umilib_ffi_Status* umilib_codec_qpack_qpack_decoder_take_instructions(umilib_codec_qpack_QPACKDecoder* decoder, umilib_ffi_Buffer* out);

/**
 * Releases a decoder. Does nothing if `decoder` is null.
 */
void umilib_codec_qpack_qpack_decoder_free(umilib_codec_qpack_QPACKDecoder* decoder);

#ifdef __cplusplus
}
#endif

#endif
