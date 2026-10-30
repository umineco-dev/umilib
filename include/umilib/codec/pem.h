/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_PEM_H
#define UMILIB_CODEC_PEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Options of PEM parsing.
 */
typedef struct umilib_codec_pem_PEMConfig umilib_codec_pem_PEMConfig;

/**
 * A label and its data, zeroized when released.
 */
typedef struct umilib_codec_pem_PEMDocument umilib_codec_pem_PEMDocument;

/**
 * Creates the default configuration (standard grammar, matching labels, 16 MiB).
 */
const umilib_ffi_Status* umilib_codec_pem_pem_config_new(umilib_codec_pem_PEMConfig** out);

/**
 * Releases a configuration. Does nothing if `config` is null.
 */
void umilib_codec_pem_pem_config_free(umilib_codec_pem_PEMConfig* config);

/**
 * Writes the settings of `config`: the grammar (0 strict, 1 standard, 2 lax), whether END
 * labels must match, and the longest text accepted.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_config_settings(const umilib_codec_pem_PEMConfig* config, uint8_t* out_strictness, bool* out_require_matching_label, size_t* out_maximum_length);

/**
 * Changes every setting of `config` (see `umilib_codec_pem_pem_config_settings`).
 */
const umilib_ffi_Status* umilib_codec_pem_pem_config_set(umilib_codec_pem_PEMConfig* config, uint8_t strictness, bool require_matching_label, size_t maximum_length);

/**
 * Writes whether the UTF-8 `label` follows the grammar of RFC 7468 section 3 into `out`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_label_is_valid(const uint8_t* label, size_t length, bool* out);

/**
 * Creates a document with the UTF-8 `label` and a copy of `length` bytes at `data`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_new(const uint8_t* label, size_t label_length, const uint8_t* data, size_t length, umilib_codec_pem_PEMDocument** out);

/**
 * Zeroizes and releases a document. Does nothing if `document` is null.
 */
void umilib_codec_pem_pem_document_free(umilib_codec_pem_PEMDocument* document);

/**
 * Writes the label of `document`, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_label(const umilib_codec_pem_PEMDocument* document, umilib_ffi_Buffer* out);

/**
 * Writes a pointer to the data of `document`, valid until it is released, into
 * `out_data` and its length into `out_length`. No copy is made.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_data(const umilib_codec_pem_PEMDocument* document, const uint8_t** out_data, size_t* out_length);

/**
 * Moves the data of `document` into `out` and releases the document; the
 * caller becomes responsible for zeroizing it. On failure the handle is not released.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_into_data(umilib_codec_pem_PEMDocument* document, umilib_ffi_Buffer* out);

/**
 * Parses the first document of `length` bytes at `text` with `config` (null for the defaults).
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_decode(const uint8_t* text, size_t length, const umilib_codec_pem_PEMConfig* config, umilib_codec_pem_PEMDocument** out);

/**
 * Parses the next document at or after byte `start` of `text`. Writes whether one was
 * found into `out_found`, the document into `out` (null if none) and the position after
 * it into `out_next`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_decode_next(const uint8_t* text, size_t length, size_t start, const umilib_codec_pem_PEMConfig* config, bool* out_found, umilib_codec_pem_PEMDocument** out, size_t* out_next);

/**
 * Writes `document` in the strict format with `line_ending` (0 LF, 1 CRLF) into `out`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_encode_with(const umilib_codec_pem_PEMDocument* document, uint8_t line_ending, umilib_ffi_Buffer* out);

/**
 * Writes `document` in the strict format with LF line endings into `out`.
 */
const umilib_ffi_Status* umilib_codec_pem_pem_document_encode(const umilib_codec_pem_PEMDocument* document, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
