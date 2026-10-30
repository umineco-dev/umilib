/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_ASN1_BER_H
#define UMILIB_CODEC_ASN1_BER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/asn1.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * One BER element; its pointers borrow the input of the reader it was read from.
 */
typedef struct umilib_codec_asn1_ber_BERElement {
    umilib_codec_asn1_Tag tag;
    const uint8_t* content;
    size_t content_length;
    const uint8_t* encoding;
    size_t encoding_length;
    size_t position;
    size_t content_position;
    bool indefinite;
    size_t depth;
    size_t maximum_depth;
} umilib_codec_asn1_ber_BERElement;

/**
 * A cursor over BER elements of caller-owned bytes.
 */
typedef struct umilib_codec_asn1_ber_BERReader umilib_codec_asn1_ber_BERReader;

/**
 * Creates a reader over `length` bytes at `data`, which must stay valid and unchanged
 * while the reader, readers nested in it and elements read from it are used.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_new(const uint8_t* data, size_t length, umilib_codec_asn1_ber_BERReader** out);

/**
 * Writes a new reader equal to `reader` with another nesting limit into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_with_maximum_depth(const umilib_codec_asn1_ber_BERReader* reader, size_t maximum_depth, umilib_codec_asn1_ber_BERReader** out);

/**
 * Writes the offset of the next element in the outermost input into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_position(const umilib_codec_asn1_ber_BERReader* reader, size_t* out);

/**
 * Writes the nesting depth into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_depth(const umilib_codec_asn1_ber_BERReader* reader, size_t* out);

/**
 * Writes whether no element is left into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_is_empty(const umilib_codec_asn1_ber_BERReader* reader, bool* out);

/**
 * Fails with `TrailingData` if any element is left.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_finish(const umilib_codec_asn1_ber_BERReader* reader);

/**
 * Writes the next element into `out` without moving.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_peek(const umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_ber_BERElement* out);

/**
 * Reads the next element of any type into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_element(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_ber_BERElement* out);

/**
 * Reads the next element, which must have `tag`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_expected(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_Tag tag, umilib_codec_asn1_ber_BERElement* out);

/**
 * Writes whether an element is left into `out_has_tag` and its tag into `out_tag`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_peek_tag(const umilib_codec_asn1_ber_BERReader* reader, bool* out_has_tag, umilib_codec_asn1_Tag* out_tag);

/**
 * Reads the next element if it has `tag`: writes whether it did into `out_found` and the element into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_optional(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_Tag tag, bool* out_found, umilib_codec_asn1_ber_BERElement* out);

/**
 * Reads a constructed element with `tag` and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_constructed(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_Tag tag, umilib_codec_asn1_ber_BERReader** out);

/**
 * Reads a SEQUENCE and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_sequence(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_ber_BERReader** out);

/**
 * Reads a SET and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_set(umilib_codec_asn1_ber_BERReader* reader, umilib_codec_asn1_ber_BERReader** out);

/**
 * Reads `[number] EXPLICIT` and writes a new reader over the tagged contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_read_explicit(umilib_codec_asn1_ber_BERReader* reader, uint32_t number, umilib_codec_asn1_ber_BERReader** out);

/**
 * Converts the single element of `length` bytes at `data` to its DER encoding, written into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_reader_to_der(const uint8_t* data, size_t length, size_t maximum_depth, umilib_ffi_Buffer* out);

/**
 * Releases a reader. Does nothing if `reader` is null.
 */
void umilib_codec_asn1_ber_ber_reader_free(umilib_codec_asn1_ber_BERReader* reader);

/**
 * Returns whether elements of the universal type `number` are strings, which BER may split into segments.
 */
bool umilib_codec_asn1_ber_ber_reader_is_string_type(uint32_t number);

/**
 * Whether elements of the universal type `number` must be constructed (SEQUENCE, SET,
 * EXTERNAL, EMBEDDED PDV and CHARACTER STRING).
 */
bool umilib_codec_asn1_ber_ber_reader_must_be_constructed(uint32_t number);

/**
 * Writes a new reader over the contents of a constructed `element` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_children(const umilib_codec_asn1_ber_BERElement* element, umilib_codec_asn1_ber_BERReader** out);

/**
 * Reads the contents as a BOOLEAN (any non-zero octet is true) into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_boolean(const umilib_codec_asn1_ber_BERElement* element, bool* out);

/**
 * Reads the contents as a UTCTime in any BER form, converted to UTC, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_utc_time(const umilib_codec_asn1_ber_BERElement* element, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads the contents as a GeneralizedTime in any BER form, converted to UTC, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_generalized_time(const umilib_codec_asn1_ber_BERElement* element, umilib_codec_asn1_ASN1Time* out);

/**
 * Writes the contents of a string type, joining constructed segments whose tag must be `segment`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_string_content(const umilib_codec_asn1_ber_BERElement* element, umilib_codec_asn1_Tag segment, umilib_ffi_Buffer* out);

/**
 * Reads the contents as an OCTET STRING, joining segments, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_octet_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a UTF8String into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_utf8_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a PrintableString into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_printable_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as an IA5String into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_ia5_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a VisibleString into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_visible_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a NumericString into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_numeric_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a BMPString, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_bmp_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a UniversalString, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_universal_string(const umilib_codec_asn1_ber_BERElement* element, umilib_ffi_Buffer* out);

/**
 * Checks the contents as an INTEGER and writes a pointer to them and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_integer(const umilib_codec_asn1_ber_BERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a BIT STRING, joining segments: writes the unused bits and the octets into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_bit_string(const umilib_codec_asn1_ber_BERElement* element, uint8_t* out_unused_bits, umilib_ffi_Buffer* out);

/**
 * Checks that the contents are a NULL.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_null(const umilib_codec_asn1_ber_BERElement* element);

/**
 * Reads the contents as an OBJECT IDENTIFIER into a new handle written into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_ber_ber_element_as_object_identifier(const umilib_codec_asn1_ber_BERElement* element, umilib_codec_asn1_ObjectIdentifier** out);

#ifdef __cplusplus
}
#endif

#endif
