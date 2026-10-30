/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_ASN1_DER_H
#define UMILIB_CODEC_ASN1_DER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/codec/asn1.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * One DER element; its pointers borrow the input of the reader it was read from.
 */
typedef struct umilib_codec_asn1_der_DERElement {
    umilib_codec_asn1_Tag tag;
    const uint8_t* content;
    size_t content_length;
    const uint8_t* encoding;
    size_t encoding_length;
    size_t position;
} umilib_codec_asn1_der_DERElement;

/**
 * A cursor over DER elements of caller-owned bytes.
 */
typedef struct umilib_codec_asn1_der_DERReader umilib_codec_asn1_der_DERReader;

/**
 * Writes DER elements.
 */
typedef struct umilib_codec_asn1_der_DERWriter umilib_codec_asn1_der_DERWriter;

/**
 * Creates a reader over `length` bytes at `data`, which must stay valid and unchanged
 * while the reader, readers nested in it and elements read from it are used.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_new(const uint8_t* data, size_t length, umilib_codec_asn1_der_DERReader** out);

/**
 * Writes a new reader equal to `reader` with another nesting limit into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_with_maximum_depth(const umilib_codec_asn1_der_DERReader* reader, size_t maximum_depth, umilib_codec_asn1_der_DERReader** out);

/**
 * Writes the offset of the next element in the outermost input into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_position(const umilib_codec_asn1_der_DERReader* reader, size_t* out);

/**
 * Writes the nesting depth into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_depth(const umilib_codec_asn1_der_DERReader* reader, size_t* out);

/**
 * Writes whether no element is left into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_is_empty(const umilib_codec_asn1_der_DERReader* reader, bool* out);

/**
 * Fails with `TrailingData` if any element is left.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_finish(const umilib_codec_asn1_der_DERReader* reader);

/**
 * Writes the next element into `out` without moving.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_peek(const umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_der_DERElement* out);

/**
 * Writes whether an element is left into `out_has_tag` and its tag into `out_tag`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_peek_tag(const umilib_codec_asn1_der_DERReader* reader, bool* out_has_tag, umilib_codec_asn1_Tag* out_tag);

/**
 * Reads the next element of any type into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_element(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_der_DERElement* out);

/**
 * Reads the next element, which must have `tag`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_expected(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_Tag tag, umilib_codec_asn1_der_DERElement* out);

/**
 * Reads the next element if it has `tag`: writes whether it did into `out_found` and the element into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_optional(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_Tag tag, bool* out_found, umilib_codec_asn1_der_DERElement* out);

/**
 * Writes a new reader over the contents of `element`, one level deeper than `reader`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_nested(const umilib_codec_asn1_der_DERReader* reader, const umilib_codec_asn1_der_DERElement* element, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads a constructed element with `tag` and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_constructed(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_Tag tag, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads a SEQUENCE and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_sequence(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads a SET and writes a new reader over its contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_set(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads a SET OF, whose components must be sorted, and writes a new reader over them into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_set_of(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads `[number] EXPLICIT` and writes a new reader over the tagged contents into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_explicit(umilib_codec_asn1_der_DERReader* reader, uint32_t number, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads `[number] EXPLICIT` if it is next: writes whether it was into `out_found` and a new reader (or null) into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_optional_explicit(umilib_codec_asn1_der_DERReader* reader, uint32_t number, bool* out_found, umilib_codec_asn1_der_DERReader** out);

/**
 * Reads an INTEGER and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_integer(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads an ENUMERATED and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_enumerated(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads an OCTET STRING and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_octet_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads a UTF8String and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_utf8_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads a PrintableString and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_printable_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads an IA5String and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_ia5_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads a VisibleString and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_visible_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads a NumericString and writes a pointer to its contents into the input, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_numeric_string(umilib_codec_asn1_der_DERReader* reader, const uint8_t** out_data, size_t* out_length);

/**
 * Reads a BOOLEAN into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_boolean(umilib_codec_asn1_der_DERReader* reader, bool* out);

/**
 * Reads a UTCTime into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_utc_time(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads a GeneralizedTime into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_generalized_time(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads a BMPString and writes its text, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_bmp_string(umilib_codec_asn1_der_DERReader* reader, umilib_ffi_Buffer* out);

/**
 * Reads a UniversalString and writes its text, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_universal_string(umilib_codec_asn1_der_DERReader* reader, umilib_ffi_Buffer* out);

/**
 * Reads a NULL.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_null(umilib_codec_asn1_der_DERReader* reader);

/**
 * Reads a BIT STRING: writes its unused bits, a pointer to its octets in the input and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_bit_string(umilib_codec_asn1_der_DERReader* reader, uint8_t* out_unused_bits, const uint8_t** out_data, size_t* out_length);

/**
 * Reads an OBJECT IDENTIFIER into a new handle written into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_read_object_identifier(umilib_codec_asn1_der_DERReader* reader, umilib_codec_asn1_ObjectIdentifier** out);

/**
 * Reads length octets at byte `position` of `data`, rejecting non-minimal forms if `strict`. Writes whether
 * the length is definite, the length, and the position after the length octets.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_decode_length(const uint8_t* data, size_t length, size_t position, bool strict, bool* out_definite, size_t* out_length, size_t* out_next);

/**
 * Writes -1, 0 or 1 into `out` as encodings `a` and `b` order in a DER SET OF.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_compare_encodings(const uint8_t* a, size_t a_length, const uint8_t* b, size_t b_length, int8_t* out);

/**
 * Validates `length` bytes at `data` as one DER element, nested up to `maximum_depth` levels.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_validate(const uint8_t* data, size_t length, size_t maximum_depth);

/**
 * Releases a reader. Does nothing if `reader` is null.
 */
void umilib_codec_asn1_der_der_reader_free(umilib_codec_asn1_der_DERReader* reader);

/**
 * Checks the form of `element` and, for a universal primitive whose rules are known, its
 * contents, without looking inside constructed elements.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_reader_validate_shallow(const umilib_codec_asn1_der_DERElement* element);

/**
 * Writes the offset of the contents octets in the outermost input into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_content_position(const umilib_codec_asn1_der_DERElement* element, size_t* out);

/**
 * Reads the contents as a BOOLEAN into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_boolean(const umilib_codec_asn1_der_DERElement* element, bool* out);

/**
 * Reads the contents as a UTCTime into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_utc_time(const umilib_codec_asn1_der_DERElement* element, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads the contents as a GeneralizedTime into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_generalized_time(const umilib_codec_asn1_der_DERElement* element, umilib_codec_asn1_ASN1Time* out);

/**
 * Fails with `NonCanonical` unless the element is primitive; writes its contents.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_primitive(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Checks the contents as an INTEGER and writes them.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_integer(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as an OCTET STRING.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_octet_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a UTF8String.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_utf8_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a PrintableString.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_printable_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as an IA5String.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_ia5_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a VisibleString.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_visible_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a NumericString.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_numeric_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a TeletexString, whose octets are not interpreted.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_teletex_string(const umilib_codec_asn1_der_DERElement* element, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as a BMPString and writes its text, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_bmp_string(const umilib_codec_asn1_der_DERElement* element, umilib_ffi_Buffer* out);

/**
 * Reads the contents as a UniversalString and writes its text, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_universal_string(const umilib_codec_asn1_der_DERElement* element, umilib_ffi_Buffer* out);

/**
 * Checks that the contents are a NULL.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_null(const umilib_codec_asn1_der_DERElement* element);

/**
 * Reads the contents as a BIT STRING: writes the unused bits, a pointer to the octets and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_bit_string(const umilib_codec_asn1_der_DERElement* element, uint8_t* out_unused_bits, const uint8_t** out_data, size_t* out_length);

/**
 * Reads the contents as an OBJECT IDENTIFIER into a new handle written into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_element_as_object_identifier(const umilib_codec_asn1_der_DERElement* element, umilib_codec_asn1_ObjectIdentifier** out);

/**
 * Creates an empty writer.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_new(umilib_codec_asn1_der_DERWriter** out);

/**
 * Writes a pointer to the bytes written so far, valid until the writer is next used, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_as_bytes(const umilib_codec_asn1_der_DERWriter* writer, const uint8_t** out_data, size_t* out_length);

/**
 * Moves the bytes written into `out` and releases the writer. On failure the handle is not released.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_into_bytes(umilib_codec_asn1_der_DERWriter* writer, umilib_ffi_Buffer* out);

/**
 * Writes the length octets of `length` in the fewest octets into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_encode_length(size_t length, umilib_ffi_Buffer* out);

/**
 * Appends an element with `tag` and the `length` bytes at `data` as contents.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_element(umilib_codec_asn1_der_DERWriter* writer, umilib_codec_asn1_Tag tag, const uint8_t* data, size_t length);

/**
 * Appends an encoding produced elsewhere, which must be a valid DER element.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_raw(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* data, size_t length);

/**
 * Appends a constructed element with `tag` whose contents are the bytes written to `inner`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_constructed(umilib_codec_asn1_der_DERWriter* writer, umilib_codec_asn1_Tag tag, const umilib_codec_asn1_der_DERWriter* inner);

/**
 * Appends a SEQUENCE whose contents are the bytes written to `inner`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_sequence(umilib_codec_asn1_der_DERWriter* writer, const umilib_codec_asn1_der_DERWriter* inner);

/**
 * Appends a SET whose contents are the bytes written to `inner`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_set(umilib_codec_asn1_der_DERWriter* writer, const umilib_codec_asn1_der_DERWriter* inner);

/**
 * Appends a SET OF holding the elements written to `inner`, sorted by encoding.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_set_of(umilib_codec_asn1_der_DERWriter* writer, const umilib_codec_asn1_der_DERWriter* inner);

/**
 * Appends `[number] EXPLICIT` around the element written to `inner`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_explicit(umilib_codec_asn1_der_DERWriter* writer, uint32_t number, const umilib_codec_asn1_der_DERWriter* inner);

/**
 * Appends a BOOLEAN.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_boolean(umilib_codec_asn1_der_DERWriter* writer, bool value);

/**
 * Appends an INTEGER.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_integer_i128(umilib_codec_asn1_der_DERWriter* writer, umilib_ffi_I128 value);

/**
 * Appends an ENUMERATED.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_enumerated(umilib_codec_asn1_der_DERWriter* writer, umilib_ffi_I128 value);

/**
 * Appends a NULL.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_null(umilib_codec_asn1_der_DERWriter* writer);

/**
 * Appends the non-negative INTEGER with the big-endian magnitude at `data`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_integer_unsigned(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* data, size_t length);

/**
 * Appends an OCTET STRING.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_octet_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* data, size_t length);

/**
 * Appends a BIT STRING; fails if its unused bits are not zero.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_bit_string(umilib_codec_asn1_der_DERWriter* writer, uint8_t unused_bits, const uint8_t* data, size_t length);

/**
 * Appends an OBJECT IDENTIFIER.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_object_identifier(umilib_codec_asn1_der_DERWriter* writer, const umilib_codec_asn1_ObjectIdentifier* identifier);

/**
 * Appends a UTF8String holding the UTF-8 `text`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_utf8_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a PrintableString; fails if a character is not allowed.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_printable_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends an IA5String; fails for characters outside ASCII.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_ia5_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a VisibleString; fails if a character is not allowed.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_visible_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a NumericString; fails if a character is not a digit or space.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_numeric_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a BMPString; fails for characters above U+FFFF.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_bmp_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a UniversalString holding the UTF-8 `text`.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_universal_string(umilib_codec_asn1_der_DERWriter* writer, const uint8_t* text, size_t length);

/**
 * Appends a UTCTime; fails outside 1950 to 2049 or with a fraction.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_utc_time(umilib_codec_asn1_der_DERWriter* writer, umilib_codec_asn1_ASN1Time time);

/**
 * Appends a GeneralizedTime.
 */
const umilib_ffi_Status* umilib_codec_asn1_der_der_writer_write_generalized_time(umilib_codec_asn1_der_DERWriter* writer, umilib_codec_asn1_ASN1Time time);

/**
 * Releases a writer. Does nothing if `writer` is null.
 */
void umilib_codec_asn1_der_der_writer_free(umilib_codec_asn1_der_DERWriter* writer);

#ifdef __cplusplus
}
#endif

#endif
