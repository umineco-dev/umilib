/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_ASN1_H
#define UMILIB_CODEC_ASN1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An identifier: tag_class (0 universal, 1 application, 2 context-specific, 3 private), form and number.
 */
typedef struct umilib_codec_asn1_Tag {
    uint8_t tag_class;
    bool constructed;
    uint32_t number;
} umilib_codec_asn1_Tag;

/**
 * A moment in UTC.
 */
typedef struct umilib_codec_asn1_ASN1Time {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint32_t nanosecond;
} umilib_codec_asn1_ASN1Time;

/**
 * An OBJECT IDENTIFIER owning its contents octets.
 */
typedef struct umilib_codec_asn1_ObjectIdentifier umilib_codec_asn1_ObjectIdentifier;

/**
 * Writes whether the bytes are PrintableString characters into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_is_printable(const uint8_t* data, size_t length, bool* out);

/**
 * Writes whether the bytes are IA5String (ASCII) characters into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_is_ia5(const uint8_t* data, size_t length, bool* out);

/**
 * Writes whether the bytes are VisibleString characters into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_is_visible(const uint8_t* data, size_t length, bool* out);

/**
 * Writes whether the bytes are NumericString characters into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_is_numeric(const uint8_t* data, size_t length, bool* out);

/**
 * Reads the identifier octets at byte `position` of `data`; writes the tag into `out`
 * and the position after them into `out_next`.
 */
const umilib_ffi_Status* umilib_codec_asn1_tag_decode(const uint8_t* data, size_t length, size_t position, umilib_codec_asn1_Tag* out, size_t* out_next);

/**
 * Writes the identifier octets of `tag` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_tag_encode(umilib_codec_asn1_Tag tag, umilib_ffi_Buffer* out);

/**
 * Creates an object identifier from contents octets, which are validated.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_new(const uint8_t* data, size_t length, umilib_codec_asn1_ObjectIdentifier** out);

/**
 * Creates an object identifier from `count` arcs.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_from_arcs(const umilib_ffi_U128* arcs, size_t count, umilib_codec_asn1_ObjectIdentifier** out);

/**
 * Parses dotted decimal UTF-8 `text` such as `1.2.840.113549`.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_parse(const uint8_t* text, size_t length, umilib_codec_asn1_ObjectIdentifier** out);

/**
 * Releases an object identifier. Does nothing if `identifier` is null.
 */
void umilib_codec_asn1_object_identifier_free(umilib_codec_asn1_ObjectIdentifier* identifier);

/**
 * Writes a pointer to the contents octets, valid until the identifier is released, and their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_as_bytes(const umilib_codec_asn1_ObjectIdentifier* identifier, const uint8_t** out_data, size_t* out_length);

/**
 * Writes the dotted decimal form into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_to_string(const umilib_codec_asn1_ObjectIdentifier* identifier, umilib_ffi_Buffer* out);

/**
 * Writes the number of arcs into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_arc_count(const umilib_codec_asn1_ObjectIdentifier* identifier, size_t* out);

/**
 * Writes the arc at `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_arcs(const umilib_codec_asn1_ObjectIdentifier* identifier, size_t index, umilib_ffi_U128* out);

/**
 * Writes whether two identifiers are equal into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_equal(const umilib_codec_asn1_ObjectIdentifier* a, const umilib_codec_asn1_ObjectIdentifier* b, bool* out);

/**
 * Fails with `InvalidContent` unless the bytes are valid INTEGER contents (the fewest octets).
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_new(const uint8_t* data, size_t length);

/**
 * Writes the value of INTEGER contents into `out`; fails with `OutOfRange` if it does not fit.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_as_i128(const uint8_t* data, size_t length, umilib_ffi_I128* out);

/**
 * Writes the value of non-negative INTEGER contents into `out`; fails with `OutOfRange` if it does not fit.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_as_u128(const uint8_t* data, size_t length, umilib_ffi_U128* out);

/**
 * Writes the magnitude of non-negative INTEGER contents (without the sign octet) as a
 * pointer into `data` and a length; fails with `OutOfRange` for negative integers.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_magnitude(const uint8_t* data, size_t length, const uint8_t** out_data, size_t* out_length);

/**
 * Writes the INTEGER contents of `value` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_encode_i128(umilib_ffi_I128 value, umilib_ffi_Buffer* out);

/**
 * Writes the INTEGER contents of the non-negative integer with the big-endian `magnitude` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_integer_encode_unsigned(const uint8_t* magnitude, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads BIT STRING contents: writes the unused bits into `out_unused_bits` and a pointer
 * into `data` to the octets, with their length.
 */
const umilib_ffi_Status* umilib_codec_asn1_bit_string_decode_content(const uint8_t* data, size_t length, uint8_t* out_unused_bits, const uint8_t** out_data, size_t* out_length);

/**
 * Fails with `InvalidContent` unless `unused_bits` is 0 to 7, and 0 when `length` is 0.
 */
const umilib_ffi_Status* umilib_codec_asn1_bit_string_new(uint8_t unused_bits, const uint8_t* data, size_t length);

/**
 * Writes whether the unused bits of the bit string are zero, as DER requires, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_bit_string_has_zero_padding(uint8_t unused_bits, const uint8_t* data, size_t length, bool* out);

/**
 * Writes the text of BMPString contents, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_decode_bmp(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the text of UniversalString contents, as UTF-8, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_decode_universal(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the BMPString contents holding the UTF-8 `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_encode_bmp(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UniversalString contents holding the UTF-8 `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_string_encode_universal(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Creates a time, checking the calendar and the ranges of every field.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_new(uint16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minute, uint8_t second, uint32_t nanosecond, umilib_codec_asn1_ASN1Time* out);

/**
 * Returns whether `year` is a leap year.
 */
bool umilib_codec_asn1_asn1_time_is_leap_year(uint16_t year);

/**
 * Returns the number of days of `month` (1 to 12) in `year`, or 0 for other months.
 */
uint8_t umilib_codec_asn1_asn1_time_days_in_month(uint16_t year, uint8_t month);

/**
 * Writes the seconds since 1970-01-01T00:00:00Z, ignoring the fraction, into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_to_unix_seconds(umilib_codec_asn1_ASN1Time time, int64_t* out);

/**
 * Writes the time `seconds` after 1970-01-01T00:00:00Z into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_from_unix_seconds(int64_t seconds, umilib_codec_asn1_ASN1Time* out);

/**
 * Writes -1, 0 or 1 into `out` as `a` comes before, with or after `b` in the canonical
 * order of X.680 section 8.6 (class, then number; the form is ignored).
 */
const umilib_ffi_Status* umilib_codec_asn1_tag_compare_order(umilib_codec_asn1_Tag a, umilib_codec_asn1_Tag b, int8_t* out);

/**
 * Checks `length` bytes at `data` as a list of subidentifiers (the contents of an OBJECT
 * IDENTIFIER or a RELATIVE-OID): at least one, each minimal and within 128 bits.
 */
const umilib_ffi_Status* umilib_codec_asn1_object_identifier_validate_subidentifiers(const uint8_t* data, size_t length);

/**
 * Writes the DER contents of the REAL whose BER contents are the `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_real_to_der(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Fails unless the `length` bytes at `data` are the DER contents of a REAL.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_real_validate_der(const uint8_t* data, size_t length);

/**
 * Writes the DER contents of the GeneralizedTime whose BER contents (with a zone) are the
 * `length` bytes at `data` into `out`, keeping every digit of the fraction.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_generalized_time_ber_to_der(const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads UTCTime contents in the DER form `YYMMDDhhmmssZ`.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_decode_utc_time(const uint8_t* data, size_t length, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads GeneralizedTime contents in the DER form.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_decode_generalized_time(const uint8_t* data, size_t length, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads UTCTime contents in any BER form with a zone, converted to UTC.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_decode_utc_time_ber(const uint8_t* data, size_t length, umilib_codec_asn1_ASN1Time* out);

/**
 * Reads GeneralizedTime contents in any BER form with a zone, converted to UTC.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_decode_generalized_time_ber(const uint8_t* data, size_t length, umilib_codec_asn1_ASN1Time* out);

/**
 * Writes UTCTime contents; fails outside 1950 to 2049 or with a fraction.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_encode_utc_time(umilib_codec_asn1_ASN1Time time, umilib_ffi_Buffer* out);

/**
 * Writes GeneralizedTime contents in the DER form.
 */
const umilib_ffi_Status* umilib_codec_asn1_asn1_time_encode_generalized_time(umilib_codec_asn1_ASN1Time time, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
