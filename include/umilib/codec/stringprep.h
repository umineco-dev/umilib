/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_STRINGPREP_H
#define UMILIB_CODEC_STRINGPREP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A profile of stringprep (RFC 3454).
 */
typedef struct umilib_codec_stringprep_StringPrepProfile umilib_codec_stringprep_StringPrepProfile;

/**
 * Writes `text` (`length` bytes) in the normalization form `form` of Unicode 3.2 into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_normalization_form_normalize(uint8_t form, const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the canonical combining class of the code point `character` in Unicode 3.2 into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_normalization_form_combining_class(uint32_t character, uint8_t* out);

/**
 * Writes whether the table `table` has the code point `character` into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_table_contains(uint8_t table, uint32_t character, bool* out);

/**
 * Writes whether the mapping table `table` (B.1, B.2 or B.3) maps the code point `character`
 * into `out_mapped` and, if it does, the UTF-8 text it maps it to into `out` (empty otherwise).
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_table_mapping(uint8_t table, uint32_t character, bool* out_mapped, umilib_ffi_Buffer* out);

/**
 * Writes the SASLprep profile (RFC 4013) into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_profile_saslprep(umilib_codec_stringprep_StringPrepProfile** out);

/**
 * Writes the "trace" profile of SASL ANONYMOUS (RFC 4505 §3) into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_profile_trace(umilib_codec_stringprep_StringPrepProfile** out);

/**
 * Writes `text` (`length` bytes) prepared by `profile` into `out`; `unassigned` says whether
 * unassigned code points are allowed (a query) or prohibited (a stored string).
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_profile_prepare(const umilib_codec_stringprep_StringPrepProfile* profile, const uint8_t* text, size_t length, uint8_t unassigned, umilib_ffi_Buffer* out);

/**
 * Succeeds if `text` (`length` bytes) follows the rules of bidirectional text of RFC 3454 section 6.
 */
const umilib_ffi_Status* umilib_codec_stringprep_string_prep_profile_check_bidi(const uint8_t* text, size_t length);

/**
 * Releases a profile. Does nothing if `profile` is null.
 */
void umilib_codec_stringprep_string_prep_profile_free(umilib_codec_stringprep_StringPrepProfile* profile);

/**
 * Writes `text` (`length` bytes) prepared by LDAPPrep (RFC 4518) for the matching rule
 * `matching` as the kind of string `kind` into `out`.
 */
const umilib_ffi_Status* umilib_codec_stringprep_ldap_prep_prepare(const uint8_t* text, size_t length, uint8_t matching, uint8_t kind, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
