/* Prepares strings with SASLprep (RFC 4013 section 3 examples) and LDAPPrep (RFC 4518), and normalizes them in
   the forms of Unicode 3.2, through the generated headers. */
#include <stdio.h>
#include <string.h>

#include "umilib.h"

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        if (!(condition)) {                                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition);      \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

#define TEXT(text) (const uint8_t*)(text), strlen(text)
#define EQUALS(buffer, text) ((buffer).length == strlen(text) && memcmp((buffer).data, (text), (buffer).length) == 0)

int main(void) {
    umilib_codec_stringprep_StringPrepProfile* saslprep = NULL;
    CHECK(umilib_codec_stringprep_string_prep_profile_saslprep(&saslprep) == NULL);
    umilib_ffi_Buffer out = {0};
    /* SOFT HYPHEN mapped to nothing; U+2168 ROMAN NUMERAL NINE by NFKC; stored strings (1). */
    CHECK(umilib_codec_stringprep_string_prep_profile_prepare(saslprep, TEXT("I\xc2\xadX"), 1, &out) == NULL && EQUALS(out, "IX"));
    umilib_ffi_buffer_free(&out);
    CHECK(umilib_codec_stringprep_string_prep_profile_prepare(saslprep, TEXT("\xe2\x85\xa8"), 1, &out) == NULL && EQUALS(out, "IX"));
    umilib_ffi_buffer_free(&out);
    const umilib_ffi_Status* status = umilib_codec_stringprep_string_prep_profile_prepare(saslprep, TEXT("\x07"), 1, &out);
    CHECK(status != NULL && strcmp(status->name, "Prohibited") == 0);
    status = umilib_codec_stringprep_string_prep_profile_prepare(saslprep, TEXT("\xd8\xa7" "1"), 1, &out);
    CHECK(status != NULL && strcmp(status->name, "Bidi") == 0);
    status = umilib_codec_stringprep_string_prep_profile_prepare(saslprep, TEXT("user"), 2, &out);
    CHECK(status != NULL && strcmp(status->name, "InvalidArgument") == 0);

    /* LDAPPrep for caseIgnoreMatch (0) of a value (0): one space around, two between words. */
    CHECK(umilib_codec_stringprep_ldap_prep_prepare(TEXT("  Foo   Bar "), 0, 0, &out) == NULL && EQUALS(out, " foo  bar "));
    umilib_ffi_buffer_free(&out);
    /* NFC (1) composes, NFD (0) decomposes. */
    CHECK(umilib_codec_stringprep_normalization_form_normalize(1, TEXT("e\xcc\x81"), &out) == NULL && EQUALS(out, "\xc3\xa9"));
    umilib_ffi_buffer_free(&out);
    CHECK(umilib_codec_stringprep_normalization_form_normalize(0, TEXT("\xc3\xa9"), &out) == NULL && EQUALS(out, "e\xcc\x81"));
    umilib_ffi_buffer_free(&out);
    uint8_t combining_class = 0;
    CHECK(umilib_codec_stringprep_normalization_form_combining_class(0x0301, &combining_class) == NULL && combining_class == 230);
    CHECK(umilib_codec_stringprep_normalization_form_combining_class(0xD800, &combining_class) != NULL);
    /* Table B.2 (2) maps U+00DF to "ss"; C.1.2 (5) holds U+00A0. */
    bool mapped = false;
    CHECK(umilib_codec_stringprep_string_prep_table_mapping(2, 0xDF, &mapped, &out) == NULL && mapped && EQUALS(out, "ss"));
    umilib_ffi_buffer_free(&out);
    bool contains = false;
    CHECK(umilib_codec_stringprep_string_prep_table_contains(5, 0xA0, &contains) == NULL && contains);
    CHECK(umilib_codec_stringprep_string_prep_table_contains(17, 0xA0, &contains) != NULL);

    umilib_codec_stringprep_string_prep_profile_free(saslprep);
    umilib_codec_stringprep_string_prep_profile_free(NULL);
    printf("stringprep: ok\n");
    return 0;
}
