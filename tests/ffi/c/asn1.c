/* Walks a DER certificate and builds DER through the generated headers. */
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

int main(void) {
    /* SEQUENCE { INTEGER 5, OBJECT IDENTIFIER 2.999.3, [0] EXPLICIT BOOLEAN TRUE } */
    umilib_codec_asn1_der_DERWriter* writer = NULL;
    umilib_codec_asn1_der_DERWriter* fields = NULL;
    umilib_codec_asn1_der_DERWriter* tagged = NULL;
    CHECK(umilib_codec_asn1_der_der_writer_new(&writer) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_new(&fields) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_new(&tagged) == NULL);
    umilib_ffi_I128 five = {0, 5};
    CHECK(umilib_codec_asn1_der_der_writer_write_integer_i128(fields, five) == NULL);
    umilib_codec_asn1_ObjectIdentifier* identifier = NULL;
    CHECK(umilib_codec_asn1_object_identifier_parse((const uint8_t*)"2.999.3", 7, &identifier) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_write_object_identifier(fields, identifier) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_write_boolean(tagged, true) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_write_explicit(fields, 0, tagged) == NULL);
    CHECK(umilib_codec_asn1_der_der_writer_write_sequence(writer, fields) == NULL);
    umilib_ffi_Buffer der = {0};
    CHECK(umilib_codec_asn1_der_der_writer_into_bytes(writer, &der) == NULL);
    const uint8_t expected[] = {0x30, 0x0D, 0x02, 0x01, 0x05, 0x06, 0x03, 0x88, 0x37, 0x03, 0xA0, 0x03, 0x01, 0x01, 0xFF};
    CHECK(der.length == sizeof expected && memcmp(der.data, expected, sizeof expected) == 0);

    umilib_codec_asn1_der_DERReader* reader = NULL;
    umilib_codec_asn1_der_DERReader* sequence = NULL;
    umilib_codec_asn1_der_DERReader* inner = NULL;
    CHECK(umilib_codec_asn1_der_der_reader_new(der.data, der.length, &reader) == NULL);
    CHECK(umilib_codec_asn1_der_der_reader_read_sequence(reader, &sequence) == NULL);
    const uint8_t* integer = NULL;
    size_t integer_length = 0;
    CHECK(umilib_codec_asn1_der_der_reader_read_integer(sequence, &integer, &integer_length) == NULL);
    CHECK(integer_length == 1 && integer[0] == 5);
    umilib_codec_asn1_ObjectIdentifier* read_identifier = NULL;
    CHECK(umilib_codec_asn1_der_der_reader_read_object_identifier(sequence, &read_identifier) == NULL);
    bool equal = false;
    CHECK(umilib_codec_asn1_object_identifier_equal(identifier, read_identifier, &equal) == NULL && equal);
    CHECK(umilib_codec_asn1_der_der_reader_read_explicit(sequence, 0, &inner) == NULL);
    bool value = false;
    CHECK(umilib_codec_asn1_der_der_reader_read_boolean(inner, &value) == NULL && value);
    CHECK(umilib_codec_asn1_der_der_reader_finish(sequence) == NULL);
    const umilib_ffi_Status* status = umilib_codec_asn1_der_der_reader_read_null(sequence);
    CHECK(status != NULL && strcmp(status->domain, "codec.asn1") == 0);

    umilib_codec_asn1_der_der_reader_free(inner);
    umilib_codec_asn1_der_der_reader_free(sequence);
    umilib_codec_asn1_der_der_reader_free(reader);
    umilib_codec_asn1_object_identifier_free(read_identifier);
    umilib_codec_asn1_object_identifier_free(identifier);
    umilib_codec_asn1_der_der_writer_free(tagged);
    umilib_codec_asn1_der_der_writer_free(fields);
    umilib_ffi_buffer_free(&der);
    printf("asn1.c: ok\n");
    return 0;
}
