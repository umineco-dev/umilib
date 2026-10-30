/* Exercises the bytes C ABI through the generated headers. */
#include <stdio.h>
#include <string.h>

#include "umilib.h"

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                       \
        }                                                                   \
    } while (0)

int main(void) {
    const uint8_t data[] = {0x00, 0x02, 0xAB, 0xCD, 0x01, 0x00, 0x00};
    umilib_bytes_Reader* reader = NULL;
    CHECK(umilib_bytes_reader_new(data, sizeof data, &reader) == NULL);
    uint16_t length = 0;
    CHECK(umilib_bytes_reader_read_be_u16(reader, &length) == NULL && length == 2);
    uint16_t value = 0;
    CHECK(umilib_bytes_reader_read_le_u16(reader, &value) == NULL && value == 0xCDAB);
    uint32_t sized = 0;
    CHECK(umilib_bytes_reader_read_be_sized_u32(reader, 3, &sized) == NULL && sized == 0x010000);
    uint8_t byte = 0;
    const umilib_ffi_Status* status = umilib_bytes_reader_read_u8(reader, &byte);
    CHECK(status != NULL && strcmp(status->domain, "bytes") == 0 && strcmp(status->name, "UnexpectedEnd") == 0);
    umilib_bytes_reader_free(reader);

    umilib_bytes_Buffer* buffer = NULL;
    CHECK(umilib_bytes_buffer_with_limit(4, &buffer) == NULL);
    CHECK(umilib_bytes_buffer_write_be_u32(buffer, 0x01020304) == NULL);
    CHECK(umilib_bytes_buffer_write_u8(buffer, 5) != NULL);
    umilib_ffi_U128 big = {0, 1};
    CHECK(umilib_bytes_buffer_write_be_u128(buffer, big) != NULL);
    umilib_ffi_Buffer bytes = {0};
    CHECK(umilib_bytes_buffer_into_vec(buffer, &bytes) == NULL);
    CHECK(bytes.length == 4 && bytes.data[0] == 1 && bytes.data[3] == 4);
    umilib_ffi_buffer_free(&bytes);
    CHECK(bytes.data == NULL && bytes.length == 0);

    CHECK(strlen(umilib_version()) > 0);
    umilib_ffi_Buffer manifest = {0};
    CHECK(umilib_ffi_manifest(&manifest) == NULL && manifest.length > 0 && manifest.data[0] == '{');
    umilib_ffi_buffer_free(&manifest);
    printf("bytes.c: ok\n");
    return 0;
}
