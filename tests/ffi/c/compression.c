/* Streams data through a compressor and a decompressor of the generated headers. */
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
    uint8_t data[5000];
    for (size_t index = 0; index < sizeof data; index++) {
        data[index] = (uint8_t)("abracadabra"[index % 11] + index / 1000);
    }

    /* Compresses in pieces of 100 bytes into outputs of 64 bytes. */
    umilib_codec_huffman_canonical_CanonicalHuffmanCompressor* compressor = NULL;
    CHECK(umilib_codec_huffman_canonical_canonical_huffman_compressor_new(1000, &compressor) == NULL);
    uint8_t stream[8000];
    size_t stream_length = 0, position = 0;
    for (;;) {
        size_t end = position + 100 < sizeof data ? position + 100 : sizeof data;
        uint8_t flush = end == sizeof data ? 2 : 0;
        umilib_codec_Progress progress = {0};
        uint8_t output[64];
        CHECK(umilib_codec_huffman_canonical_canonical_huffman_compressor_compress(
                  compressor, data + position, end - position, output, sizeof output, flush, &progress) == NULL);
        position += progress.consumed;
        CHECK(stream_length + progress.produced <= sizeof stream);
        memcpy(stream + stream_length, output, progress.produced);
        stream_length += progress.produced;
        if (progress.finished) {
            break;
        }
    }
    CHECK(position == sizeof data && stream_length < sizeof data);

    /* Decompresses into outputs of 7 bytes. */
    umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor* decompressor = NULL;
    CHECK(umilib_codec_huffman_canonical_canonical_huffman_decompressor_new(&decompressor) == NULL);
    uint8_t recovered[sizeof data];
    size_t recovered_length = 0;
    position = 0;
    for (;;) {
        umilib_codec_Progress progress = {0};
        size_t room = sizeof recovered - recovered_length < 7 ? sizeof recovered - recovered_length : 7;
        CHECK(umilib_codec_huffman_canonical_canonical_huffman_decompressor_decompress(
                  decompressor, stream + position, stream_length - position, recovered + recovered_length, room,
                  &progress) == NULL);
        position += progress.consumed;
        recovered_length += progress.produced;
        if (progress.finished) {
            break;
        }
        CHECK(progress.consumed + progress.produced > 0);
    }
    CHECK(position == stream_length && recovered_length == sizeof data && memcmp(recovered, data, sizeof data) == 0);

    /* The whole stream at once, and its limit. */
    umilib_ffi_Buffer whole = {0};
    CHECK(umilib_codec_huffman_canonical_canonical_huffman_decompressor_reset(decompressor) == NULL);
    CHECK(umilib_codec_huffman_canonical_canonical_huffman_decompressor_decompress_to_vec(
              decompressor, stream, stream_length, sizeof data, &whole) == NULL);
    CHECK(whole.length == sizeof data && memcmp(whole.data, data, sizeof data) == 0);
    umilib_ffi_buffer_free(&whole);
    CHECK(umilib_codec_huffman_canonical_canonical_huffman_decompressor_reset(decompressor) == NULL);
    const umilib_ffi_Status* status = umilib_codec_huffman_canonical_canonical_huffman_decompressor_decompress_to_vec(
        decompressor, stream, stream_length, 10, &whole);
    CHECK(status != NULL && strcmp(status->name, "LimitExceeded") == 0);

    umilib_codec_huffman_canonical_canonical_huffman_compressor_free(compressor);
    umilib_codec_huffman_canonical_canonical_huffman_decompressor_free(decompressor);

    /* A Brotli stream of the defaults, whole, and its decompression. */
    uint32_t level = 0, window_bits = 0, maximum_window_bits = 0;
    CHECK(umilib_codec_brotli_brotli_config_defaults(&level, &window_bits, &maximum_window_bits) == NULL);
    umilib_codec_brotli_BrotliCompressor* brotli = NULL;
    CHECK(umilib_codec_brotli_brotli_compressor_new(level, window_bits, &brotli) == NULL);
    umilib_ffi_Buffer compressed = {0};
    CHECK(umilib_codec_brotli_brotli_compressor_compress_to_vec(brotli, data, sizeof data, &compressed) == NULL);
    CHECK(compressed.length > 0 && compressed.length < sizeof data);
    umilib_codec_brotli_BrotliDecompressor* unbrotli = NULL;
    CHECK(umilib_codec_brotli_brotli_decompressor_new(maximum_window_bits, &unbrotli) == NULL);
    CHECK(umilib_codec_brotli_brotli_decompressor_decompress_to_vec(
              unbrotli, compressed.data, compressed.length, sizeof data, &whole) == NULL);
    CHECK(whole.length == sizeof data && memcmp(whole.data, data, sizeof data) == 0);
    umilib_ffi_buffer_free(&whole);
    umilib_ffi_buffer_free(&compressed);
    umilib_codec_brotli_brotli_compressor_free(brotli);
    umilib_codec_brotli_brotli_decompressor_free(unbrotli);

    /* A .xz Stream with the x86 filter and CRC32, and its decompression. */
    const umilib_codec_xz_XZFilterFlags filters[1] = {{0x04, 0}};
    umilib_codec_xz_XZCompressor* xz = NULL;
    CHECK(umilib_codec_xz_xz_compressor_new(6, 0, 0x01, 0, filters, 1, &xz) == NULL);
    CHECK(umilib_codec_xz_xz_compressor_compress_to_vec(xz, data, sizeof data, &compressed) == NULL);
    umilib_codec_xz_XZDecompressor* unxz = NULL;
    CHECK(umilib_codec_xz_xz_decompressor_new(1 << 26, true, &unxz) == NULL);
    CHECK(umilib_codec_xz_xz_decompressor_decompress_to_vec(unxz, compressed.data, compressed.length, sizeof data, &whole) ==
          NULL);
    CHECK(whole.length == sizeof data && memcmp(whole.data, data, sizeof data) == 0);
    umilib_ffi_buffer_free(&whole);
    umilib_ffi_buffer_free(&compressed);
    umilib_codec_xz_xz_compressor_free(xz);
    umilib_codec_xz_xz_decompressor_free(unxz);
    printf("compression.c: ok\n");
    return 0;
}
