/* Hash functions, HMAC and a DRBG through the generated headers, against published test vectors. */
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

static int fails_with(const umilib_ffi_Status* status, const char* domain, const char* name) {
    return status != NULL && strcmp(status->domain, domain) == 0 && strcmp(status->name, name) == 0;
}

int main(void) {
    /* FIPS 180-4: SHA-256("abc"), streamed in two pieces. */
    static const uint8_t sha256_abc[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                           0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                           0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    umilib_hash_sha_v2_SHA256* sha256 = NULL;
    uint8_t digest[32];
    CHECK(umilib_hash_sha_v2_sha256_new(&sha256) == NULL);
    CHECK(umilib_hash_sha_v2_sha256_update(sha256, (const uint8_t*)"a", 1) == NULL);
    CHECK(umilib_hash_sha_v2_sha256_update(sha256, (const uint8_t*)"bc", 2) == NULL);
    CHECK(fails_with(umilib_hash_sha_v2_sha256_finalize(sha256, digest, 31), "hash", "OutputLength"));
    CHECK(umilib_hash_sha_v2_sha256_finalize(sha256, digest, sizeof digest) == NULL);
    CHECK(memcmp(digest, sha256_abc, 32) == 0);

    /* RFC 4231 test case 2: HMAC-SHA-256 with the key "Jefe". */
    static const uint8_t hmac_expected[32] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
                                              0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
                                              0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
    const char* hash = "umilib_hash_sha_v2_SHA256";
    const char* data = "what do ya want for nothing?";
    umilib_crypto_hmac_HMAC* hmac = NULL;
    bool valid = false;
    CHECK(umilib_crypto_hmac_hmac_new((const uint8_t*)hash, strlen(hash), (const uint8_t*)"Jefe", 4, &hmac) == NULL);
    CHECK(umilib_crypto_hmac_hmac_update(hmac, (const uint8_t*)data, strlen(data)) == NULL);
    CHECK(umilib_crypto_hmac_hmac_verify(hmac, hmac_expected, sizeof hmac_expected, &valid) == NULL);
    CHECK(valid);

    /* The check value of CRC-32/ISO-HDLC, a 128-bit value in two halves. */
    umilib_hash_crc_CRCTable* table = NULL;
    umilib_ffi_U128 check = {0, 0};
    const char* name = "CRC-32/ISO-HDLC";
    CHECK(umilib_hash_crc_crc_catalogue_find((const uint8_t*)name, strlen(name), &table) == NULL);
    CHECK(umilib_hash_crc_crc_checksum(table, (const uint8_t*)"123456789", 9, &check) == NULL);
    CHECK(check.high == 0 && check.low == 0xCBF43926u);
    umilib_hash_crc_crc_table_free(table);

    /* RFC 7693 appendix B: BLAKE2s-256("abc") through a parameter structure. */
    static const uint8_t blake2s_abc[4] = {0x50, 0x8c, 0x5e, 0x8c};
    umilib_hash_blake_v2_BLAKE2sParameters parameters = umilib_hash_blake_v2_blake2s_parameters_new(32);
    umilib_hash_blake_v2_BLAKE2s* blake2s = NULL;
    CHECK(parameters.fanout == 1 && parameters.depth == 1 && parameters.salt[7] == 0);
    CHECK(umilib_hash_blake_v2_blake2s_with_parameters(&parameters, NULL, 0, &blake2s) == NULL);
    CHECK(umilib_hash_blake_v2_blake2s_update(blake2s, (const uint8_t*)"abc", 3) == NULL);
    CHECK(umilib_hash_blake_v2_blake2s_finalize_into(blake2s, digest, 32) == NULL);
    CHECK(memcmp(digest, blake2s_abc, 4) == 0);
    umilib_hash_blake_v2_blake2s_free(blake2s);

    /* A DRBG refuses entropy shorter than its security strength. */
    uint8_t entropy[32] = {0};
    uint8_t nonce[16] = {0};
    umilib_crypto_random_HMACDRBG* drbg = NULL;
    CHECK(fails_with(umilib_crypto_random_hmac_drbg_new((const uint8_t*)hash, strlen(hash), entropy, 31, NULL, 0, NULL, 0, &drbg),
                     "crypto.random", "EntropyLength"));
    CHECK(fails_with(umilib_crypto_random_hmac_drbg_new((const uint8_t*)hash, strlen(hash), entropy, 32, NULL, 0, NULL, 0, &drbg),
                     "crypto.random", "NonceLength"));
    CHECK(umilib_crypto_random_hmac_drbg_new((const uint8_t*)hash, strlen(hash), entropy, 32, nonce, 16, NULL, 0, &drbg) == NULL);
    CHECK(umilib_crypto_random_hmac_drbg_fill(drbg, digest, sizeof digest) == NULL);
    umilib_crypto_random_hmac_drbg_free(drbg);
    puts("hash: ok");
    return 0;
}
