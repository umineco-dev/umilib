/* Block ciphers, modes, MACs and key derivation through the generated headers, against published test vectors. */
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
    const char* aes128 = "umilib_crypto_aes_AES128";

    /* FIPS 197 appendix C.1: AES-128. */
    static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t ciphertext[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                           0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    uint8_t block[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    umilib_crypto_aes_AES128* aes = NULL;
    CHECK(umilib_crypto_aes_aes128_new(key, sizeof key, &aes) == NULL);
    CHECK(umilib_crypto_aes_aes128_encrypt_blocks(aes, block, sizeof block) == NULL);
    CHECK(memcmp(block, ciphertext, 16) == 0);
    CHECK(fails_with(umilib_crypto_aes_aes128_encrypt_blocks(aes, block, 15), "crypto", "InputLength"));
    umilib_crypto_aes_aes128_free(aes);

    /* The same block through ECB, with the cipher chosen by name. */
    umilib_crypto_mode_ecb_ECB* ecb = NULL;
    CHECK(umilib_crypto_mode_ecb_ecb_new((const uint8_t*)aes128, strlen(aes128), key, sizeof key, &ecb) == NULL);
    CHECK(umilib_crypto_mode_ecb_ecb_decrypt(ecb, block, sizeof block) == NULL);
    CHECK(block[0] == 0x00 && block[15] == 0xff);
    umilib_crypto_mode_ecb_ecb_free(ecb);
    CHECK(fails_with(umilib_crypto_mode_ecb_ecb_new((const uint8_t*)"AES128", 6, key, sizeof key, &ecb), "ffi",
                     "InvalidArgument"));

    /* The GCM specification, test case 2: the zero key, IV and block. */
    static const uint8_t zeros[16] = {0};
    static const uint8_t gcm_ciphertext[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                               0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const uint8_t gcm_tag[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    umilib_crypto_mode_gcm_GCM* gcm = NULL;
    uint8_t buffer[16] = {0};
    uint8_t tag[16];
    CHECK(umilib_crypto_mode_gcm_gcm_new((const uint8_t*)aes128, strlen(aes128), zeros, 16, 16, &gcm) == NULL);
    CHECK(umilib_crypto_mode_gcm_gcm_encrypt_in_place(gcm, zeros, 12, NULL, 0, buffer, 16, tag, 16) == NULL);
    CHECK(memcmp(buffer, gcm_ciphertext, 16) == 0 && memcmp(tag, gcm_tag, 16) == 0);
    tag[0] ^= 1;
    CHECK(fails_with(umilib_crypto_mode_gcm_gcm_decrypt_in_place(gcm, zeros, 12, NULL, 0, buffer, 16, tag, 16), "crypto",
                     "AuthenticationFailed"));
    CHECK(memcmp(buffer, gcm_ciphertext, 16) == 0);
    tag[0] ^= 1;
    CHECK(umilib_crypto_mode_gcm_gcm_decrypt_in_place(gcm, zeros, 12, NULL, 0, buffer, 16, tag, 16) == NULL);
    CHECK(memcmp(buffer, zeros, 16) == 0);
    umilib_crypto_mode_gcm_gcm_free(gcm);

    /* RFC 4493 section 4: the CMAC of the empty message. */
    static const uint8_t cmac_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t cmac_empty[16] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                                           0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    uint8_t mac[16];
    CHECK(umilib_crypto_cmac_cmac_mac((const uint8_t*)aes128, strlen(aes128), cmac_key, 16, NULL, 0, mac, 16) == NULL);
    CHECK(memcmp(mac, cmac_empty, 16) == 0);

    /* RFC 8439 section 2.5.2: Poly1305. */
    static const uint8_t poly1305_key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52,
                                             0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d,
                                             0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
    static const uint8_t poly1305_tag[16] = {0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                                             0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};
    const char* forum = "Cryptographic Forum Research Group";
    umilib_crypto_poly1305_Poly1305* poly1305 = NULL;
    bool valid = false;
    CHECK(umilib_crypto_poly1305_poly1305_new(poly1305_key, 32, &poly1305) == NULL);
    CHECK(umilib_crypto_poly1305_poly1305_update(poly1305, (const uint8_t*)forum, strlen(forum)) == NULL);
    CHECK(umilib_crypto_poly1305_poly1305_verify(poly1305, poly1305_tag, 16, &valid) == NULL);
    CHECK(valid);

    /* RFC 5869 appendix A.1: HKDF-SHA-256. */
    static const uint8_t okm[42] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
                                    0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
                                    0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
                                    0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t derived[42];
    size_t index;
    memset(ikm, 0x0b, sizeof ikm);
    for (index = 0; index < sizeof salt; index++) {
        salt[index] = (uint8_t)index;
    }
    for (index = 0; index < sizeof info; index++) {
        info[index] = (uint8_t)(0xf0 + index);
    }
    const char* sha256 = "umilib_hash_sha_v2_SHA256";
    CHECK(umilib_crypto_hkdf_hkdf_derive((const uint8_t*)sha256, strlen(sha256), salt, sizeof salt, ikm, sizeof ikm,
                                         info, sizeof info, derived, sizeof derived) == NULL);
    CHECK(memcmp(derived, okm, sizeof okm) == 0);

    /* RFC 6070: PBKDF2-HMAC-SHA1 with one iteration. */
    static const uint8_t dk[20] = {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9,
                                   0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6};
    const char* sha1 = "umilib_hash_sha_v1_SHA1";
    uint8_t pbkdf2[20];
    CHECK(umilib_crypto_pbkdf2_pbkdf2_derive((const uint8_t*)sha1, strlen(sha1), (const uint8_t*)"password", 8,
                                             (const uint8_t*)"salt", 4, 1, pbkdf2, sizeof pbkdf2) == NULL);
    CHECK(memcmp(pbkdf2, dk, sizeof dk) == 0);
    CHECK(fails_with(umilib_crypto_pbkdf2_pbkdf2_derive((const uint8_t*)sha1, strlen(sha1), NULL, 0, NULL, 0, 0, pbkdf2,
                                                        sizeof pbkdf2),
                     "crypto", "InvalidParameter"));

    /* IEEE 1619 section 5.1: the tweak of a data unit is its little-endian number. */
    uint8_t tweak[16];
    umilib_ffi_U128 unit = {0, 0x0102};
    CHECK(umilib_crypto_mode_xts_xts_tweak_of(unit, tweak, sizeof tweak) == NULL);
    CHECK(tweak[0] == 0x02 && tweak[1] == 0x01 && tweak[2] == 0x00 && tweak[15] == 0x00);

    puts("crypto: ok");
    return 0;
}
