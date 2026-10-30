/* Public-key cryptography through the generated headers: X25519 (RFC 7748 section 6.1), Ed25519 (RFC 8032
 * section 7.1, TEST 1) and an HPKE exchange whose contexts are opaque handles. */
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

/* The value of a lowercase hexadecimal digit. */
static uint8_t nibble(char digit) {
    return (uint8_t)(digit <= '9' ? digit - '0' : digit - 'a' + 10);
}

/* Writes the bytes of the lowercase hexadecimal text into `out`, which has half its length. */
static void from_hex(const char* text, uint8_t* out) {
    size_t index;
    for (index = 0; text[2 * index] != '\0'; index++) {
        out[index] = (uint8_t)(nibble(text[2 * index]) << 4 | nibble(text[2 * index + 1]));
    }
}

int main(void) {
    const char* curve25519 = "umilib_crypto_curve_curve25519_Curve25519";
    const char* edwards25519 = "umilib_crypto_curve_curve25519_Edwards25519";
    uint8_t alice[32], alice_public[32], bob[32], bob_public[32], shared[32], computed[32];
    from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice);
    from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alice_public);
    from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob);
    from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bob_public);
    from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared);

    size_t sizes[3];
    CHECK(umilib_crypto_ecdh_xdh_sizes((const uint8_t*)curve25519, strlen(curve25519), sizes) == NULL);
    CHECK(sizes[0] == 32 && sizes[1] == 32 && sizes[2] == 32);
    CHECK(umilib_crypto_ecdh_xdh_public_key((const uint8_t*)curve25519, strlen(curve25519), alice, 32, computed, 32) == NULL);
    CHECK(memcmp(computed, alice_public, 32) == 0);
    CHECK(umilib_crypto_ecdh_xdh_agree((const uint8_t*)curve25519, strlen(curve25519), alice, 32, bob_public, 32, computed, 32) == NULL);
    CHECK(memcmp(computed, shared, 32) == 0);
    CHECK(umilib_crypto_ecdh_xdh_agree((const uint8_t*)curve25519, strlen(curve25519), bob, 32, alice_public, 32, computed, 32) == NULL);
    CHECK(memcmp(computed, shared, 32) == 0);
    CHECK(fails_with(umilib_crypto_ecdh_xdh_agree((const uint8_t*)curve25519, strlen(curve25519), alice, 32, bob_public, 32, computed, 31),
                     "crypto", "InputLength"));

    uint8_t secret[32], public_key[32], signature[64], expected[64];
    from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", secret);
    from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
             expected);
    CHECK(umilib_crypto_eddsa_eddsa_verifying_key((const uint8_t*)edwards25519, strlen(edwards25519), secret, 32, public_key, 32) == NULL);
    from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", computed);
    CHECK(memcmp(public_key, computed, 32) == 0);
    CHECK(umilib_crypto_eddsa_eddsa_sign((const uint8_t*)edwards25519, strlen(edwards25519), secret, 32, NULL, 0, signature, 64) == NULL);
    CHECK(memcmp(signature, expected, 64) == 0);
    CHECK(umilib_crypto_eddsa_eddsa_verify((const uint8_t*)edwards25519, strlen(edwards25519), public_key, 32, NULL, 0, signature, 64) == NULL);
    signature[0] ^= 1;
    CHECK(fails_with(umilib_crypto_eddsa_eddsa_verify((const uint8_t*)edwards25519, strlen(edwards25519), public_key, 32, NULL, 0, signature, 64),
                     "crypto", "InvalidSignature"));

    /* HPKE DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 in the base mode. */
    const char* sha256 = "umilib_hash_sha_v2_SHA256";
    const char* drbg = "umilib_crypto_random_HMACDRBG";
    static const uint8_t entropy[32] = {7}, nonce[16] = {8};
    umilib_crypto_random_HMACDRBG* random = NULL;
    CHECK(umilib_crypto_random_hmac_drbg_new((const uint8_t*)sha256, strlen(sha256), entropy, 32, nonce, 16, NULL, 0, &random) == NULL);
    uint8_t recipient[32], recipient_public[32], encapsulated[32];
    CHECK(umilib_crypto_hpke_hpke_generate_key_pair(0x0020, random, (const uint8_t*)drbg, strlen(drbg), recipient, 32, recipient_public, 32) == NULL);
    umilib_crypto_hpke_HPKESenderContext* sender = NULL;
    umilib_crypto_hpke_HPKEReceiverContext* receiver = NULL;
    CHECK(umilib_crypto_hpke_hpke_setup_sender(0x0020, 0x0001, 0x0003, recipient_public, 32, (const uint8_t*)"info", 4, NULL, 0, NULL, 0, NULL, 0,
                                               random, (const uint8_t*)drbg, strlen(drbg), encapsulated, 32, &sender) == NULL);
    CHECK(umilib_crypto_hpke_hpke_setup_receiver(0x0020, 0x0001, 0x0003, encapsulated, 32, recipient, 32, (const uint8_t*)"info", 4, NULL, 0, NULL, 0,
                                                 NULL, 0, &receiver) == NULL);
    umilib_ffi_Buffer ciphertext = {0}, plaintext = {0};
    CHECK(umilib_crypto_hpke_hpke_sender_context_seal(sender, NULL, 0, (const uint8_t*)"message", 7, &ciphertext) == NULL);
    CHECK(ciphertext.length == 7 + 16);
    CHECK(umilib_crypto_hpke_hpke_receiver_context_open(receiver, NULL, 0, ciphertext.data, ciphertext.length, &plaintext) == NULL);
    CHECK(plaintext.length == 7 && memcmp(plaintext.data, "message", 7) == 0);
    CHECK(fails_with(umilib_crypto_hpke_hpke_receiver_context_open(receiver, NULL, 0, ciphertext.data, ciphertext.length, &plaintext), "crypto",
                     "AuthenticationFailed"));
    uint64_t sequence = 0;
    CHECK(umilib_crypto_hpke_hpke_receiver_context_sequence(receiver, &sequence) == NULL);
    CHECK(sequence == 1);
    umilib_ffi_buffer_free(&ciphertext);
    umilib_ffi_buffer_free(&plaintext);
    umilib_crypto_hpke_hpke_sender_context_free(sender);
    umilib_crypto_hpke_hpke_receiver_context_free(receiver);

    /* SM9 on its curve with SM3: the encryption of a message for Bob with SM4 and an encapsulated key. */
    const char* sm9_curve = "umilib_math_pairing_SM9BN256";
    const char* sm3 = "umilib_hash_sm3_SM3";
    const char* sm4 = "umilib_crypto_sm4_SM4";
    umilib_crypto_sm9_SM9EncryptMasterKey* master = NULL;
    umilib_crypto_sm9_SM9EncryptUserKey* sm9_bob = NULL;
    CHECK(umilib_crypto_sm9_sm9_encrypt_master_key_generate((const uint8_t*)sm9_curve, strlen(sm9_curve), random, (const uint8_t*)drbg, strlen(drbg),
                                                            &master) == NULL);
    CHECK(umilib_crypto_sm9_sm9_encrypt_master_key_extract(master, (const uint8_t*)sm3, strlen(sm3), (const uint8_t*)"Bob", 3, 0x03, &sm9_bob) == NULL);
    umilib_ffi_Buffer master_public = {0}, sealed = {0}, opened = {0};
    CHECK(umilib_crypto_sm9_sm9_encrypt_master_key_public_key(master, &master_public) == NULL);
    CHECK(master_public.length == 64);
    CHECK(umilib_crypto_sm9_sm9pke_encrypt((const uint8_t*)sm9_curve, strlen(sm9_curve), (const uint8_t*)sm3, strlen(sm3), (const uint8_t*)sm4,
                                           strlen(sm4), master_public.data, master_public.length, (const uint8_t*)"Bob", 3, 0x03,
                                           (const uint8_t*)"message", 7, random, (const uint8_t*)drbg, strlen(drbg), &sealed) == NULL);
    CHECK(sealed.length == 64 + 32 + 16);
    CHECK(umilib_crypto_sm9_sm9pke_decrypt(sm9_bob, (const uint8_t*)sm3, strlen(sm3), (const uint8_t*)sm4, strlen(sm4), sealed.data, sealed.length,
                                           &opened) == NULL);
    CHECK(opened.length == 7 && memcmp(opened.data, "message", 7) == 0);
    uint8_t sm9_key[32], sm9_decapsulated[32], sm9_encapsulated[64];
    CHECK(umilib_crypto_sm9_sm9kem_encapsulate((const uint8_t*)sm9_curve, strlen(sm9_curve), (const uint8_t*)sm3, strlen(sm3), master_public.data,
                                               master_public.length, (const uint8_t*)"Bob", 3, 0x03, random, (const uint8_t*)drbg, strlen(drbg),
                                               sm9_key, 32, sm9_encapsulated, 64) == NULL);
    CHECK(umilib_crypto_sm9_sm9kem_decapsulate(sm9_bob, (const uint8_t*)sm3, strlen(sm3), sm9_encapsulated, 64, sm9_decapsulated, 32) == NULL);
    CHECK(memcmp(sm9_key, sm9_decapsulated, 32) == 0);
    umilib_ffi_buffer_free(&master_public);
    umilib_ffi_buffer_free(&sealed);
    umilib_ffi_buffer_free(&opened);
    umilib_crypto_sm9_sm9_encrypt_user_key_free(sm9_bob);
    umilib_crypto_sm9_sm9_encrypt_master_key_free(master);

    /* ML-KEM-768 and ML-DSA-44 (FIPS 203, FIPS 204). */
    const char* mlkem768 = "umilib_crypto_mlkem_MLKEM768";
    static uint8_t mlkem_dk[2400], mlkem_ek[1184], mlkem_ciphertext[1088];
    uint8_t mlkem_sent[32], mlkem_received[32];
    CHECK(umilib_crypto_mlkem_mlkem_generate((const uint8_t*)mlkem768, strlen(mlkem768), random, (const uint8_t*)drbg, strlen(drbg), mlkem_dk,
                                             sizeof mlkem_dk) == NULL);
    CHECK(umilib_crypto_mlkem_mlkem_encapsulation_key((const uint8_t*)mlkem768, strlen(mlkem768), mlkem_dk, sizeof mlkem_dk, mlkem_ek,
                                                      sizeof mlkem_ek) == NULL);
    CHECK(umilib_crypto_mlkem_mlkem_encapsulate((const uint8_t*)mlkem768, strlen(mlkem768), mlkem_ek, sizeof mlkem_ek, random, (const uint8_t*)drbg,
                                                strlen(drbg), mlkem_ciphertext, sizeof mlkem_ciphertext, mlkem_sent, 32) == NULL);
    CHECK(umilib_crypto_mlkem_mlkem_decapsulate((const uint8_t*)mlkem768, strlen(mlkem768), mlkem_dk, sizeof mlkem_dk, mlkem_ciphertext,
                                                sizeof mlkem_ciphertext, mlkem_received, 32) == NULL);
    CHECK(memcmp(mlkem_sent, mlkem_received, 32) == 0);
    const char* mldsa44 = "umilib_crypto_mldsa_MLDSA44";
    static uint8_t mldsa_sk[2560], mldsa_pk[1312], mldsa_signature[2420];
    CHECK(umilib_crypto_mldsa_mldsa_generate((const uint8_t*)mldsa44, strlen(mldsa44), random, (const uint8_t*)drbg, strlen(drbg), mldsa_sk,
                                             sizeof mldsa_sk) == NULL);
    CHECK(umilib_crypto_mldsa_mldsa_verifying_key((const uint8_t*)mldsa44, strlen(mldsa44), mldsa_sk, sizeof mldsa_sk, mldsa_pk, sizeof mldsa_pk) ==
          NULL);
    CHECK(umilib_crypto_mldsa_mldsa_sign_with_context((const uint8_t*)mldsa44, strlen(mldsa44), mldsa_sk, sizeof mldsa_sk, (const uint8_t*)"message",
                                                      7, (const uint8_t*)"context", 7, random, (const uint8_t*)drbg, strlen(drbg), mldsa_signature,
                                                      sizeof mldsa_signature) == NULL);
    CHECK(umilib_crypto_mldsa_mldsa_verify_with_context((const uint8_t*)mldsa44, strlen(mldsa44), mldsa_pk, sizeof mldsa_pk,
                                                        (const uint8_t*)"message", 7, (const uint8_t*)"context", 7, mldsa_signature,
                                                        sizeof mldsa_signature) == NULL);
    CHECK(fails_with(umilib_crypto_mldsa_mldsa_verify_with_context((const uint8_t*)mldsa44, strlen(mldsa44), mldsa_pk, sizeof mldsa_pk,
                                                                   (const uint8_t*)"message", 7, (const uint8_t*)"other", 5, mldsa_signature,
                                                                   sizeof mldsa_signature),
                     "crypto", "InvalidSignature"));
    umilib_crypto_random_hmac_drbg_free(random);

    printf("public_key.c: ok\n");
    return 0;
}
