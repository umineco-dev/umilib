/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_RSA_H
#define UMILIB_CRYPTO_RSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An RSA public key (n, e) of RFC 8017 section 3.1.
 */
typedef struct umilib_crypto_rsa_RSAPublicKey umilib_crypto_rsa_RSAPublicKey;

/**
 * An RSA private key of RFC 8017 section 3.2, with its primes when they are known.
 */
typedef struct umilib_crypto_rsa_RSAPrivateKey umilib_crypto_rsa_RSAPrivateKey;

/**
 * Creates the public key (n, e) of the big-endian integers; fails with InvalidKey unless n is odd and
 * e odd with 3 ≤ e < n.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_new(const uint8_t* n, size_t n_length, const uint8_t* e, size_t e_length, umilib_crypto_rsa_RSAPublicKey** out);

/**
 * Releases the public key. Does nothing if it is null.
 */
void umilib_crypto_rsa_rsa_public_key_free(umilib_crypto_rsa_RSAPublicKey* key);

/**
 * The bytes of n: the length of signatures and ciphertexts.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_size(const umilib_crypto_rsa_RSAPublicKey* key, size_t* out);

/**
 * Writes n big-endian without leading zeros into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_n(const umilib_crypto_rsa_RSAPublicKey* key, umilib_ffi_Buffer* out);

/**
 * Writes e big-endian without leading zeros into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_e(const umilib_crypto_rsa_RSAPublicKey* key, umilib_ffi_Buffer* out);

/**
 * Creates the private key of the big-endian n, e and d, without its primes; fails with InvalidKey
 * unless d inverts e.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_new(const uint8_t* n, size_t n_length, const uint8_t* e, size_t e_length, const uint8_t* d, size_t d_length, umilib_crypto_rsa_RSAPrivateKey** out);

/**
 * Creates the private key of the primes p and q and the public exponent e, with d = e^-1 mod
 * lcm(p - 1, q - 1).
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_from_primes(const uint8_t* p, size_t p_length, const uint8_t* q, size_t q_length, const uint8_t* e, size_t e_length, umilib_crypto_rsa_RSAPrivateKey** out);

/**
 * Generates a private key of `bits` bits (at least 2048, even) with the public exponent e (odd,
 * 2^16 < e < 2^256), from the generator handle `random` of the type named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_generate(uint32_t bits, const uint8_t* e, size_t e_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_rsa_RSAPrivateKey** out);

/**
 * Releases the private key, zeroizing it. Does nothing if it is null.
 */
void umilib_crypto_rsa_rsa_private_key_free(umilib_crypto_rsa_RSAPrivateKey* key);

/**
 * Writes the private exponent d big-endian, without leading zeros, into a new buffer, which zeroizes it
 * when it is released.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_d(const umilib_crypto_rsa_RSAPrivateKey* key, umilib_ffi_Buffer* out);

/**
 * Creates a copy of the public key of the private key.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_public_key(const umilib_crypto_rsa_RSAPrivateKey* key, umilib_crypto_rsa_RSAPublicKey** out);

/**
 * Writes the RSASSA-PKCS1-v1_5 signature of the message with the hash function named by `hash` into
 * `out` of the size of the key.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_pkcs1v15_sign(const umilib_crypto_rsa_RSAPrivateKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is the RSASSA-PKCS1-v1_5 signature of the message with the hash function
 * named by `hash`; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_pkcs1v15_verify(const umilib_crypto_rsa_RSAPublicKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the RSASSA-PSS signature of the message with the hash functions named by `hash` and `mgf` and
 * a random salt of `salt_length` bytes into `out` of the size of the key.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_pss_sign(const umilib_crypto_rsa_RSAPrivateKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* mgf, size_t mgf_length, size_t salt_length, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is an RSASSA-PSS signature of the message with the hash functions named by
 * `hash` and `mgf` and a salt of `salt_length` bytes; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_pss_verify(const umilib_crypto_rsa_RSAPublicKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* mgf, size_t mgf_length, size_t salt_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the RSAES-OAEP encryption of the message with the label and the hash functions named by
 * `hash` and `mgf` into `out` of the size of the key; fails with InputLength for a message too long.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_oaep_encrypt(const umilib_crypto_rsa_RSAPublicKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* mgf, size_t mgf_length, const uint8_t* label, size_t label_length, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the message of the RSAES-OAEP ciphertext with the label and the hash functions named by `hash`
 * and `mgf` into a new buffer; fails with DecryptionFailed alike for every invalid ciphertext.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_oaep_decrypt(const umilib_crypto_rsa_RSAPrivateKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* mgf, size_t mgf_length, const uint8_t* label, size_t label_length, const uint8_t* ciphertext, size_t ciphertext_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Creates the public key of the PKCS #1 `RSAPublicKey` in DER.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_from_pkcs1_der(const uint8_t* der, size_t der_length, umilib_crypto_rsa_RSAPublicKey** out);

/**
 * Writes the PKCS #1 `RSAPublicKey` in DER into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_public_key_to_pkcs1_der(const umilib_crypto_rsa_RSAPublicKey* key, umilib_ffi_Buffer* out);

/**
 * Creates the private key of the PKCS #1 `RSAPrivateKey` (version 0) in DER.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_from_pkcs1_der(const uint8_t* der, size_t der_length, umilib_crypto_rsa_RSAPrivateKey** out);

/**
 * Writes the PKCS #1 `RSAPrivateKey` in DER into a new buffer; fails with InvalidKey for a key
 * without its primes.
 */
const umilib_ffi_Status* umilib_crypto_rsa_rsa_private_key_to_pkcs1_der(const umilib_crypto_rsa_RSAPrivateKey* key, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
