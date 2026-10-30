/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_CERT_KEY_H
#define UMILIB_AUTH_CERT_KEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A signature algorithm and its parameters.
 */
typedef struct umilib_auth_cert_key_SignatureAlgorithm umilib_auth_cert_key_SignatureAlgorithm;

/**
 * The algorithm of a key and its parameters.
 */
typedef struct umilib_auth_cert_key_KeyAlgorithm umilib_auth_cert_key_KeyAlgorithm;

/**
 * A validated public key and its algorithm.
 */
typedef struct umilib_auth_cert_key_PublicKey umilib_auth_cert_key_PublicKey;

/**
 * A private key and its algorithm.
 */
typedef struct umilib_auth_cert_key_PrivateKey umilib_auth_cert_key_PrivateKey;

/**
 * The parameters of PBES2: the indices of the PRF's hash function and of the cipher, the iterations, the salt length and the most iterations accepted when decrypting.
 */
typedef struct umilib_auth_cert_key_PBES2Config {
    uint8_t prf;
    uint8_t cipher;
    uint32_t iterations;
    uint32_t salt_length;
    uint32_t maximum_iterations;
} umilib_auth_cert_key_PBES2Config;

/**
 * Writes the bytes of the digest of the hash function `hash` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_hash_algorithm_output_size(uint8_t hash, size_t* out);

/**
 * Writes the signature algorithm RSASSA-PKCS1-v1_5 with the hash function `hash` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_rsa_pkcs1v15(uint8_t hash, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm RSASSA-PSS with the hash functions `hash` and `mask_hash` (of MGF1)
 * and a salt of `salt_length` bytes into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_rsa_pss(uint8_t hash, uint8_t mask_hash, uint32_t salt_length, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm ECDSA with the hash function `hash` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_ecdsa(uint8_t hash, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm Ed25519 into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_ed25519(umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm Ed448 into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_ed448(umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm ML-DSA of the parameter set `set` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_mldsa(uint8_t set, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm SLH-DSA (pure, or HashSLH-DSA if `pre_hash`) of the parameter set `set` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_slhdsa(uint8_t set, bool pre_hash, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the signature algorithm of the DER `AlgorithmIdentifier` of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_from_der(const uint8_t* data, size_t length, umilib_auth_cert_key_SignatureAlgorithm** out);

/**
 * Writes the DER `AlgorithmIdentifier` of the signature algorithm into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_signature_algorithm_to_der(const umilib_auth_cert_key_SignatureAlgorithm* algorithm, umilib_ffi_Buffer* out);

/**
 * Releases a signature algorithm. Does nothing if `algorithm` is null.
 */
void umilib_auth_cert_key_signature_algorithm_free(umilib_auth_cert_key_SignatureAlgorithm* algorithm);

/**
 * Writes the key algorithm `kind` into `out`: 0 RSA, 1 RSASSA-PSS (without parameters), 2 EC (on
 * the curve `parameter`), 3 X25519, 4 X448, 5 Ed25519, 6 Ed448, 7 ML-DSA, 8 SLH-DSA, 9 HashSLH-DSA
 * and 10 ML-KEM (of the parameter set `parameter`).
 */
const umilib_ffi_Status* umilib_auth_cert_key_key_algorithm_new(uint8_t kind, uint8_t parameter, umilib_auth_cert_key_KeyAlgorithm** out);

/**
 * Writes the key algorithm RSASSA-PSS restricted to the parameters of `signature` (an RSASSA-PSS
 * signature algorithm) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_key_algorithm_rsa_pss(const umilib_auth_cert_key_SignatureAlgorithm* signature, umilib_auth_cert_key_KeyAlgorithm** out);

/**
 * Writes the key algorithm of the DER `AlgorithmIdentifier` of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_key_algorithm_from_der(const uint8_t* data, size_t length, umilib_auth_cert_key_KeyAlgorithm** out);

/**
 * Writes the DER `AlgorithmIdentifier` of the key algorithm into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_key_algorithm_to_der(const umilib_auth_cert_key_KeyAlgorithm* algorithm, umilib_ffi_Buffer* out);

/**
 * Writes whether a key of `algorithm` makes signatures of `signature` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_key_algorithm_signs(const umilib_auth_cert_key_KeyAlgorithm* algorithm, const umilib_auth_cert_key_SignatureAlgorithm* signature, bool* out);

/**
 * Releases a key algorithm. Does nothing if `algorithm` is null.
 */
void umilib_auth_cert_key_key_algorithm_free(umilib_auth_cert_key_KeyAlgorithm* algorithm);

/**
 * Writes the public key of the DER `SubjectPublicKeyInfo` of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_from_der(const uint8_t* data, size_t length, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes the public key of the PEM text (`PUBLIC KEY`) of `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes the DER `SubjectPublicKeyInfo` of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_to_der(const umilib_auth_cert_key_PublicKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the PEM text (`PUBLIC KEY`) of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_to_pem(const umilib_auth_cert_key_PublicKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the bytes of the key's `subjectPublicKey` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_key(const umilib_auth_cert_key_PublicKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the algorithm of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_algorithm(const umilib_auth_cert_key_PublicKey* key, umilib_auth_cert_key_KeyAlgorithm** out);

/**
 * Succeeds if the `signature_length` bytes at `signature` are a signature of the `length` bytes at
 * `message` with `algorithm` under the key; fails with InvalidSignature, or Mismatch if the key
 * does not make such signatures.
 */
const umilib_ffi_Status* umilib_auth_cert_key_public_key_verify(const umilib_auth_cert_key_PublicKey* key, const umilib_auth_cert_key_SignatureAlgorithm* algorithm, const uint8_t* message, size_t length, const uint8_t* signature, size_t signature_length);

/**
 * Releases a public key. Does nothing if `key` is null.
 */
void umilib_auth_cert_key_public_key_free(umilib_auth_cert_key_PublicKey* key);

/**
 * Writes a new key of `algorithm` (not RSA) drawn from the generator `random` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_generate(const umilib_auth_cert_key_KeyAlgorithm* algorithm, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes a new RSA key of `bits` bits for `algorithm` (RSA or RSASSA-PSS) into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_generate_rsa(const umilib_auth_cert_key_KeyAlgorithm* algorithm, uint32_t bits, void* random, const uint8_t* random_type, size_t random_type_length, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of the DER `OneAsymmetricKey` (PKCS #8) of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_pkcs8_der(const uint8_t* data, size_t length, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of the `OneAsymmetricKey` (PKCS #8) in BER (DER included, as RFC 5958 requires
 * receivers to accept) of `length` bytes at `data` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_pkcs8_ber(const uint8_t* data, size_t length, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of the `EncryptedPrivateKeyInfo` in BER (DER included) of `length` bytes at
 * `data`, decrypted as in `_from_encrypted_pkcs8_der`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_encrypted_pkcs8_ber(const uint8_t* data, size_t length, const uint8_t* password, size_t password_length, umilib_auth_cert_key_PBES2Config config, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of PEM text (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`) of `length`
 * bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_pem(const uint8_t* text, size_t length, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of the DER `EncryptedPrivateKeyInfo` of `length` bytes at `data`, decrypted with
 * the `password_length` bytes at `password` and the limits of `config`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_encrypted_pkcs8_der(const uint8_t* data, size_t length, const uint8_t* password, size_t password_length, umilib_auth_cert_key_PBES2Config config, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the key of PEM text of an `ENCRYPTED PRIVATE KEY`, decrypted as in
 * `_from_encrypted_pkcs8_der`, into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_from_encrypted_pem(const uint8_t* text, size_t length, const uint8_t* password, size_t password_length, umilib_auth_cert_key_PBES2Config config, umilib_auth_cert_key_PrivateKey** out);

/**
 * Writes the DER `OneAsymmetricKey` (PKCS #8) of the key into `out` (zeroized by `umilib_ffi_buffer_free`).
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_to_pkcs8_der(const umilib_auth_cert_key_PrivateKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the PEM text (`PRIVATE KEY`) of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_to_pem(const umilib_auth_cert_key_PrivateKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the DER `EncryptedPrivateKeyInfo` of the key, encrypted with the `password_length` bytes
 * at `password` and the parameters of `config` (a salt and an IV from `random`), into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_to_encrypted_pkcs8_der(const umilib_auth_cert_key_PrivateKey* key, const uint8_t* password, size_t password_length, umilib_auth_cert_key_PBES2Config config, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Writes the public key of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_public_key(const umilib_auth_cert_key_PrivateKey* key, umilib_auth_cert_key_PublicKey** out);

/**
 * Writes the algorithm of the key into `out`.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_algorithm(const umilib_auth_cert_key_PrivateKey* key, umilib_auth_cert_key_KeyAlgorithm** out);

/**
 * Writes the signature of the `length` bytes at `message` with `algorithm` (drawing from `random`
 * where the algorithm uses random bytes) into `out`; fails with Mismatch if the key does not make
 * such signatures.
 */
const umilib_ffi_Status* umilib_auth_cert_key_private_key_sign(const umilib_auth_cert_key_PrivateKey* key, const umilib_auth_cert_key_SignatureAlgorithm* algorithm, const uint8_t* message, size_t length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

/**
 * Releases a private key, zeroizing it. Does nothing if `key` is null.
 */
void umilib_auth_cert_key_private_key_free(umilib_auth_cert_key_PrivateKey* key);

#ifdef __cplusplus
}
#endif

#endif
