/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_DSA_H
#define UMILIB_CRYPTO_DSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The domain parameters (p, q, g) of DSA (FIPS 186-4 section 4.3).
 */
typedef struct umilib_crypto_dsa_DSAParameters umilib_crypto_dsa_DSAParameters;

/**
 * A signing key x of DSA with its parameters and verifying key.
 */
typedef struct umilib_crypto_dsa_DSASigningKey umilib_crypto_dsa_DSASigningKey;

/**
 * A verifying key y of DSA with its parameters.
 */
typedef struct umilib_crypto_dsa_DSAVerifyingKey umilib_crypto_dsa_DSAVerifyingKey;

/**
 * Creates the domain parameters (p, q, g) of the big-endian integers; fails with InvalidParameter for
 * sizes other than those of FIPS 186-4 or inconsistent values.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_parameters_new(const uint8_t* p, size_t p_length, const uint8_t* q, size_t q_length, const uint8_t* g, size_t g_length, umilib_crypto_dsa_DSAParameters** out);

/**
 * Releases the parameters. Does nothing if they are null.
 */
void umilib_crypto_dsa_dsa_parameters_free(umilib_crypto_dsa_DSAParameters* parameters);

/**
 * The bytes of each half of a signature: those of q.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_parameters_q_bytes(const umilib_crypto_dsa_DSAParameters* parameters, size_t* out);

/**
 * Writes p big-endian, without leading zeros, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_parameters_p(const umilib_crypto_dsa_DSAParameters* parameters, umilib_ffi_Buffer* out);

/**
 * Writes q big-endian, without leading zeros, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_parameters_q(const umilib_crypto_dsa_DSAParameters* parameters, umilib_ffi_Buffer* out);

/**
 * Writes g big-endian, of the bytes of p, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_parameters_g(const umilib_crypto_dsa_DSAParameters* parameters, umilib_ffi_Buffer* out);

/**
 * Creates the signing key x (big-endian, 1 ≤ x < q) under a copy of the parameters.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signing_key_new(const umilib_crypto_dsa_DSAParameters* parameters, const uint8_t* x, size_t x_length, umilib_crypto_dsa_DSASigningKey** out);

/**
 * Generates a signing key under a copy of the parameters from the generator handle `random` of the type
 * named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signing_key_generate(const umilib_crypto_dsa_DSAParameters* parameters, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_dsa_DSASigningKey** out);

/**
 * Releases the signing key, zeroizing it. Does nothing if it is null.
 */
void umilib_crypto_dsa_dsa_signing_key_free(umilib_crypto_dsa_DSASigningKey* key);

/**
 * Creates a copy of the verifying key of the signing key.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signing_key_verifying_key(const umilib_crypto_dsa_DSASigningKey* key, umilib_crypto_dsa_DSAVerifyingKey** out);

/**
 * Writes x big-endian, of the bytes of q, into a new buffer, which zeroizes it when it is released.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signing_key_x(const umilib_crypto_dsa_DSASigningKey* key, umilib_ffi_Buffer* out);

/**
 * Creates a copy of the parameters of the signing key.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signing_key_parameters(const umilib_crypto_dsa_DSASigningKey* key, umilib_crypto_dsa_DSAParameters** out);

/**
 * Creates the verifying key y (big-endian) under a copy of the parameters; fails with InvalidKey unless
 * 2 ≤ y ≤ p - 2 and y^q = 1 mod p.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_verifying_key_new(const umilib_crypto_dsa_DSAParameters* parameters, const uint8_t* y, size_t y_length, umilib_crypto_dsa_DSAVerifyingKey** out);

/**
 * Releases the verifying key. Does nothing if it is null.
 */
void umilib_crypto_dsa_dsa_verifying_key_free(umilib_crypto_dsa_DSAVerifyingKey* key);

/**
 * Writes y big-endian, of the bytes of p, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_verifying_key_y(const umilib_crypto_dsa_DSAVerifyingKey* key, umilib_ffi_Buffer* out);

/**
 * Creates a copy of the parameters of the verifying key.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_verifying_key_parameters(const umilib_crypto_dsa_DSAVerifyingKey* key, umilib_crypto_dsa_DSAParameters** out);

/**
 * Writes the signature r || s of the message with the hash function named by `hash` (and the nonce of
 * RFC 6979) into `out` of twice the bytes of q.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_sign(const umilib_crypto_dsa_DSASigningKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if r || s is a signature of the message with the hash function named by `hash`; fails with
 * InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_verify(const umilib_crypto_dsa_DSAVerifyingKey* key, const uint8_t* hash, size_t hash_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature r || s of the DER `Dss-Sig-Value` into a new buffer; fails with InvalidSignature
 * for another encoding or values out of range.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signature_from_der(const umilib_crypto_dsa_DSAParameters* parameters, const uint8_t* der, size_t der_length, umilib_ffi_Buffer* out);

/**
 * Writes the DER `Dss-Sig-Value` of the signature r || s into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_dsa_dsa_signature_to_der(const umilib_crypto_dsa_DSAParameters* parameters, const uint8_t* signature, size_t signature_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
