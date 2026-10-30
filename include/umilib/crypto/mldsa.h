/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MLDSA_H
#define UMILIB_CRYPTO_MLDSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a signing key, a verifying key and a signature of ML-DSA with the parameter set named by `parameters` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sizes(const uint8_t* parameters, size_t parameters_length, size_t* sizes);

/**
 * Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_generate(const uint8_t* parameters, size_t parameters_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_verifying_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_check_signing_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_check_verifying_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length);

/**
 * Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sign(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is a signature of the message under the encoded verifying key; fails
 * with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_verify(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the private key of the seed ξ (32 bytes) into `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_signing_key_from_seed(const uint8_t* parameters, size_t parameters_length, const uint8_t* seed, size_t seed_length, uint8_t* out, size_t out_length);

/**
 * ML-DSA.Sign (FIPS 204 algorithm 2) of the message with the context (at most 255 bytes) and rnd from the
 * generator handle `random`, into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sign_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * The deterministic variant of ML-DSA.Sign (rnd = 0^32) with the context.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sign_deterministic_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, uint8_t* out, size_t out_length);

/**
 * ML-DSA.Verify (FIPS 204 algorithm 3) with the context; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_verify_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, const uint8_t* signature, size_t signature_length);

/**
 * HashML-DSA.Sign (FIPS 204 algorithm 4) with the pre-hash named by `hash`, the context and rnd from the
 * generator handle `random`.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sign_pre_hash(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * The deterministic variant of HashML-DSA.Sign (rnd = 0^32).
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_sign_pre_hash_deterministic(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, uint8_t* out, size_t out_length);

/**
 * HashML-DSA.Verify (FIPS 204 algorithm 5) with the pre-hash named by `hash` and the context.
 */
const umilib_ffi_Status* umilib_crypto_mldsa_mldsa_verify_pre_hash(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, const uint8_t* signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
