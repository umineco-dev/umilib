/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SLHDSA_H
#define UMILIB_CRYPTO_SLHDSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a signing key, a verifying key and a signature of SLH-DSA with the parameter set named by `parameters` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sizes(const uint8_t* parameters, size_t parameters_length, size_t* sizes);

/**
 * Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_generate(const uint8_t* parameters, size_t parameters_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_verifying_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_check_signing_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_check_verifying_key(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length);

/**
 * Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sign(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is a signature of the message under the encoded verifying key; fails
 * with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_verify(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * slh_keygen_internal (FIPS 205 algorithm 18) of SK.seed, SK.prf and PK.seed (n bytes each): writes
 * the private key into `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_key_gen_internal(const uint8_t* parameters, size_t parameters_length, const uint8_t* sk_seed, size_t sk_seed_length, const uint8_t* sk_prf, size_t sk_prf_length, const uint8_t* pk_seed, size_t pk_seed_length, uint8_t* out, size_t out_length);

/**
 * slh_sign (FIPS 205 algorithm 22) of the message with the context (at most 255 bytes) and addrnd from
 * the generator handle `random`, into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sign_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * The deterministic variant of slh_sign (opt_rand = PK.seed) with the context.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sign_deterministic_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, uint8_t* out, size_t out_length);

/**
 * slh_verify (FIPS 205 algorithm 24) with the context; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_verify_with_context(const uint8_t* parameters, size_t parameters_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, const uint8_t* signature, size_t signature_length);

/**
 * hash_slh_sign (FIPS 205 algorithm 23) with the pre-hash named by `hash`, the context and addrnd from
 * the generator handle `random`.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sign_pre_hash(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * The deterministic variant of hash_slh_sign (opt_rand = PK.seed).
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_sign_pre_hash_deterministic(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, uint8_t* out, size_t out_length);

/**
 * hash_slh_verify (FIPS 205 algorithm 25) with the pre-hash named by `hash` and the context.
 */
const umilib_ffi_Status* umilib_crypto_slhdsa_slhdsa_verify_pre_hash(const uint8_t* parameters, size_t parameters_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* context, size_t context_length, const uint8_t* signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
