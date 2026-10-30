/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_EDDSA_H
#define UMILIB_CRYPTO_EDDSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a signing key, a verifying key and a signature of EdDSA on the curve named by `curve` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_sizes(const uint8_t* curve, size_t curve_length, size_t* sizes);

/**
 * Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_generate(const uint8_t* curve, size_t curve_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_check_signing_key(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_check_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length);

/**
 * Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_sign(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is a signature of the message under the encoded verifying key; fails
 * with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_verify(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature of Ed25519ctx or of Ed448 with the context of at most 255 bytes into `out`
 * of the size of a signature; fails with InvalidParameter for a longer context.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_sign_with_context(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* context, size_t context_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is one of Ed25519ctx or Ed448 with the context; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_verify_with_context(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* context, size_t context_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature of Ed25519ph or Ed448ph of the message (hashed by the function) with the
 * context into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_sign_prehashed(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* context, size_t context_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is one of Ed25519ph or Ed448ph with the context; fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eddsa_eddsa_verify_prehashed(const uint8_t* curve, size_t curve_length, const uint8_t* key, size_t key_length, const uint8_t* context, size_t context_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
