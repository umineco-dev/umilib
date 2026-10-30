/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ECDSA_H
#define UMILIB_CRYPTO_ECDSA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a signing key, a verifying key and a signature of ECDSA on the curve named by `curve` with the hash function named by `hash` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_sizes(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, size_t* sizes);

/**
 * Generates a signing key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a signing key.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_generate(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the verifying key of the encoded signing key into `out` of the size of a verifying key.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded signing key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_check_signing_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded verifying key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_check_verifying_key(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length);

/**
 * Writes the signature of the message under the encoded signing key into `out` of the size of a signature.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_sign(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the signature is a signature of the message under the encoded verifying key; fails
 * with InvalidSignature otherwise and with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_verify(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

/**
 * Writes the signature r || s of the DER `ECDSA-Sig-Value` on the curve named by `curve` into a new
 * buffer; fails with InvalidSignature for another encoding or values out of range.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_signature_from_der(const uint8_t* curve, size_t curve_length, const uint8_t* der, size_t der_length, umilib_ffi_Buffer* out);

/**
 * Writes the DER `ECDSA-Sig-Value` of the signature r || s on the curve named by `curve` into a new
 * buffer.
 */
const umilib_ffi_Status* umilib_crypto_ecdsa_ecdsa_signature_to_der(const uint8_t* curve, size_t curve_length, const uint8_t* signature, size_t signature_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
