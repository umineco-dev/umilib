/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ECCSI_H
#define UMILIB_CRYPTO_ECCSI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a secret, a point and a signature of ECCSI on the curve named by `curve`
 * with the hash function named by `hash` into `sizes` (three elements); fails with InvalidParameter for a
 * pair other than those of section 4.1.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_sizes(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, size_t* sizes);

/**
 * Writes the sizes in bytes of a secret and a point on the curve named by `curve` into `sizes` (two
 * elements).
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_kms_sizes(const uint8_t* curve, size_t curve_length, size_t* sizes);

/**
 * Generates a KMS on the curve named by `curve` from the generator handle `random` of the type named by
 * `random_type`: writes its KSAK into `secret` and its KPAK into `public_key`.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_kms_generate(const uint8_t* curve, size_t curve_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* secret, size_t secret_length, uint8_t* public_key, size_t public_key_length);

/**
 * Writes the KPAK of the KSAK `secret` on the curve named by `curve` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_kms_public_key(const uint8_t* curve, size_t curve_length, const uint8_t* secret, size_t secret_length, uint8_t* out, size_t out_length);

/**
 * Issues the (SSK, PVT) pair of `identity` from the KSAK `kms` (section 5.1.1) with v drawn from the
 * generator handle `random` of the type named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_kms_issue(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* kms, size_t kms_length, const uint8_t* identity, size_t identity_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* secret, size_t secret_length, uint8_t* token, size_t token_length);

/**
 * [`umilib_crypto_eccsi_eccsi_kms_issue`] with v given (section 5.1.1 steps 2 to 6). v must be secret,
 * random and used once; fails with InvalidParameter when another v is needed.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_kms_issue_with_ephemeral(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* kms, size_t kms_length, const uint8_t* identity, size_t identity_length, const uint8_t* ephemeral, size_t ephemeral_length, uint8_t* secret, size_t secret_length, uint8_t* token, size_t token_length);

/**
 * Succeeds if (SSK, PVT) is a valid key of `identity` under the KPAK `authority` (section 5.1.2); fails
 * with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_user_key_check(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* authority, size_t authority_length, const uint8_t* identity, size_t identity_length, const uint8_t* secret, size_t secret_length, const uint8_t* token, size_t token_length);

/**
 * Writes the signature r || s || PVT of `message` by the key (SSK, PVT) of `identity` under the KPAK
 * `authority` (section 5.2.1) into `out` of the size of a signature, with j derived from the key, the
 * message and the generator handle `random` of the type named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_sign(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* authority, size_t authority_length, const uint8_t* identity, size_t identity_length, const uint8_t* secret, size_t secret_length, const uint8_t* token, size_t token_length, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * [`umilib_crypto_eccsi_eccsi_sign`] with j given (section 5.2.1 steps 2 to 7). j must be secret, random
 * and used once; fails with InvalidParameter when another j is needed.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_sign_with_ephemeral(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* authority, size_t authority_length, const uint8_t* identity, size_t identity_length, const uint8_t* secret, size_t secret_length, const uint8_t* token, size_t token_length, const uint8_t* message, size_t message_length, const uint8_t* ephemeral, size_t ephemeral_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if `signature` is a signature of `message` by `identity` under the KPAK `authority` (section
 * 5.2.2); fails with InvalidSignature otherwise.
 */
const umilib_ffi_Status* umilib_crypto_eccsi_eccsi_verify(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* authority, size_t authority_length, const uint8_t* identity, size_t identity_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
