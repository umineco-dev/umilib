/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_IBS_CHACHEON_H
#define UMILIB_CRYPTO_IBS_CHACHEON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/crypto/ibs.h"
#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a master secret, a master public key and a signature of the scheme of Cha and Cheon on
 * the curve named by `curve` with the hash function named by `hash` into `sizes` (three elements).
 */
const umilib_ffi_Status* umilib_crypto_ibs_chacheon_chacheon_sizes(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, size_t* sizes);

/**
 * Creates the master key of a new private key generator (Setup) from the generator handle `random`,
 * whose C type is named by `random_type`.
 */
const umilib_ffi_Status* umilib_crypto_ibs_chacheon_chacheon_setup(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_crypto_ibs_IBSMasterKey** out);

/**
 * Creates the master key of the master secret (big-endian, 1 ≤ s < r); fails with InvalidKey
 * otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ibs_chacheon_chacheon_master_key_new(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* secret, size_t secret_length, umilib_crypto_ibs_IBSMasterKey** out);

/**
 * Succeeds if `signature` is a signature of `message` by `identity` under the encoded master public
 * key `master`; fails with InvalidSignature otherwise and InvalidKey for a master key that is not a
 * point of G_2.
 */
const umilib_ffi_Status* umilib_crypto_ibs_chacheon_chacheon_verify(const uint8_t* curve, size_t curve_length, const uint8_t* hash, size_t hash_length, const uint8_t* master, size_t master_length, const uint8_t* identity, size_t identity_length, const uint8_t* message, size_t message_length, const uint8_t* signature, size_t signature_length);

#ifdef __cplusplus
}
#endif

#endif
