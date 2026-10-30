/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_IBS_H
#define UMILIB_CRYPTO_IBS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The master key of a private key generator of an identity-based signature scheme, which keeps its scheme.
 */
typedef struct umilib_crypto_ibs_IBSMasterKey umilib_crypto_ibs_IBSMasterKey;

/**
 * The key of a user of an identity-based signature scheme, which keeps its scheme.
 */
typedef struct umilib_crypto_ibs_IBSUserKey umilib_crypto_ibs_IBSUserKey;

/**
 * Releases the master key, zeroizing its secret. Does nothing if it is null.
 */
void umilib_crypto_ibs_ibs_master_key_free(umilib_crypto_ibs_IBSMasterKey* key);

/**
 * Writes the encoded master public key P_pub into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_ibs_ibs_master_key_public_key(const umilib_crypto_ibs_IBSMasterKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the master secret s into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_ibs_ibs_master_key_secret(const umilib_crypto_ibs_IBSMasterKey* key, umilib_ffi_Buffer* out);

/**
 * Creates the user key of `identity` (Extract) of the scheme of the master key.
 */
const umilib_ffi_Status* umilib_crypto_ibs_ibs_master_key_extract(const umilib_crypto_ibs_IBSMasterKey* key, const uint8_t* identity, size_t identity_length, umilib_crypto_ibs_IBSUserKey** out);

/**
 * Releases the user key, zeroizing it. Does nothing if it is null.
 */
void umilib_crypto_ibs_ibs_user_key_free(umilib_crypto_ibs_IBSUserKey* key);

/**
 * Writes the identity of the key into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_ibs_ibs_user_key_identity(const umilib_crypto_ibs_IBSUserKey* key, umilib_ffi_Buffer* out);

/**
 * Writes the encoded signature of `message` by the owner of the key, with random values from the
 * generator handle `random` of the type named by `random_type`, into a new buffer.
 */
const umilib_ffi_Status* umilib_crypto_ibs_ibs_user_key_sign(const umilib_crypto_ibs_IBSUserKey* key, const uint8_t* message, size_t message_length, void* random, const uint8_t* random_type, size_t random_type_length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
