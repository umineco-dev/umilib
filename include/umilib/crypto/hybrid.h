/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_HYBRID_H
#define UMILIB_CRYPTO_HYBRID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a decapsulation key, an encapsulation key, a ciphertext and a shared secret of the hybrid group named by `group`
 * into `sizes` (four elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_sizes(const uint8_t* group, size_t group_length, size_t* sizes);

/**
 * Generates a decapsulation key from the generator handle `random`, whose C type is named by the
 * UTF-8 text at `random_type`, and writes its encoding into `out` of the size of a decapsulation key.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_generate(const uint8_t* group, size_t group_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the encapsulation key of the encoded decapsulation key into `out` of the size of an
 * encapsulation key.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_encapsulation_key(const uint8_t* group, size_t group_length, const uint8_t* key, size_t key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded decapsulation key passes the checks of the scheme; fails with
 * InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_check_decapsulation_key(const uint8_t* group, size_t group_length, const uint8_t* key, size_t key_length);

/**
 * Succeeds if the encoded encapsulation key passes the checks of the scheme; fails with
 * InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_check_encapsulation_key(const uint8_t* group, size_t group_length, const uint8_t* key, size_t key_length);

/**
 * Encapsulates to the encoded encapsulation key with random values from the generator handle
 * `random`: the ciphertext into `ciphertext` and the shared secret into `shared`, of their sizes.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_encapsulate(const uint8_t* group, size_t group_length, const uint8_t* key, size_t key_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* ciphertext, size_t ciphertext_length, uint8_t* shared, size_t shared_length);

/**
 * Writes the shared secret of the ciphertext for the encoded decapsulation key into `shared` of
 * the size of a shared secret.
 */
const umilib_ffi_Status* umilib_crypto_hybrid_hybrid_kem_decapsulate(const uint8_t* group, size_t group_length, const uint8_t* key, size_t key_length, const uint8_t* ciphertext, size_t ciphertext_length, uint8_t* shared, size_t shared_length);

#ifdef __cplusplus
}
#endif

#endif
