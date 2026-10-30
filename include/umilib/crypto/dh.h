/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_DH_H
#define UMILIB_CRYPTO_DH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a private key, a public key and a shared secret of DH in the group named by `group` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_sizes(const uint8_t* group, size_t group_length, size_t* sizes);

/**
 * Generates a private key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a private key.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_generate(const uint8_t* group, size_t group_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the public key of the encoded private key into `out` of the size of a public key.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_public_key(const uint8_t* group, size_t group_length, const uint8_t* private_key, size_t private_key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded private key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_check_private_key(const uint8_t* group, size_t group_length, const uint8_t* private_key, size_t private_key_length);

/**
 * Succeeds if the encoded public key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_check_public_key(const uint8_t* group, size_t group_length, const uint8_t* public_key, size_t public_key_length);

/**
 * Writes the secret shared by the encoded private key and the peer's encoded public key into
 * `out` of the size of a shared secret; fails with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_dh_dh_agree(const uint8_t* group, size_t group_length, const uint8_t* private_key, size_t private_key_length, const uint8_t* public_key, size_t public_key_length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
