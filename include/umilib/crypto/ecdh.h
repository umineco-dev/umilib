/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ECDH_H
#define UMILIB_CRYPTO_ECDH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of a private key, a public key and a shared secret of ECDH on the curve named by `curve` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_sizes(const uint8_t* curve, size_t curve_length, size_t* sizes);

/**
 * Generates a private key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a private key.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_generate(const uint8_t* curve, size_t curve_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the public key of the encoded private key into `out` of the size of a public key.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_public_key(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded private key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_check_private_key(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length);

/**
 * Succeeds if the encoded public key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_check_public_key(const uint8_t* curve, size_t curve_length, const uint8_t* public_key, size_t public_key_length);

/**
 * Writes the secret shared by the encoded private key and the peer's encoded public key into
 * `out` of the size of a shared secret; fails with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_ecdh_agree(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length, const uint8_t* public_key, size_t public_key_length, uint8_t* out, size_t out_length);

/**
 * Writes the sizes in bytes of a private key, a public key and a shared secret of XDH on the curve named by `curve` into
 * `sizes` (three elements); fails with InvalidArgument for names that are unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_sizes(const uint8_t* curve, size_t curve_length, size_t* sizes);

/**
 * Generates a private key from the generator handle `random`, whose C type is named by the UTF-8
 * text at `random_type` (such as `umilib_crypto_random_HMACDRBG`), and writes its encoding into
 * `out` of the size of a private key.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_generate(const uint8_t* curve, size_t curve_length, void* random, const uint8_t* random_type, size_t random_type_length, uint8_t* out, size_t out_length);

/**
 * Writes the public key of the encoded private key into `out` of the size of a public key.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_public_key(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length, uint8_t* out, size_t out_length);

/**
 * Succeeds if the encoded private key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_check_private_key(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length);

/**
 * Succeeds if the encoded public key is valid; fails with InvalidKey otherwise.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_check_public_key(const uint8_t* curve, size_t curve_length, const uint8_t* public_key, size_t public_key_length);

/**
 * Writes the secret shared by the encoded private key and the peer's encoded public key into
 * `out` of the size of a shared secret; fails with InvalidKey for a key the scheme refuses.
 */
const umilib_ffi_Status* umilib_crypto_ecdh_xdh_agree(const uint8_t* curve, size_t curve_length, const uint8_t* private_key, size_t private_key_length, const uint8_t* public_key, size_t public_key_length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
