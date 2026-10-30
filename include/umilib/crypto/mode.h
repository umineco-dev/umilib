/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_H
#define UMILIB_CRYPTO_MODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the `length` bytes at `data` followed by their PKCS #7 padding for blocks of
 * `block_size` bytes (1 to 255) into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_pkcs7_pad(const uint8_t* data, size_t length, size_t block_size, umilib_ffi_Buffer* out);

/**
 * Writes into `out` the length of the `length` bytes at `data` without their PKCS #7 padding for
 * blocks of `block_size` bytes (1 to 255), checked in constant time; fails with InputLength unless
 * `data` is a whole number of blocks, at least one, and with InvalidParameter if the padding is not
 * valid.
 */
const umilib_ffi_Status* umilib_crypto_mode_pkcs7_unpad_length(const uint8_t* data, size_t length, size_t block_size, size_t* out);

#ifdef __cplusplus
}
#endif

#endif
