/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_XTS_H
#define UMILIB_CRYPTO_MODE_XTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * XTS over a 128-bit block cipher chosen by name, for data units such as disk sectors.
 */
typedef struct umilib_crypto_mode_xts_XTS umilib_crypto_mode_xts_XTS;

/**
 * Creates XTS over the 128-bit block cipher whose C type is named by the UTF-8 text at `cipher`,
 * such as `umilib_crypto_aes_AES128`, with the data key at `data_key` and the tweak key at
 * `tweak_key`, which must have the same length and differ; fails with InvalidArgument if that
 * cipher is unknown, not enabled or has another block size.
 */
const umilib_ffi_Status* umilib_crypto_mode_xts_xts_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* data_key, size_t data_key_length, const uint8_t* tweak_key, size_t tweak_key_length, umilib_crypto_mode_xts_XTS** out);

/**
 * Releases the state, zeroizing its keys. Does nothing if `xts` is null.
 */
void umilib_crypto_mode_xts_xts_free(umilib_crypto_mode_xts_XTS* xts);

/**
 * Writes a copy of `xts` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_xts_xts_clone(const umilib_crypto_mode_xts_XTS* xts, umilib_crypto_mode_xts_XTS** out);

/**
 * Encrypts the data unit of `length` bytes (16 bytes to 2^20 blocks) at `data` in place under the 16-byte
 * tweak at `tweak`, which must not overlap it.
 */
const umilib_ffi_Status* umilib_crypto_mode_xts_xts_encrypt(const umilib_crypto_mode_xts_XTS* xts, const uint8_t* tweak, size_t tweak_length, uint8_t* data, size_t length);

/**
 * Decrypts the data unit of `length` bytes (16 bytes to 2^20 blocks) at `data` in place under the 16-byte
 * tweak at `tweak`, which must not overlap it.
 */
const umilib_ffi_Status* umilib_crypto_mode_xts_xts_decrypt(const umilib_crypto_mode_xts_XTS* xts, const uint8_t* tweak, size_t tweak_length, uint8_t* data, size_t length);

/**
 * Writes the 16-byte tweak of data unit number `unit` (its little-endian encoding) into the
 * `length` bytes at `out`, which must be 16.
 */
const umilib_ffi_Status* umilib_crypto_mode_xts_xts_tweak_of(umilib_ffi_U128 unit, uint8_t* out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
