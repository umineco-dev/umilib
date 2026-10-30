/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_DES_H
#define UMILIB_CRYPTO_DES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DES (SP 800-67r2 section 2): a 64-bit key of 56 bits and 64-bit blocks; broken, for legacy data.
 */
typedef struct umilib_crypto_des_DES umilib_crypto_des_DES;

/**
 * Triple DES (SP 800-67r2 section 3): a bundle of three keys (24 bytes) or two (16 bytes, Key3 = Key1); Key1 = Key2 or Key2 = Key3 is refused.
 */
typedef struct umilib_crypto_des_TDES umilib_crypto_des_TDES;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_des_des_new(const uint8_t* key, size_t key_length, umilib_crypto_des_DES** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_des_des_free(umilib_crypto_des_DES* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_des_des_clone(const umilib_crypto_des_DES* cipher, umilib_crypto_des_DES** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_des_des_encrypt_blocks(const umilib_crypto_des_DES* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_des_des_decrypt_blocks(const umilib_crypto_des_DES* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_des_des_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_des_des_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_des_des_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_des_tdes_new(const uint8_t* key, size_t key_length, umilib_crypto_des_TDES** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_des_tdes_free(umilib_crypto_des_TDES* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_des_tdes_clone(const umilib_crypto_des_TDES* cipher, umilib_crypto_des_TDES** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_des_tdes_encrypt_blocks(const umilib_crypto_des_TDES* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_des_tdes_decrypt_blocks(const umilib_crypto_des_TDES* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_des_tdes_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_des_tdes_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_des_tdes_maximum_key_size(void);

/**
 * Writes into `out` whether the 8 bytes at `key` are a weak, semi-weak or possibly weak DES key
 * (SP 800-67r2 section 3.3.2), ignoring the parity bits; fails with KeyLength for another length.
 */
const umilib_ffi_Status* umilib_crypto_des_des_is_weak(const uint8_t* key, size_t key_length, bool* out);

#ifdef __cplusplus
}
#endif

#endif
