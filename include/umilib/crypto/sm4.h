/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SM4_H
#define UMILIB_CRYPTO_SM4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SM4 (GB/T 32907-2016): a 128-bit key and 32 rounds.
 */
typedef struct umilib_crypto_sm4_SM4 umilib_crypto_sm4_SM4;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_sm4_sm4_new(const uint8_t* key, size_t key_length, umilib_crypto_sm4_SM4** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_sm4_sm4_free(umilib_crypto_sm4_SM4* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_sm4_sm4_clone(const umilib_crypto_sm4_SM4* cipher, umilib_crypto_sm4_SM4** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_sm4_sm4_encrypt_blocks(const umilib_crypto_sm4_SM4* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_sm4_sm4_decrypt_blocks(const umilib_crypto_sm4_SM4* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_sm4_sm4_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_sm4_sm4_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_sm4_sm4_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
