/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_GOST_MAGMA_H
#define UMILIB_CRYPTO_GOST_MAGMA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Magma (GOST R 34.12-2015, RFC 8891): a 256-bit key and 64-bit blocks.
 */
typedef struct umilib_crypto_gost_magma_Magma umilib_crypto_gost_magma_Magma;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_gost_magma_magma_new(const uint8_t* key, size_t key_length, umilib_crypto_gost_magma_Magma** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_gost_magma_magma_free(umilib_crypto_gost_magma_Magma* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_gost_magma_magma_clone(const umilib_crypto_gost_magma_Magma* cipher, umilib_crypto_gost_magma_Magma** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_gost_magma_magma_encrypt_blocks(const umilib_crypto_gost_magma_Magma* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_gost_magma_magma_decrypt_blocks(const umilib_crypto_gost_magma_Magma* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_gost_magma_magma_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_gost_magma_magma_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_gost_magma_magma_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
