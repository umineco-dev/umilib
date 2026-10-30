/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ARIA_H
#define UMILIB_CRYPTO_ARIA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ARIA-128 (RFC 5794): a 128-bit key and 12 rounds.
 */
typedef struct umilib_crypto_aria_ARIA128 umilib_crypto_aria_ARIA128;

/**
 * ARIA-192 (RFC 5794): a 192-bit key and 14 rounds.
 */
typedef struct umilib_crypto_aria_ARIA192 umilib_crypto_aria_ARIA192;

/**
 * ARIA-256 (RFC 5794): a 256-bit key and 16 rounds.
 */
typedef struct umilib_crypto_aria_ARIA256 umilib_crypto_aria_ARIA256;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria128_new(const uint8_t* key, size_t key_length, umilib_crypto_aria_ARIA128** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aria_aria128_free(umilib_crypto_aria_ARIA128* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria128_clone(const umilib_crypto_aria_ARIA128* cipher, umilib_crypto_aria_ARIA128** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria128_encrypt_blocks(const umilib_crypto_aria_ARIA128* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria128_decrypt_blocks(const umilib_crypto_aria_ARIA128* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aria_aria128_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aria_aria128_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aria_aria128_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria192_new(const uint8_t* key, size_t key_length, umilib_crypto_aria_ARIA192** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aria_aria192_free(umilib_crypto_aria_ARIA192* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria192_clone(const umilib_crypto_aria_ARIA192* cipher, umilib_crypto_aria_ARIA192** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria192_encrypt_blocks(const umilib_crypto_aria_ARIA192* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria192_decrypt_blocks(const umilib_crypto_aria_ARIA192* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aria_aria192_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aria_aria192_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aria_aria192_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria256_new(const uint8_t* key, size_t key_length, umilib_crypto_aria_ARIA256** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aria_aria256_free(umilib_crypto_aria_ARIA256* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria256_clone(const umilib_crypto_aria_ARIA256* cipher, umilib_crypto_aria_ARIA256** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria256_encrypt_blocks(const umilib_crypto_aria_ARIA256* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aria_aria256_decrypt_blocks(const umilib_crypto_aria_ARIA256* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aria_aria256_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aria_aria256_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aria_aria256_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
