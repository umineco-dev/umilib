/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_CAMELLIA_H
#define UMILIB_CRYPTO_CAMELLIA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Camellia with a 128-bit key (RFC 3713): 18 rounds.
 */
typedef struct umilib_crypto_camellia_Camellia128 umilib_crypto_camellia_Camellia128;

/**
 * Camellia with a 192-bit key (RFC 3713): 24 rounds.
 */
typedef struct umilib_crypto_camellia_Camellia192 umilib_crypto_camellia_Camellia192;

/**
 * Camellia with a 256-bit key (RFC 3713): 24 rounds.
 */
typedef struct umilib_crypto_camellia_Camellia256 umilib_crypto_camellia_Camellia256;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia128_new(const uint8_t* key, size_t key_length, umilib_crypto_camellia_Camellia128** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_camellia_camellia128_free(umilib_crypto_camellia_Camellia128* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia128_clone(const umilib_crypto_camellia_Camellia128* cipher, umilib_crypto_camellia_Camellia128** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia128_encrypt_blocks(const umilib_crypto_camellia_Camellia128* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia128_decrypt_blocks(const umilib_crypto_camellia_Camellia128* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_camellia_camellia128_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_camellia_camellia128_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_camellia_camellia128_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia192_new(const uint8_t* key, size_t key_length, umilib_crypto_camellia_Camellia192** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_camellia_camellia192_free(umilib_crypto_camellia_Camellia192* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia192_clone(const umilib_crypto_camellia_Camellia192* cipher, umilib_crypto_camellia_Camellia192** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia192_encrypt_blocks(const umilib_crypto_camellia_Camellia192* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia192_decrypt_blocks(const umilib_crypto_camellia_Camellia192* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_camellia_camellia192_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_camellia_camellia192_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_camellia_camellia192_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia256_new(const uint8_t* key, size_t key_length, umilib_crypto_camellia_Camellia256** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_camellia_camellia256_free(umilib_crypto_camellia_Camellia256* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia256_clone(const umilib_crypto_camellia_Camellia256* cipher, umilib_crypto_camellia_Camellia256** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia256_encrypt_blocks(const umilib_crypto_camellia_Camellia256* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_camellia_camellia256_decrypt_blocks(const umilib_crypto_camellia_Camellia256* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_camellia_camellia256_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_camellia_camellia256_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_camellia_camellia256_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
