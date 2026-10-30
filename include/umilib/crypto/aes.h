/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_AES_H
#define UMILIB_CRYPTO_AES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AES-128 (FIPS 197): a 128-bit key and 10 rounds, bitsliced.
 */
typedef struct umilib_crypto_aes_AES128 umilib_crypto_aes_AES128;

/**
 * AES-192 (FIPS 197): a 192-bit key and 12 rounds, bitsliced.
 */
typedef struct umilib_crypto_aes_AES192 umilib_crypto_aes_AES192;

/**
 * AES-256 (FIPS 197): a 256-bit key and 14 rounds, bitsliced.
 */
typedef struct umilib_crypto_aes_AES256 umilib_crypto_aes_AES256;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes128_new(const uint8_t* key, size_t key_length, umilib_crypto_aes_AES128** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aes_aes128_free(umilib_crypto_aes_AES128* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes128_clone(const umilib_crypto_aes_AES128* cipher, umilib_crypto_aes_AES128** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes128_encrypt_blocks(const umilib_crypto_aes_AES128* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes128_decrypt_blocks(const umilib_crypto_aes_AES128* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aes_aes128_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aes_aes128_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aes_aes128_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes192_new(const uint8_t* key, size_t key_length, umilib_crypto_aes_AES192** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aes_aes192_free(umilib_crypto_aes_AES192* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes192_clone(const umilib_crypto_aes_AES192* cipher, umilib_crypto_aes_AES192** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes192_encrypt_blocks(const umilib_crypto_aes_AES192* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes192_decrypt_blocks(const umilib_crypto_aes_AES192* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aes_aes192_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aes_aes192_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aes_aes192_maximum_key_size(void);

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes256_new(const uint8_t* key, size_t key_length, umilib_crypto_aes_AES256** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_aes_aes256_free(umilib_crypto_aes_AES256* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes256_clone(const umilib_crypto_aes_AES256* cipher, umilib_crypto_aes_AES256** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes256_encrypt_blocks(const umilib_crypto_aes_AES256* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes256_decrypt_blocks(const umilib_crypto_aes_AES256* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_aes_aes256_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_aes_aes256_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_aes_aes256_maximum_key_size(void);

/**
 * Applies one round of the AES cipher (SubBytes, ShiftRows, MixColumns, AddRoundKey) to each
 * 16-byte block of the `length` bytes at `blocks` in place, with the key of the same position in
 * the `length` bytes at `keys`, which must not overlap `blocks`: AESRound of AEGIS.
 */
const umilib_ffi_Status* umilib_crypto_aes_aes_bitslice_round(uint8_t* blocks, const uint8_t* keys, size_t length);

#ifdef __cplusplus
}
#endif

#endif
