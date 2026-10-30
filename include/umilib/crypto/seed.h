/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SEED_H
#define UMILIB_CRYPTO_SEED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SEED (RFC 4269): a 128-bit key and 16 rounds.
 */
typedef struct umilib_crypto_seed_SEED umilib_crypto_seed_SEED;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_seed_seed_new(const uint8_t* key, size_t key_length, umilib_crypto_seed_SEED** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_seed_seed_free(umilib_crypto_seed_SEED* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_seed_seed_clone(const umilib_crypto_seed_SEED* cipher, umilib_crypto_seed_SEED** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_seed_seed_encrypt_blocks(const umilib_crypto_seed_SEED* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_seed_seed_decrypt_blocks(const umilib_crypto_seed_SEED* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_seed_seed_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_seed_seed_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_seed_seed_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
