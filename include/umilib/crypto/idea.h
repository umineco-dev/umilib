/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_IDEA_H
#define UMILIB_CRYPTO_IDEA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IDEA: a 128-bit key, 64-bit blocks and 8.5 rounds.
 */
typedef struct umilib_crypto_idea_IDEA umilib_crypto_idea_IDEA;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_idea_idea_new(const uint8_t* key, size_t key_length, umilib_crypto_idea_IDEA** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_idea_idea_free(umilib_crypto_idea_IDEA* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_idea_idea_clone(const umilib_crypto_idea_IDEA* cipher, umilib_crypto_idea_IDEA** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_idea_idea_encrypt_blocks(const umilib_crypto_idea_IDEA* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_idea_idea_decrypt_blocks(const umilib_crypto_idea_IDEA* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_idea_idea_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_idea_idea_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_idea_idea_maximum_key_size(void);

#ifdef __cplusplus
}
#endif

#endif
