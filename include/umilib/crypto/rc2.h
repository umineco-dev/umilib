/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_RC2_H
#define UMILIB_CRYPTO_RC2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RC2 (RFC 2268): a key of 1 to 128 bytes and 64-bit blocks; _new takes 8 effective bits per key byte.
 */
typedef struct umilib_crypto_rc2_RC2 umilib_crypto_rc2_RC2;

/**
 * Creates the cipher with the `key_length` bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_rc2_rc2_new(const uint8_t* key, size_t key_length, umilib_crypto_rc2_RC2** out);

/**
 * Releases the cipher, zeroizing its round keys. Does nothing if `cipher` is null.
 */
void umilib_crypto_rc2_rc2_free(umilib_crypto_rc2_RC2* cipher);

/**
 * Writes a copy of `cipher` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_rc2_rc2_clone(const umilib_crypto_rc2_RC2* cipher, umilib_crypto_rc2_RC2** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_rc2_rc2_encrypt_blocks(const umilib_crypto_rc2_RC2* cipher, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, block by block.
 */
const umilib_ffi_Status* umilib_crypto_rc2_rc2_decrypt_blocks(const umilib_crypto_rc2_RC2* cipher, uint8_t* data, size_t length);

/**
 * The number of bytes of a block.
 */
size_t umilib_crypto_rc2_rc2_block_size(void);

/**
 * The shortest key in bytes.
 */
size_t umilib_crypto_rc2_rc2_minimum_key_size(void);

/**
 * The longest key in bytes.
 */
size_t umilib_crypto_rc2_rc2_maximum_key_size(void);

/**
 * Creates RC2 with the `key_length` bytes at `key` (1 to 128) and `effective_bits` effective key
 * bits (1 to 1024, RFC 2268 section 2).
 */
const umilib_ffi_Status* umilib_crypto_rc2_rc2_new_with_effective_bits(const uint8_t* key, size_t key_length, size_t effective_bits, umilib_crypto_rc2_RC2** out);

#ifdef __cplusplus
}
#endif

#endif
