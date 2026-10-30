/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_CBC_H
#define UMILIB_CRYPTO_MODE_CBC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CBC over a block cipher chosen by name, chaining across calls.
 */
typedef struct umilib_crypto_mode_cbc_CBC umilib_crypto_mode_cbc_CBC;

/**
 * Creates CBC over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
 * fails with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_cbc_cbc_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* iv, size_t iv_length, umilib_crypto_mode_cbc_CBC** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_mode_cbc_cbc_free(umilib_crypto_mode_cbc_CBC* state);

/**
 * Writes a copy of `state` into `out`; the copy continues from the same point of the data.
 */
const umilib_ffi_Status* umilib_crypto_mode_cbc_cbc_clone(const umilib_crypto_mode_cbc_CBC* state, umilib_crypto_mode_cbc_CBC** out);

/**
 * Encrypts the `length` bytes at `data` in place, a whole number of blocks, continuing the chain.
 */
const umilib_ffi_Status* umilib_crypto_mode_cbc_cbc_encrypt(umilib_crypto_mode_cbc_CBC* state, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, a whole number of blocks, continuing the chain.
 */
const umilib_ffi_Status* umilib_crypto_mode_cbc_cbc_decrypt(umilib_crypto_mode_cbc_CBC* state, uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
