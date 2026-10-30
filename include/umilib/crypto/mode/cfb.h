/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_CFB_H
#define UMILIB_CRYPTO_MODE_CFB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CFB with segments of a whole block over a block cipher chosen by name.
 */
typedef struct umilib_crypto_mode_cfb_CFB umilib_crypto_mode_cfb_CFB;

/**
 * CFB with 8-bit segments over a block cipher chosen by name.
 */
typedef struct umilib_crypto_mode_cfb_CFB8 umilib_crypto_mode_cfb_CFB8;

/**
 * CFB with 1-bit segments over a block cipher chosen by name.
 */
typedef struct umilib_crypto_mode_cfb_CFB1 umilib_crypto_mode_cfb_CFB1;

/**
 * Creates CFB over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
 * fails with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* iv, size_t iv_length, umilib_crypto_mode_cfb_CFB** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_mode_cfb_cfb_free(umilib_crypto_mode_cfb_CFB* state);

/**
 * Writes a copy of `state` into `out`; the copy continues from the same point of the data.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb_clone(const umilib_crypto_mode_cfb_CFB* state, umilib_crypto_mode_cfb_CFB** out);

/**
 * Encrypts the `length` bytes at `data` in place, continuing the stream.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb_encrypt(umilib_crypto_mode_cfb_CFB* state, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, continuing the stream.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb_decrypt(umilib_crypto_mode_cfb_CFB* state, uint8_t* data, size_t length);

/**
 * Creates CFB8 over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
 * fails with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb8_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* iv, size_t iv_length, umilib_crypto_mode_cfb_CFB8** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_mode_cfb_cfb8_free(umilib_crypto_mode_cfb_CFB8* state);

/**
 * Writes a copy of `state` into `out`; the copy continues from the same point of the data.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb8_clone(const umilib_crypto_mode_cfb_CFB8* state, umilib_crypto_mode_cfb_CFB8** out);

/**
 * Encrypts the `length` bytes at `data` in place, continuing the stream.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb8_encrypt(umilib_crypto_mode_cfb_CFB8* state, uint8_t* data, size_t length);

/**
 * Decrypts the `length` bytes at `data` in place, continuing the stream.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb8_decrypt(umilib_crypto_mode_cfb_CFB8* state, uint8_t* data, size_t length);

/**
 * Creates CFB1 over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
 * fails with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb1_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* iv, size_t iv_length, umilib_crypto_mode_cfb_CFB1** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_mode_cfb_cfb1_free(umilib_crypto_mode_cfb_CFB1* state);

/**
 * Writes a copy of `state` into `out`; the copy continues from the same point of the data.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb1_clone(const umilib_crypto_mode_cfb_CFB1* state, umilib_crypto_mode_cfb_CFB1** out);

/**
 * Encrypts the first `bits` bits (most significant first) of the `length` bytes at `data` in place.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb1_encrypt_bits(umilib_crypto_mode_cfb_CFB1* state, uint8_t* data, size_t length, size_t bits);

/**
 * Decrypts the first `bits` bits (most significant first) of the `length` bytes at `data` in place.
 */
const umilib_ffi_Status* umilib_crypto_mode_cfb_cfb1_decrypt_bits(umilib_crypto_mode_cfb_CFB1* state, uint8_t* data, size_t length, size_t bits);

#ifdef __cplusplus
}
#endif

#endif
