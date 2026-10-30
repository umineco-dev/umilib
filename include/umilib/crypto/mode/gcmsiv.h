/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_GCMSIV_H
#define UMILIB_CRYPTO_MODE_GCMSIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AES-GCM-SIV (RFC 8452) over a 128-bit block cipher chosen by name: nonce-misuse-resistant, with 12-byte nonces and 16-byte tags.
 */
typedef struct umilib_crypto_mode_gcmsiv_GCMSIV umilib_crypto_mode_gcmsiv_GCMSIV;

/**
 * Creates GCM-SIV over the 128-bit block cipher whose C type is named by the UTF-8 text at
 * `cipher`, such as `umilib_crypto_aes_AES128`, with the key-generating key of `key_length` bytes
 * (16 or 32, a key length of the cipher) at `key`; fails with InvalidArgument if that cipher is unknown, not enabled or has
 * another block size.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, umilib_crypto_mode_gcmsiv_GCMSIV** out);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_mode_gcmsiv_gcmsiv_free(umilib_crypto_mode_gcmsiv_GCMSIV* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_clone(const umilib_crypto_mode_gcmsiv_GCMSIV* aead, umilib_crypto_mode_gcmsiv_GCMSIV** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_nonce_size(const umilib_crypto_mode_gcmsiv_GCMSIV* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_tag_size(const umilib_crypto_mode_gcmsiv_GCMSIV* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_encrypt_in_place(const umilib_crypto_mode_gcmsiv_GCMSIV* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_mode_gcmsiv_gcmsiv_decrypt_in_place(const umilib_crypto_mode_gcmsiv_GCMSIV* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

#ifdef __cplusplus
}
#endif

#endif
