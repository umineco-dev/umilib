/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_SIV_H
#define UMILIB_CRYPTO_MODE_SIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SIV (RFC 5297) over a 128-bit block cipher chosen by name: deterministic authenticated encryption, and an AEAD whose tag is V.
 */
typedef struct umilib_crypto_mode_siv_SIV umilib_crypto_mode_siv_SIV;

/**
 * Creates SIV over the 128-bit block cipher whose C type is named by the UTF-8 text at `cipher`,
 * such as `umilib_crypto_aes_AES128`, with K1 (of S2V) at `mac_key` and K2 (of CTR) at
 * `cipher_key`; fails with InvalidArgument if that cipher is unknown, not enabled or has another
 * block size.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* mac_key, size_t mac_key_length, const uint8_t* cipher_key, size_t cipher_key_length, umilib_crypto_mode_siv_SIV** out);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_mode_siv_siv_free(umilib_crypto_mode_siv_SIV* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_clone(const umilib_crypto_mode_siv_SIV* aead, umilib_crypto_mode_siv_SIV** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_nonce_size(const umilib_crypto_mode_siv_SIV* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_tag_size(const umilib_crypto_mode_siv_SIV* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_encrypt_in_place(const umilib_crypto_mode_siv_SIV* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_decrypt_in_place(const umilib_crypto_mode_siv_SIV* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes V, which authenticates them and the
 * `count` components of associated data (the `index`-th at `associated[index]`, of
 * `associated_lengths[index]` bytes; at most 126), into the `out_length` bytes at `out`, which
 * must be 16. The components must not overlap `buffer` or `siv`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_encrypt_vector_in_place(const umilib_crypto_mode_siv_SIV* siv, const uint8_t* const* associated, const size_t* associated_lengths, size_t count, uint8_t* buffer, size_t length, uint8_t* out, size_t out_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `v_length` bytes at `v` authenticate
 * them and the `count` components of associated data; otherwise fails with AuthenticationFailed
 * and leaves the ciphertext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_mode_siv_siv_decrypt_vector_in_place(const umilib_crypto_mode_siv_SIV* siv, const uint8_t* const* associated, const size_t* associated_lengths, size_t count, uint8_t* buffer, size_t length, const uint8_t* v, size_t v_length);

#ifdef __cplusplus
}
#endif

#endif
