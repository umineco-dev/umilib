/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_CHACHA20POLY1305_H
#define UMILIB_CRYPTO_CHACHA20POLY1305_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ChaCha20-Poly1305 (RFC 8439): a 32-byte key, 12-byte nonces and 16-byte tags.
 */
typedef struct umilib_crypto_chacha20poly1305_ChaCha20Poly1305 umilib_crypto_chacha20poly1305_ChaCha20Poly1305;

/**
 * XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): a 32-byte key, 24-byte nonces and 16-byte tags.
 */
typedef struct umilib_crypto_chacha20poly1305_XChaCha20Poly1305 umilib_crypto_chacha20poly1305_XChaCha20Poly1305;

/**
 * Creates ChaCha20-Poly1305 (RFC 8439) with the 32-byte key at `key`; nonces have 12 bytes.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_new(const uint8_t* key, size_t key_length, umilib_crypto_chacha20poly1305_ChaCha20Poly1305** out);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_chacha20poly1305_chacha20poly1305_free(umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_clone(const umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead, umilib_crypto_chacha20poly1305_ChaCha20Poly1305** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_nonce_size(const umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_tag_size(const umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_encrypt_in_place(const umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_chacha20poly1305_decrypt_in_place(const umilib_crypto_chacha20poly1305_ChaCha20Poly1305* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

/**
 * Creates XChaCha20-Poly1305 with the 32-byte key at `key`; nonces have 24 bytes, enough to be
 * chosen at random.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_new(const uint8_t* key, size_t key_length, umilib_crypto_chacha20poly1305_XChaCha20Poly1305** out);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_chacha20poly1305_xchacha20poly1305_free(umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_clone(const umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead, umilib_crypto_chacha20poly1305_XChaCha20Poly1305** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_nonce_size(const umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_tag_size(const umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_encrypt_in_place(const umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20poly1305_xchacha20poly1305_decrypt_in_place(const umilib_crypto_chacha20poly1305_XChaCha20Poly1305* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

#ifdef __cplusplus
}
#endif

#endif
