/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ASCON_H
#define UMILIB_CRYPTO_ASCON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Ascon-AEAD128 (SP 800-232): a 16-byte key, 16-byte nonces and tags of 4 to 16 bytes (16 recommended).
 */
typedef struct umilib_crypto_ascon_AsconAEAD128 umilib_crypto_ascon_AsconAEAD128;

/**
 * Creates Ascon-AEAD128 with tags of `tag_size` bytes (4 to 16) and the 16-byte key at `key`; nonces
 * have 16 bytes.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_new(size_t tag_size, const uint8_t* key, size_t key_length, umilib_crypto_ascon_AsconAEAD128** out);

/**
 * Creates Ascon-AEAD128 like `umilib_crypto_ascon_ascon_aead128_new`, with the 16-byte nonce mask at
 * `nonce_mask` (SP 800-232 section 4.2.2): the second half of a 32-byte key.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_with_nonce_mask(size_t tag_size, const uint8_t* key, size_t key_length, const uint8_t* nonce_mask, size_t nonce_mask_length, umilib_crypto_ascon_AsconAEAD128** out);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_ascon_ascon_aead128_free(umilib_crypto_ascon_AsconAEAD128* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_clone(const umilib_crypto_ascon_AsconAEAD128* aead, umilib_crypto_ascon_AsconAEAD128** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_nonce_size(const umilib_crypto_ascon_AsconAEAD128* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_tag_size(const umilib_crypto_ascon_AsconAEAD128* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_encrypt_in_place(const umilib_crypto_ascon_AsconAEAD128* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_ascon_ascon_aead128_decrypt_in_place(const umilib_crypto_ascon_AsconAEAD128* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

#ifdef __cplusplus
}
#endif

#endif
