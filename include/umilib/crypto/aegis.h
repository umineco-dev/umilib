/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_AEGIS_H
#define UMILIB_CRYPTO_AEGIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AEGIS-128X (draft-irtf-cfrg-aegis-aead) of degree 1 (AEGIS-128L), 2 or 4, with 16- or 32-byte tags: a 16-byte key and 16-byte nonces.
 */
typedef struct umilib_crypto_aegis_AEGIS128X umilib_crypto_aegis_AEGIS128X;

/**
 * The MAC of AEGIS-128X, of degree 1, 2 or 4, with 16- or 32-byte tags and a key and a nonce of 16 bytes.
 */
typedef struct umilib_crypto_aegis_AEGISMAC128X umilib_crypto_aegis_AEGISMAC128X;

/**
 * AEGIS-256X (draft-irtf-cfrg-aegis-aead) of degree 1 (AEGIS-256), 2 or 4, with 16- or 32-byte tags: a 32-byte key and 32-byte nonces.
 */
typedef struct umilib_crypto_aegis_AEGIS256X umilib_crypto_aegis_AEGIS256X;

/**
 * The MAC of AEGIS-256X, of degree 1, 2 or 4, with 16- or 32-byte tags and a key and a nonce of 32 bytes.
 */
typedef struct umilib_crypto_aegis_AEGISMAC256X umilib_crypto_aegis_AEGISMAC256X;

/**
 * Creates AEGIS-128X (AEGIS-128L for degree 1) of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes (16 or 32)
 * and the 16-byte key at `key`; nonces have 16 bytes.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_new(size_t degree, size_t tag_size, const uint8_t* key, size_t key_length, umilib_crypto_aegis_AEGIS128X** out);

/**
 * Writes the key stream of degree `degree` (1, 2 or 4) for the 16-byte key at `key` and
 * the 16-byte nonce at `nonce` into the `length` bytes at `out` (Stream, section 7), which
 * must not overlap them.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_stream(size_t degree, const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint8_t* out, size_t length);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_aegis_aegis128x_free(umilib_crypto_aegis_AEGIS128X* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_clone(const umilib_crypto_aegis_AEGIS128X* aead, umilib_crypto_aegis_AEGIS128X** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_nonce_size(const umilib_crypto_aegis_AEGIS128X* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_tag_size(const umilib_crypto_aegis_AEGIS128X* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_encrypt_in_place(const umilib_crypto_aegis_AEGIS128X* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis128x_decrypt_in_place(const umilib_crypto_aegis_AEGIS128X* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

/**
 * Creates the MAC of AEGIS-128X (AEGIS-128L for degree 1) of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes
 * (16 or 32), the 16-byte key at `key` and the 16-byte nonce at `nonce`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_new(size_t degree, size_t tag_size, const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, umilib_crypto_aegis_AEGISMAC128X** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_aegis_aegis_mac128x_free(umilib_crypto_aegis_AEGISMAC128X* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_clone(const umilib_crypto_aegis_AEGISMAC128X* state, umilib_crypto_aegis_AEGISMAC128X** out);

/**
 * Writes the output size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_output_size(const umilib_crypto_aegis_AEGISMAC128X* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the message.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_update(umilib_crypto_aegis_AEGISMAC128X* state, const uint8_t* data, size_t length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_finalize(umilib_crypto_aegis_AEGISMAC128X* state, uint8_t* out, size_t out_length);

/**
 * Returns to the state after the key.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_reset(umilib_crypto_aegis_AEGISMAC128X* state);

/**
 * Writes into `out` whether the `tag_length` bytes at `tag` are the tag of the message,
 * compared in constant time, and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac128x_verify(umilib_crypto_aegis_AEGISMAC128X* state, const uint8_t* tag, size_t tag_length, bool* out);

/**
 * Creates AEGIS-256X (AEGIS-256 for degree 1) of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes (16 or 32)
 * and the 32-byte key at `key`; nonces have 32 bytes.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_new(size_t degree, size_t tag_size, const uint8_t* key, size_t key_length, umilib_crypto_aegis_AEGIS256X** out);

/**
 * Writes the key stream of degree `degree` (1, 2 or 4) for the 32-byte key at `key` and
 * the 32-byte nonce at `nonce` into the `length` bytes at `out` (Stream, section 7), which
 * must not overlap them.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_stream(size_t degree, const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint8_t* out, size_t length);

/**
 * Releases the AEAD, zeroizing its key. Does nothing if `aead` is null.
 */
void umilib_crypto_aegis_aegis256x_free(umilib_crypto_aegis_AEGIS256X* aead);

/**
 * Writes a copy of `aead` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_clone(const umilib_crypto_aegis_AEGIS256X* aead, umilib_crypto_aegis_AEGIS256X** out);

/**
 * Writes the recommended nonce size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_nonce_size(const umilib_crypto_aegis_AEGIS256X* aead, size_t* out);

/**
 * Writes the tag size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_tag_size(const umilib_crypto_aegis_AEGIS256X* aead, size_t* out);

/**
 * Encrypts the `length` bytes at `buffer` in place and writes the tag into the `tag_length`
 * bytes at `tag`, which must be the tag size. The nonce and the associated data must not
 * overlap `buffer` or `tag`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_encrypt_in_place(const umilib_crypto_aegis_AEGIS256X* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, uint8_t* tag, size_t tag_length);

/**
 * Decrypts the `length` bytes at `buffer` in place if the `tag_length` bytes at `tag`
 * authenticate them and the associated data; otherwise fails with AuthenticationFailed and
 * leaves no plaintext in `buffer`. The other inputs must not overlap `buffer`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis256x_decrypt_in_place(const umilib_crypto_aegis_AEGIS256X* aead, const uint8_t* nonce, size_t nonce_length, const uint8_t* associated, size_t associated_length, uint8_t* buffer, size_t length, const uint8_t* tag, size_t tag_length);

/**
 * Creates the MAC of AEGIS-256X (AEGIS-256 for degree 1) of degree `degree` (1, 2 or 4) with tags of `tag_size` bytes
 * (16 or 32), the 32-byte key at `key` and the 32-byte nonce at `nonce`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_new(size_t degree, size_t tag_size, const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, umilib_crypto_aegis_AEGISMAC256X** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_aegis_aegis_mac256x_free(umilib_crypto_aegis_AEGISMAC256X* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_clone(const umilib_crypto_aegis_AEGISMAC256X* state, umilib_crypto_aegis_AEGISMAC256X** out);

/**
 * Writes the output size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_output_size(const umilib_crypto_aegis_AEGISMAC256X* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the message.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_update(umilib_crypto_aegis_AEGISMAC256X* state, const uint8_t* data, size_t length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_finalize(umilib_crypto_aegis_AEGISMAC256X* state, uint8_t* out, size_t out_length);

/**
 * Returns to the state after the key.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_reset(umilib_crypto_aegis_AEGISMAC256X* state);

/**
 * Writes into `out` whether the `tag_length` bytes at `tag` are the tag of the message,
 * compared in constant time, and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_aegis_aegis_mac256x_verify(umilib_crypto_aegis_AEGISMAC256X* state, const uint8_t* tag, size_t tag_length, bool* out);

#ifdef __cplusplus
}
#endif

#endif
