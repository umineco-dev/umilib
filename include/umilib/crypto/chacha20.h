/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_CHACHA20_H
#define UMILIB_CRYPTO_CHACHA20_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ChaCha20 (RFC 8439): a stream cipher with a 32-byte key; it stops before the block counter wraps.
 */
typedef struct umilib_crypto_chacha20_ChaCha20 umilib_crypto_chacha20_ChaCha20;

/**
 * XChaCha20 (draft-irtf-cfrg-xchacha): ChaCha20 with 24-byte nonces, through HChaCha20.
 */
typedef struct umilib_crypto_chacha20_XChaCha20 umilib_crypto_chacha20_XChaCha20;

/**
 * Creates ChaCha20 (RFC 8439) with the 32-byte key at `key`, the 12-byte nonce at `nonce` and the
 * initial 32-bit block counter `counter`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_new(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint32_t counter, umilib_crypto_chacha20_ChaCha20** out);

/**
 * Creates the original ChaCha20 with the 32-byte key at `key`, the 8-byte nonce at `nonce` and the
 * initial 64-bit block counter `counter`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_with_64_bit_counter(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint64_t counter, umilib_crypto_chacha20_ChaCha20** out);

/**
 * Releases the cipher, zeroizing its state. Does nothing if `cipher` is null.
 */
void umilib_crypto_chacha20_chacha20_free(umilib_crypto_chacha20_ChaCha20* cipher);

/**
 * Writes a copy of `cipher` into `out`; the copy continues the same key stream.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_clone(const umilib_crypto_chacha20_ChaCha20* cipher, umilib_crypto_chacha20_ChaCha20** out);

/**
 * Xors the next `length` bytes of the key stream into the bytes at `data`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_apply_keystream(umilib_crypto_chacha20_ChaCha20* cipher, uint8_t* data, size_t length);

/**
 * Writes the bytes of key stream left before the counter wraps into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_remaining_bytes(const umilib_crypto_chacha20_ChaCha20* cipher, umilib_ffi_U128* out);

/**
 * Writes the state of RFC 8439 section 2.3 (constants, key, block counter, nonce) for the
 * 32-byte key at `key`, `counter` and the 12-byte nonce at `nonce` into the 16 words at `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_initial_state(const uint8_t* key, size_t key_length, uint32_t counter, const uint8_t* nonce, size_t nonce_length, uint32_t* out);

/**
 * Applies the quarter round to the words `a`, `b`, `c` and `d` (each below 16) of the 16 words at
 * `state`; fails with InvalidArgument for another index.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_quarter_round(uint32_t* state, size_t a, size_t b, size_t c, size_t d);

/**
 * Applies the 20 rounds to the 16 words at `state`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_rounds(uint32_t* state);

/**
 * Writes the 64-byte block of the 16 words at `state` (the rounds, then the addition of the
 * input state) into the `out_length` bytes at `out`, which must be 64.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_chacha20_block(const uint32_t* state, uint8_t* out, size_t out_length);

/**
 * Creates XChaCha20 with the 32-byte key at `key`, the 24-byte nonce at `nonce` and the initial
 * 32-bit block counter `counter`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_new(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint32_t counter, umilib_crypto_chacha20_XChaCha20** out);

/**
 * Creates XChaCha20 with the 64-bit block counter of the original ChaCha20 (libsodium), with the
 * 32-byte key at `key`, the 24-byte nonce at `nonce` and the initial counter `counter`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_with_64_bit_counter(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint64_t counter, umilib_crypto_chacha20_XChaCha20** out);

/**
 * Releases the cipher, zeroizing its state. Does nothing if `cipher` is null.
 */
void umilib_crypto_chacha20_xchacha20_free(umilib_crypto_chacha20_XChaCha20* cipher);

/**
 * Writes a copy of `cipher` into `out`; the copy continues the same key stream.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_clone(const umilib_crypto_chacha20_XChaCha20* cipher, umilib_crypto_chacha20_XChaCha20** out);

/**
 * Xors the next `length` bytes of the key stream into the bytes at `data`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_apply_keystream(umilib_crypto_chacha20_XChaCha20* cipher, uint8_t* data, size_t length);

/**
 * Writes the bytes of key stream left before the counter wraps into `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_remaining_bytes(const umilib_crypto_chacha20_XChaCha20* cipher, umilib_ffi_U128* out);

/**
 * Writes the subkey (HChaCha20 of the key and the first 16 bytes of the nonce) into the 32 bytes at
 * `out_key` and the ChaCha20 nonce (4 zero bytes, then the last 8 bytes of the nonce) into the 12
 * bytes at `out_nonce`, for the 32-byte key at `key` and the 24-byte nonce at `nonce`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_derive(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint8_t* out_key, size_t out_key_length, uint8_t* out_nonce, size_t out_nonce_length);

/**
 * Writes HChaCha20 of the 32-byte key at `key` and the 16-byte nonce at `nonce` into the 32 bytes
 * at `out`.
 */
const umilib_ffi_Status* umilib_crypto_chacha20_xchacha20_hchacha20(const uint8_t* key, size_t key_length, const uint8_t* nonce, size_t nonce_length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
