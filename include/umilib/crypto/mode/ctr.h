/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_CTR_H
#define UMILIB_CRYPTO_MODE_CTR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CTR over a block cipher chosen by name: a stream cipher that refuses to repeat its counter.
 */
typedef struct umilib_crypto_mode_ctr_CTR umilib_crypto_mode_ctr_CTR;

/**
 * Creates CTR over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the initial counter block at `initial`;
 * fails with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_ctr_ctr_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* initial, size_t initial_length, umilib_crypto_mode_ctr_CTR** out);

/**
 * Creates CTR as `umilib_crypto_mode_ctr_ctr_new`, with only the last `counter_bits` bits (1 to 8 × the block size)
 * of the initial block counting.
 */
const umilib_ffi_Status* umilib_crypto_mode_ctr_ctr_with_counter_bits(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* initial, size_t initial_length, uint32_t counter_bits, umilib_crypto_mode_ctr_CTR** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_mode_ctr_ctr_free(umilib_crypto_mode_ctr_CTR* state);

/**
 * Writes a copy of `state` into `out`; the copy continues from the same point of the data.
 */
const umilib_ffi_Status* umilib_crypto_mode_ctr_ctr_clone(const umilib_crypto_mode_ctr_CTR* state, umilib_crypto_mode_ctr_CTR** out);

/**
 * Xors the next `length` bytes of the key stream into the bytes at `data`; fails with LimitExceeded, changing nothing, if the counter would wrap.
 */
const umilib_ffi_Status* umilib_crypto_mode_ctr_ctr_apply_keystream(umilib_crypto_mode_ctr_CTR* state, uint8_t* data, size_t length);

/**
 * Writes into `has_value` whether the bytes of key stream left before the counter runs out fit in
 * 128 bits (not for counters of 124 bits or more with 16-byte blocks) and, if so, that number into
 * `out` (0 otherwise).
 */
const umilib_ffi_Status* umilib_crypto_mode_ctr_ctr_remaining_bytes(const umilib_crypto_mode_ctr_CTR* state, bool* has_value, umilib_ffi_U128* out);

#ifdef __cplusplus
}
#endif

#endif
