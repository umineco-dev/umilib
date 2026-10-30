/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_KBKDF_H
#define UMILIB_CRYPTO_KBKDF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * KBKDF (SP 800-108r1) over HMAC or CMAC chosen by name, with its counter size.
 */
typedef struct umilib_crypto_kbkdf_KBKDF umilib_crypto_kbkdf_KBKDF;

/**
 * Creates KBKDF (SP 800-108r1) over the PRF whose C type is named by the UTF-8 text at `prf`
 * (`umilib_crypto_hmac_HMAC` or `umilib_crypto_cmac_CMAC`), over the hash function or block cipher
 * whose C type is named by the UTF-8 text at `primitive`, keyed with K_IN at `key`, with a counter of
 * `counter_bits` bits (8, 16, 24 or 32); fails with InvalidArgument if the PRF or the primitive is
 * unknown or not enabled, and with InvalidParameter for another counter size.
 */
const umilib_ffi_Status* umilib_crypto_kbkdf_kbkdf_new(const uint8_t* prf, size_t prf_length, const uint8_t* primitive, size_t primitive_length, const uint8_t* key, size_t key_length, uint32_t counter_bits, umilib_crypto_kbkdf_KBKDF** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_kbkdf_kbkdf_free(umilib_crypto_kbkdf_KBKDF* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_kbkdf_kbkdf_clone(const umilib_crypto_kbkdf_KBKDF* state, umilib_crypto_kbkdf_KBKDF** out);

/**
 * Fills the `length` bytes at `out` in the counter mode (section 4.1), with the fixed input data
 * split around the counter: K(i) = PRF(before || \[i\] || after). The inputs must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_kbkdf_kbkdf_counter(const umilib_crypto_kbkdf_KBKDF* state, const uint8_t* before, size_t before_length, const uint8_t* after, size_t after_length, uint8_t* out, size_t length);

/**
 * Fills the `length` bytes at `out` in the feedback mode (section 4.2) from the initial value `iv`
 * and the fixed input data, with the counter at `location` (0 to 3). The inputs must not overlap
 * `out`.
 */
const umilib_ffi_Status* umilib_crypto_kbkdf_kbkdf_feedback(const umilib_crypto_kbkdf_KBKDF* state, const uint8_t* iv, size_t iv_length, const uint8_t* fixed, size_t fixed_length, uint32_t location, uint8_t* out, size_t length);

/**
 * Fills the `length` bytes at `out` in the double-pipeline mode (section 4.3) from the fixed input
 * data, with the counter at `location` (0 to 3), which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_kbkdf_kbkdf_double_pipeline(const umilib_crypto_kbkdf_KBKDF* state, const uint8_t* fixed, size_t fixed_length, uint32_t location, uint8_t* out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
