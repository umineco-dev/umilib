/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_MODE_KW_H
#define UMILIB_CRYPTO_MODE_KW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * AES Key Wrap (SP 800-38F, RFC 3394), TKW over a cipher of 64-bit blocks.
 */
typedef struct umilib_crypto_mode_kw_KW umilib_crypto_mode_kw_KW;

/**
 * AES Key Wrap with Padding (SP 800-38F, RFC 5649).
 */
typedef struct umilib_crypto_mode_kw_KWP umilib_crypto_mode_kw_KWP;

/**
 * Creates KW (TKW for a cipher of 64-bit blocks) over the cipher whose C type is named by the UTF-8
 * text at `cipher`, such as `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key`; fails
 * with InvalidArgument if that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kw_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, umilib_crypto_mode_kw_KW** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_mode_kw_kw_free(umilib_crypto_mode_kw_KW* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kw_clone(const umilib_crypto_mode_kw_KW* state, umilib_crypto_mode_kw_KW** out);

/**
 * Writes the wrapping of the `length` bytes at `key` (whole semiblocks, at least two) into `out`,
 * one semiblock longer.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kw_wrap(const umilib_crypto_mode_kw_KW* state, const uint8_t* key, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the key the `length` bytes at `wrapped` hold into `out`; fails with AuthenticationFailed if
 * the integrity check fails.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kw_unwrap(const umilib_crypto_mode_kw_KW* state, const uint8_t* wrapped, size_t length, umilib_ffi_Buffer* out);

/**
 * Creates KWP over the cipher of 128-bit blocks whose C type is named by the UTF-8 text at `cipher`,
 * with the `key_length` bytes at `key`; fails with InvalidArgument if that cipher is unknown, not
 * enabled, or of 64-bit blocks.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kwp_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, umilib_crypto_mode_kw_KWP** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_mode_kw_kwp_free(umilib_crypto_mode_kw_KWP* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kwp_clone(const umilib_crypto_mode_kw_KWP* state, umilib_crypto_mode_kw_KWP** out);

/**
 * Writes the wrapping of the `length` bytes at `key` (1 to 2^32 − 1 bytes) into `out`.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kwp_wrap(const umilib_crypto_mode_kw_KWP* state, const uint8_t* key, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the key the `length` bytes at `wrapped` hold into `out`; fails with AuthenticationFailed if
 * the integrity value, the length or the padding is wrong.
 */
const umilib_ffi_Status* umilib_crypto_mode_kw_kwp_unwrap(const umilib_crypto_mode_kw_KWP* state, const uint8_t* wrapped, size_t length, umilib_ffi_Buffer* out);

#ifdef __cplusplus
}
#endif

#endif
