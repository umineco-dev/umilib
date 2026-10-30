/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_CMAC_H
#define UMILIB_CRYPTO_CMAC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CMAC (SP 800-38B) over a block cipher chosen by name.
 */
typedef struct umilib_crypto_cmac_CMAC umilib_crypto_cmac_CMAC;

/**
 * Creates CMAC over the block cipher whose C type is named by the UTF-8 text at `cipher`, such as
 * `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key`; fails with InvalidArgument if
 * that cipher is unknown or not enabled.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_new(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, umilib_crypto_cmac_CMAC** out);

/**
 * Releases the state, zeroizing it. Does nothing if `state` is null.
 */
void umilib_crypto_cmac_cmac_free(umilib_crypto_cmac_CMAC* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_clone(const umilib_crypto_cmac_CMAC* state, umilib_crypto_cmac_CMAC** out);

/**
 * Writes the output size into `out`.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_output_size(const umilib_crypto_cmac_CMAC* state, size_t* out);

/**
 * Adds the `length` bytes at `data` to the message.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_update(umilib_crypto_cmac_CMAC* state, const uint8_t* data, size_t length);

/**
 * Writes the tag into the `out_length` bytes at `out`, which must be the output size, and
 * releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_finalize(umilib_crypto_cmac_CMAC* state, uint8_t* out, size_t out_length);

/**
 * Returns to the state after the key.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_reset(umilib_crypto_cmac_CMAC* state);

/**
 * Writes into `out` whether the `tag_length` bytes at `tag` are the tag of the message,
 * compared in constant time, and releases the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_verify(umilib_crypto_cmac_CMAC* state, const uint8_t* tag, size_t tag_length, bool* out);

/**
 * Writes into `out` whether the `tag_length` bytes at `tag` are the leftmost bytes (at least 8, or
 * the whole block if shorter) of the tag of the message, compared in constant time, and releases
 * the state. On failure the state is not released.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_verify_truncated(umilib_crypto_cmac_CMAC* state, const uint8_t* tag, size_t tag_length, bool* out);

/**
 * Like `umilib_crypto_cmac_cmac_verify_truncated` with tags of at least `minimum` bytes (and one);
 * SP 800-38B appendix A.2 allows tags shorter than 8 bytes only where the protocol limits the
 * failed verifications per key.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_verify_truncated_with_minimum(umilib_crypto_cmac_CMAC* state, const uint8_t* tag, size_t tag_length, size_t minimum, bool* out);

/**
 * Writes the tag of the `length` bytes at `data` with the cipher named by `cipher` and the key into
 * the `out_length` bytes at `out`, which must be the block size and must not overlap the inputs.
 */
const umilib_ffi_Status* umilib_crypto_cmac_cmac_mac(const uint8_t* cipher, size_t cipher_length, const uint8_t* key, size_t key_length, const uint8_t* data, size_t length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
