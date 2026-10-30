/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_RC4_H
#define UMILIB_CRYPTO_RC4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RC4: a stream cipher with keys of 1 to 256 bytes; broken (RFC 7465), for legacy data.
 */
typedef struct umilib_crypto_rc4_RC4 umilib_crypto_rc4_RC4;

/**
 * Creates RC4 with the key of 1 to 256 bytes at `key`.
 */
const umilib_ffi_Status* umilib_crypto_rc4_rc4_new(const uint8_t* key, size_t key_length, umilib_crypto_rc4_RC4** out);

/**
 * Releases the cipher, zeroizing its state. Does nothing if `cipher` is null.
 */
void umilib_crypto_rc4_rc4_free(umilib_crypto_rc4_RC4* cipher);

/**
 * Writes a copy of `cipher` into `out`; the copy continues the same key stream.
 */
const umilib_ffi_Status* umilib_crypto_rc4_rc4_clone(const umilib_crypto_rc4_RC4* cipher, umilib_crypto_rc4_RC4** out);

/**
 * Xors the next `length` bytes of the key stream into the bytes at `data`.
 */
const umilib_ffi_Status* umilib_crypto_rc4_rc4_apply_keystream(umilib_crypto_rc4_RC4* cipher, uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif

#endif
