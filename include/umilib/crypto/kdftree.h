/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_KDFTREE_H
#define UMILIB_CRYPTO_KDFTREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * KDF_TREE (RFC 7836 section 4.4) over HMAC or CMAC chosen by name, with its counter size.
 */
typedef struct umilib_crypto_kdftree_KDFTree umilib_crypto_kdftree_KDFTree;

/**
 * Creates KDF_TREE (RFC 7836 section 4.4) over the PRF whose C type is named by the UTF-8 text at
 * `prf` (`umilib_crypto_hmac_HMAC` or `umilib_crypto_cmac_CMAC`), over the hash function or block
 * cipher whose C type is named by the UTF-8 text at `primitive` (Streebog-256 in RFC 7836), keyed with
 * K_in at `key`, with a counter of `counter_bytes` bytes (1 to 4); fails with InvalidArgument if the
 * PRF or the primitive is unknown or not enabled, and with InvalidParameter for another counter size.
 */
const umilib_ffi_Status* umilib_crypto_kdftree_kdftree_new(const uint8_t* prf, size_t prf_length, const uint8_t* primitive, size_t primitive_length, const uint8_t* key, size_t key_length, size_t counter_bytes, umilib_crypto_kdftree_KDFTree** out);

/**
 * Releases the state, zeroizing its key. Does nothing if `state` is null.
 */
void umilib_crypto_kdftree_kdftree_free(umilib_crypto_kdftree_KDFTree* state);

/**
 * Writes a copy of `state` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_kdftree_kdftree_clone(const umilib_crypto_kdftree_KDFTree* state, umilib_crypto_kdftree_KDFTree** out);

/**
 * Fills the `length` bytes (L = 8 × `length` bits) at `out` with the keying material of the label and
 * the seed, which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_kdftree_kdftree_derive(const umilib_crypto_kdftree_KDFTree* state, const uint8_t* label, size_t label_length, const uint8_t* seed, size_t seed_length, uint8_t* out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
