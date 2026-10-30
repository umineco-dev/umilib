/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_PBKDF2_H
#define UMILIB_CRYPTO_PBKDF2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fills the `length` bytes at `out` with PBKDF2 (RFC 8018 section 5.2) of the password and the salt
 * with `iterations` (at least 1) iterations of HMAC over the hash function whose C type is named by
 * the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with InvalidArgument if that
 * hash function is unknown or not enabled. The inputs must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_pbkdf2_pbkdf2_derive(const uint8_t* hash, size_t hash_length, const uint8_t* password, size_t password_length, const uint8_t* salt, size_t salt_length, uint32_t iterations, uint8_t* out, size_t length);

/**
 * Writes the longest output with the hash function named by `hash`, (2^32 - 1) × HashLen bytes,
 * into `out`.
 */
const umilib_ffi_Status* umilib_crypto_pbkdf2_pbkdf2_maximum_output(const uint8_t* hash, size_t hash_length, uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif
