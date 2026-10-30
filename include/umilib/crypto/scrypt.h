/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_SCRYPT_H
#define UMILIB_CRYPTO_SCRYPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The parameters N, r and p of scrypt (RFC 7914), checked when they are created.
 */
typedef struct umilib_crypto_scrypt_Scrypt umilib_crypto_scrypt_Scrypt;

/**
 * Creates scrypt with the cost N (a power of two above 1, below 2^(16r)), the block size r and the
 * parallelization p (r × p < 2^30); fails with InvalidParameter otherwise.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_new(uint64_t n, uint32_t r, uint32_t p, umilib_crypto_scrypt_Scrypt** out);

/**
 * Releases the parameters. Does nothing if `scrypt` is null.
 */
void umilib_crypto_scrypt_scrypt_free(umilib_crypto_scrypt_Scrypt* scrypt);

/**
 * Writes a copy of `scrypt` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_clone(const umilib_crypto_scrypt_Scrypt* scrypt, umilib_crypto_scrypt_Scrypt** out);

/**
 * Writes N into `out`.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_n(const umilib_crypto_scrypt_Scrypt* scrypt, uint64_t* out);

/**
 * Writes r into `out`.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_r(const umilib_crypto_scrypt_Scrypt* scrypt, uint32_t* out);

/**
 * Writes p into `out`.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_p(const umilib_crypto_scrypt_Scrypt* scrypt, uint32_t* out);

/**
 * Writes the bytes of memory a derivation allocates, 128 × r × (N + p), into `out`; a caller should
 * bound it before deriving with parameters it did not choose.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_memory(const umilib_crypto_scrypt_Scrypt* scrypt, umilib_ffi_U128* out);

/**
 * Fills the `length` bytes at `out` with scrypt (RFC 7914) of the password and the salt, which must
 * not overlap `out`; fails with Allocation if the memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_derive(const umilib_crypto_scrypt_Scrypt* scrypt, const uint8_t* password, size_t password_length, const uint8_t* salt, size_t salt_length, uint8_t* out, size_t length);

/**
 * Applies the Salsa20/8 core (RFC 7914 section 3) to the 16 little-endian words at `block`.
 */
const umilib_ffi_Status* umilib_crypto_scrypt_scrypt_salsa20_8(uint32_t* block);

#ifdef __cplusplus
}
#endif

#endif
