/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CRYPTO_ARGON2_H
#define UMILIB_CRYPTO_ARGON2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The type and the parameters m, t and p of Argon2 (RFC 9106), version 0x13, checked when they are created.
 */
typedef struct umilib_crypto_argon2_Argon2 umilib_crypto_argon2_Argon2;

/**
 * Creates Argon2 of the type `variant` (0 Argon2d, 1 Argon2i, 2 Argon2id) with `memory` KiB (at
 * least 8 × `lanes`), `passes` passes (at least 1) and `lanes` lanes (1 to 2^24 - 1); fails with
 * InvalidArgument for another type and with InvalidParameter for other parameters.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_new(uint32_t variant, uint32_t memory, uint32_t passes, uint32_t lanes, umilib_crypto_argon2_Argon2** out);

/**
 * Releases the parameters. Does nothing if `argon2` is null.
 */
void umilib_crypto_argon2_argon2_free(umilib_crypto_argon2_Argon2* argon2);

/**
 * Writes a copy of `argon2` into `out`.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_clone(const umilib_crypto_argon2_Argon2* argon2, umilib_crypto_argon2_Argon2** out);

/**
 * Writes the type (0 Argon2d, 1 Argon2i, 2 Argon2id) into `out`.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_variant(const umilib_crypto_argon2_Argon2* argon2, uint32_t* out);

/**
 * Writes the number of blocks of memory, m' = 4p × ⌊m / 4p⌋, into `out`.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_blocks(const umilib_crypto_argon2_Argon2* argon2, uint32_t* out);

/**
 * Writes the bytes of memory a derivation allocates into `out`.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_memory_bytes(const umilib_crypto_argon2_Argon2* argon2, uint64_t* out);

/**
 * Fills the tag of `length` bytes (4 to 2^32 - 1) at `out` from the password, the salt, the optional
 * secret K and the optional associated data X (RFC 9106 section 3.2), which must not overlap `out`;
 * fails with Allocation if the memory cannot be allocated.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_derive(const umilib_crypto_argon2_Argon2* argon2, const uint8_t* password, size_t password_length, const uint8_t* salt, size_t salt_length, const uint8_t* secret, size_t secret_length, const uint8_t* associated, size_t associated_length, uint8_t* out, size_t length);

/**
 * Fills the `length` bytes (at least 1) at `out` with H' (RFC 9106 section 3.3) of the
 * concatenation of the `count` inputs (the `index`-th at `inputs[index]`, of
 * `input_lengths[index]` bytes), which must not overlap `out`.
 */
const umilib_ffi_Status* umilib_crypto_argon2_argon2_variable_hash(const uint8_t* const* inputs, const size_t* input_lengths, size_t count, uint8_t* out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
