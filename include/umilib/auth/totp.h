/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_AUTH_TOTP_H
#define UMILIB_AUTH_TOTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An HOTP generator (RFC 4226).
 */
typedef struct umilib_auth_totp_HOTP umilib_auth_totp_HOTP;

/**
 * A TOTP generator (RFC 6238).
 */
typedef struct umilib_auth_totp_TOTP umilib_auth_totp_TOTP;

/**
 * The digits of a password, the time step in seconds and its origin (seconds of the Unix epoch).
 */
typedef struct umilib_auth_totp_TOTPConfig {
    uint32_t digits;
    uint64_t period;
    uint64_t origin;
} umilib_auth_totp_TOTPConfig;

/**
 * Writes an HOTP generator of the `key_length` bytes at `key` and passwords of `digits` digits
 * over the hash function whose C type is named by the UTF-8 text at `hash` (such as
 * `umilib_hash_sha_v1_SHA1`) into `out`; fails with InvalidArgument if that hash function is
 * unknown or not enabled, and with KeyTooShort, Digits or Hash.
 */
const umilib_ffi_Status* umilib_auth_totp_hotp_new(const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, uint32_t digits, umilib_auth_totp_HOTP** out);

/**
 * Releases a generator, zeroizing its key. Does nothing if `hotp` is null.
 */
void umilib_auth_totp_hotp_free(umilib_auth_totp_HOTP* hotp);

/**
 * Writes the ASCII digits of the password of `counter` into the `length` bytes at `out` (at
 * least 10 are always enough) and their number into `written`.
 */
const umilib_ffi_Status* umilib_auth_totp_hotp_generate(const umilib_auth_totp_HOTP* hotp, uint64_t counter, uint8_t* out, size_t length, size_t* written);

/**
 * Writes whether the `length` ASCII digits at `code` are the password of a counter from
 * `counter` to `counter + look_ahead` into `found`, and that counter into `matched`.
 */
const umilib_ffi_Status* umilib_auth_totp_hotp_verify(const umilib_auth_totp_HOTP* hotp, const uint8_t* code, size_t length, uint64_t counter, uint64_t look_ahead, bool* found, uint64_t* matched);

/**
 * Writes a TOTP generator of the `key_length` bytes at `key` and the parameters `config` over
 * the hash function named as in `umilib_auth_totp_hotp_new` into `out`; fails as it does, and
 * with Period.
 */
const umilib_ffi_Status* umilib_auth_totp_totp_new(const uint8_t* hash, size_t hash_length, const uint8_t* key, size_t key_length, umilib_auth_totp_TOTPConfig config, umilib_auth_totp_TOTP** out);

/**
 * Releases a generator, zeroizing its key. Does nothing if `totp` is null.
 */
void umilib_auth_totp_totp_free(umilib_auth_totp_TOTP* totp);

/**
 * Writes the time step of `time` (seconds of the Unix epoch) into `out`; fails with Time.
 */
const umilib_ffi_Status* umilib_auth_totp_totp_counter(const umilib_auth_totp_TOTP* totp, uint64_t time, uint64_t* out);

/**
 * Writes the ASCII digits of the password at `time` into the `length` bytes at `out` and their
 * number into `written`; fails with Time.
 */
const umilib_ffi_Status* umilib_auth_totp_totp_generate(const umilib_auth_totp_TOTP* totp, uint64_t time, uint8_t* out, size_t length, size_t* written);

/**
 * Writes whether the `length` ASCII digits at `code` are the password of a time step from
 * `behind` steps before that of `time` to `ahead` steps after it into `found`, and that step
 * into `matched`; fails with Time.
 */
const umilib_ffi_Status* umilib_auth_totp_totp_verify(const umilib_auth_totp_TOTP* totp, const uint8_t* code, size_t length, uint64_t time, uint64_t behind, uint64_t ahead, bool* found, uint64_t* matched);

#ifdef __cplusplus
}
#endif

#endif
