/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_SECRET_H
#define UMILIB_SECRET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bytes that are zeroized when released.
 */
typedef struct umilib_secret_Secret umilib_secret_Secret;

/**
 * Keeps the data-independent timing mode set for the thread that created it.
 */
typedef struct umilib_secret_DataIndependentTiming umilib_secret_DataIndependentTiming;

/**
 * A table of 256 entries of 8 bits whose reads and writes take the same time for every index.
 */
typedef struct umilib_secret_ConstantTimeTable32_8 umilib_secret_ConstantTimeTable32_8;

/**
 * Returns the lowest bit of `bit` as a choice.
 */
uint8_t umilib_secret_choice_from_bit(uint8_t bit);

/**
 * Returns the logical AND of two choices.
 */
uint8_t umilib_secret_choice_and(uint8_t a, uint8_t b);

/**
 * Returns the logical OR of two choices.
 */
uint8_t umilib_secret_choice_or(uint8_t a, uint8_t b);

/**
 * Returns the logical XOR of two choices.
 */
uint8_t umilib_secret_choice_xor(uint8_t a, uint8_t b);

/**
 * Returns the logical NOT of a choice.
 */
uint8_t umilib_secret_choice_not(uint8_t choice);

/**
 * Reveals a choice as a boolean.
 */
bool umilib_secret_choice_into_bool(uint8_t choice);

/**
 * Compares two byte sequences in time that depends only on their lengths
 * and writes the resulting choice into `out`.
 */
const umilib_ffi_Status* umilib_secret_constant_time_eq_ct_eq(const uint8_t* a, size_t a_length, const uint8_t* b, size_t b_length, uint8_t* out);

/**
 * Like `umilib_secret_constant_time_eq_ct_eq`, but writes whether the sequences differ.
 */
const umilib_ffi_Status* umilib_secret_constant_time_eq_ct_ne(const uint8_t* a, size_t a_length, const uint8_t* b, size_t b_length, uint8_t* out);

/**
 * Writes `a` into `out` if `choice` is 0 and `b` if it is 1; all three hold `length` bytes.
 * `out` may be `a` or `b`; partially overlapping ranges are rejected.
 */
const umilib_ffi_Status* umilib_secret_conditionally_selectable_select(const uint8_t* a, const uint8_t* b, size_t length, uint8_t choice, uint8_t* out);

/**
 * Overwrites the `length` bytes at `target` with those at `source` if `choice` is 1.
 * `target` may be `source`; partially overlapping ranges are rejected.
 */
const umilib_ffi_Status* umilib_secret_conditionally_selectable_conditional_assign(uint8_t* target, const uint8_t* source, size_t length, uint8_t choice);

/**
 * Swaps the `length` bytes at `a` and `b` if `choice` is 1.
 * `a` may be `b`; partially overlapping ranges are rejected.
 */
const umilib_ffi_Status* umilib_secret_conditionally_selectable_conditional_swap(uint8_t* a, uint8_t* b, size_t length, uint8_t choice);

/**
 * Overwrites the `length` bytes at `data` with zeros in a way the compiler does not remove.
 */
const umilib_ffi_Status* umilib_secret_zeroize_zeroize(uint8_t* data, size_t length);

/**
 * Copies `length` bytes at `data` into a new secret, which zeroizes them when released.
 */
const umilib_ffi_Status* umilib_secret_secret_new(const uint8_t* data, size_t length, umilib_secret_Secret** out);

/**
 * Zeroizes and releases a secret. Does nothing if `secret` is null.
 */
void umilib_secret_secret_free(umilib_secret_Secret* secret);

/**
 * Writes a pointer to the secret bytes into `out_data` and their number into `out_length`.
 * The pointer is valid until the secret is released.
 */
const umilib_ffi_Status* umilib_secret_secret_expose(const umilib_secret_Secret* secret, const uint8_t** out_data, size_t* out_length);

/**
 * Like `umilib_secret_secret_expose`, but the bytes may be modified in place.
 */
const umilib_ffi_Status* umilib_secret_secret_expose_mut(umilib_secret_Secret* secret, uint8_t** out_data, size_t* out_length);

/**
 * Whether data-independent timing guards set the mode of the processor on this target.
 */
bool umilib_secret_data_independent_timing_available(void);

/**
 * Whether the data-independent timing mode is set for the calling thread.
 */
bool umilib_secret_data_independent_timing_is_enabled(void);

/**
 * Sets the data-independent timing mode for the calling thread until the guard written to
 * `out` is released, which must happen on the same thread.
 */
const umilib_ffi_Status* umilib_secret_data_independent_timing_enable(umilib_secret_DataIndependentTiming** out);

/**
 * Restores the mode found when `guard` was created and releases it, on the thread that
 * created it. Does nothing if `guard` is null.
 */
void umilib_secret_data_independent_timing_free(umilib_secret_DataIndependentTiming* guard);

/**
 * Creates the table of 256 entries of 8 bits from the `length` bytes at `entries`, which must be 256.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_from_bytes(const uint8_t* entries, size_t length, umilib_secret_ConstantTimeTable32_8** out);

/**
 * Creates the table whose entries are all zero.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_new(umilib_secret_ConstantTimeTable32_8** out);

/**
 * Releases the table, zeroizing it. Does nothing if `table` is null.
 */
void umilib_secret_constant_time_table32_8_free(umilib_secret_ConstantTimeTable32_8* table);

/**
 * Writes a copy of `table` into `out`.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_clone(const umilib_secret_ConstantTimeTable32_8* table, umilib_secret_ConstantTimeTable32_8** out);

/**
 * Writes the entry at `index` (modulo 256) into `out`, reading every word of the table.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_get(const umilib_secret_ConstantTimeTable32_8* table, size_t index, uint32_t* out);

/**
 * Replaces the entry at `index` (modulo 256) with the low 8 bits of `value`, writing every word of
 * the table.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_set(umilib_secret_ConstantTimeTable32_8* table, size_t index, uint32_t value);

/**
 * Exchanges the entries at `first` and `second` (modulo 256).
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_swap(umilib_secret_ConstantTimeTable32_8* table, size_t first, size_t second);

/**
 * Writes the 32 packed words of the table into the 32 words at `out`: entry `i` is bits
 * 8 × (`i` mod 8) and up of word `i` / 8.
 */
const umilib_ffi_Status* umilib_secret_constant_time_table32_8_words(const umilib_secret_ConstantTimeTable32_8* table, uint64_t* out);

/**
 * Returns all ones if `a` equals `b` and zero otherwise, without branching on them.
 */
uint64_t umilib_secret_constant_time_table32_8_mask(size_t a, size_t b);

#ifdef __cplusplus
}
#endif

#endif
