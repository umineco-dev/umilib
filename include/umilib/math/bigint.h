/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_MATH_BIGINT_H
#define UMILIB_MATH_BIGINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An unsigned integer of a precision chosen at run time, zeroized when released.
 */
typedef struct umilib_math_bigint_BoxedUint umilib_math_bigint_BoxedUint;

/**
 * Zeroizes and releases `value`. Does nothing if it is null.
 */
void umilib_math_bigint_boxed_uint_free(umilib_math_bigint_BoxedUint* value);

/**
 * Writes the multiple of bits that precisions are rounded up to into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_precision_unit(uint32_t* out);

/**
 * Writes the largest precision in bits into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_maximum_precision(uint32_t* out);

/**
 * Creates zero of `precision` bits, rounded up to a multiple of 64 (at least 64).
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_zero(uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates one of `precision` bits.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_one(uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `value` in `precision` bits.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_from_u64(uint64_t value, uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates the big-endian number of `length` bytes at `data` in `precision` bits.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_from_be_bytes(const uint8_t* data, size_t length, uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates the little-endian number of `length` bytes at `data` in `precision` bits.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_from_le_bytes(const uint8_t* data, size_t length, uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates the number of the big-endian hexadecimal UTF-8 `text` in `precision` bits.
 * The time depends on the digits: use it for public values.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_from_hex_vartime(const uint8_t* text, size_t length, uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates a copy of `value`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_clone(const umilib_math_bigint_BoxedUint* value, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `value` in `precision` bits; fails if it does not fit.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_resize(const umilib_math_bigint_BoxedUint* value, uint32_t precision, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `value << bits`, discarding the bits shifted out; the time depends on `bits` only.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_shl(const umilib_math_bigint_BoxedUint* value, uint32_t bits, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `value >> bits`; the time depends on `bits` only.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_shr(const umilib_math_bigint_BoxedUint* value, uint32_t bits, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `value` with every bit of the precision inverted.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_not(const umilib_math_bigint_BoxedUint* value, umilib_math_bigint_BoxedUint** out);

/**
 * Writes the precision in bits into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_precision(const umilib_math_bigint_BoxedUint* value, uint32_t* out);

/**
 * Writes the number of bytes of the precision into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bytes(const umilib_math_bigint_BoxedUint* value, size_t* out);

/**
 * Writes whether `value` is zero, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_is_zero(const umilib_math_bigint_BoxedUint* value, uint8_t* out);

/**
 * Writes whether `value` is odd, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_is_odd(const umilib_math_bigint_BoxedUint* value, uint8_t* out);

/**
 * Writes bit `index`, counted from the least significant, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bit(const umilib_math_bigint_BoxedUint* value, uint32_t index, uint8_t* out);

/**
 * Writes the number of bits up to the highest set bit into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bit_length(const umilib_math_bigint_BoxedUint* value, uint32_t* out);

/**
 * Writes the value big-endian in the bytes of its precision into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_to_be_bytes(const umilib_math_bigint_BoxedUint* value, umilib_ffi_Buffer* out);

/**
 * Writes the value big-endian into all `length` bytes at `data`, padded with zeros;
 * fails if it needs more bytes.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_write_be_bytes(const umilib_math_bigint_BoxedUint* value, uint8_t* data, size_t length);

/**
 * Writes the value little-endian in the bytes of its precision into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_to_le_bytes(const umilib_math_bigint_BoxedUint* value, umilib_ffi_Buffer* out);

/**
 * Writes the value little-endian into all `length` bytes at `data`, padded with zeros;
 * fails if it needs more bytes.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_write_le_bytes(const umilib_math_bigint_BoxedUint* value, uint8_t* data, size_t length);

/**
 * Writes whether `a == b`, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_ct_eq(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, uint8_t* out);

/**
 * Writes whether `a < b`, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_ct_lt(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, uint8_t* out);

/**
 * Writes whether `a > b`, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_ct_gt(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, uint8_t* out);

/**
 * Writes -1, 0 or 1 as `a` is below, equal to or above `b` into `out`; the time depends on the values.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_compare_vartime(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, int8_t* out);

/**
 * Creates `a + b` modulo 2^precision, the larger precision of the two.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_wrapping_add(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a - b` modulo 2^precision.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_wrapping_sub(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a * b` modulo 2^precision.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_wrapping_mul(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a & b`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bitand(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a | b`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bitor(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a ^ b`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_bitxor(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a mod modulus` in the precision of the modulus; fails if it is zero.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_rem(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* modulus, umilib_math_bigint_BoxedUint** out);

/**
 * Creates `a + b` modulo 2^precision and writes whether it carried, as a choice, into `out_carry`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_overflowing_add(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out, uint8_t* out_carry);

/**
 * Creates `a - b` modulo 2^precision and writes whether it borrowed, as a choice, into `out_borrow`.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_overflowing_sub(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out, uint8_t* out_borrow);

/**
 * Creates the low and the high half of the full product `a * b`; the two outputs must differ.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_widening_mul(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* b, umilib_math_bigint_BoxedUint** out_low, umilib_math_bigint_BoxedUint** out_high);

/**
 * Creates the quotient, in the precision of `a`, and the remainder, in that of the
 * divisor, of `a / divisor`; fails if the divisor is zero. The two outputs must differ.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_div_rem(const umilib_math_bigint_BoxedUint* a, const umilib_math_bigint_BoxedUint* divisor, umilib_math_bigint_BoxedUint** out_quotient, umilib_math_bigint_BoxedUint** out_remainder);

/**
 * Creates `(low + high * 2^precision(low)) mod modulus` in the precision of the modulus;
 * fails if it is zero.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_rem_wide(const umilib_math_bigint_BoxedUint* low, const umilib_math_bigint_BoxedUint* high, const umilib_math_bigint_BoxedUint* modulus, umilib_math_bigint_BoxedUint** out);

/**
 * Sets `target` to `source` if `choice` is 1; both must have the same precision.
 * Does nothing if they are the same object.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_conditional_assign(umilib_math_bigint_BoxedUint* target, const umilib_math_bigint_BoxedUint* source, uint8_t choice);

/**
 * Swaps `a` and `b` if `choice` is 1; both must have the same precision.
 * Does nothing if they are the same object.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_conditional_swap(umilib_math_bigint_BoxedUint* a, umilib_math_bigint_BoxedUint* b, uint8_t choice);

/**
 * Sets `value` to zero, keeping its precision.
 */
const umilib_ffi_Status* umilib_math_bigint_boxed_uint_zeroize(umilib_math_bigint_BoxedUint* value);

#ifdef __cplusplus
}
#endif

#endif
