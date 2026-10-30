/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_MATH_MODULAR_H
#define UMILIB_MATH_MODULAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/math/bigint.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * An odd modulus with its Montgomery constants, zeroized when released.
 */
typedef struct umilib_math_modular_BoxedModulus umilib_math_modular_BoxedModulus;

/**
 * A value modulo a BoxedModulus in the Montgomery form, zeroized when released.
 */
typedef struct umilib_math_modular_BoxedResidue umilib_math_modular_BoxedResidue;

/**
 * Zeroizes and releases `modulus`. Does nothing if it is null.
 */
void umilib_math_modular_boxed_modulus_free(umilib_math_modular_BoxedModulus* modulus);

/**
 * Zeroizes and releases `residue`. Does nothing if it is null.
 */
void umilib_math_modular_boxed_residue_free(umilib_math_modular_BoxedResidue* residue);

/**
 * Prepares a copy of `value` as a modulus; fails if it is even or below 3.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_new(const umilib_math_bigint_BoxedUint* value, umilib_math_modular_BoxedModulus** out);

/**
 * Creates a copy of `modulus`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_clone(const umilib_math_modular_BoxedModulus* modulus, umilib_math_modular_BoxedModulus** out);

/**
 * Creates a copy of the value of `modulus`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_value(const umilib_math_modular_BoxedModulus* modulus, umilib_math_bigint_BoxedUint** out);

/**
 * Writes the precision in bits of `modulus` and its residues into `out`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_precision(const umilib_math_modular_BoxedModulus* modulus, uint32_t* out);

/**
 * Fails unless `residue` has the precision of `modulus`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_check(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* residue);

/**
 * Creates the residue zero.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_zero(const umilib_math_modular_BoxedModulus* modulus, umilib_math_modular_BoxedResidue** out);

/**
 * Creates the residue one.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_one(const umilib_math_modular_BoxedModulus* modulus, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `x mod modulus` as a residue; `x` may have any precision.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_residue(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_bigint_BoxedUint* x, umilib_math_modular_BoxedResidue** out);

/**
 * Creates the value of `residue`, below the modulus.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_retrieve(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* residue, umilib_math_bigint_BoxedUint** out);

/**
 * Creates the residue whose Montgomery form is `montgomery`; fails if it is not below the
 * modulus or has another precision.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_from_montgomery(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_bigint_BoxedUint* montgomery, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `a + b`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_add(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, const umilib_math_modular_BoxedResidue* b, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `a - b`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_sub(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, const umilib_math_modular_BoxedResidue* b, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `a * b`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_mul(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, const umilib_math_modular_BoxedResidue* b, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `-a`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_neg(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `a^2`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_square(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `a^-1`; fails if `a` is not invertible, which is the one fact the time reveals.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_invert(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* a, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `base^exponent`, over every bit of the exponent's precision, in constant time.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_pow(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* base, const umilib_math_bigint_BoxedUint* exponent, umilib_math_modular_BoxedResidue** out);

/**
 * Creates `base^exponent` in time that depends on the exponent, which must be public.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_pow_vartime(const umilib_math_modular_BoxedModulus* modulus, const umilib_math_modular_BoxedResidue* base, const umilib_math_bigint_BoxedUint* exponent, umilib_math_modular_BoxedResidue** out);

/**
 * Writes whether the moduli are equal, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_ct_eq(const umilib_math_modular_BoxedModulus* a, const umilib_math_modular_BoxedModulus* b, uint8_t* out);

/**
 * Zeroizes `modulus`, which is unusable afterwards except to be released.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_modulus_zeroize(umilib_math_modular_BoxedModulus* modulus);

/**
 * Creates the residue whose Montgomery form is a copy of `montgomery`, which must be below the
 * modulus and of its precision; `umilib_math_modular_boxed_modulus_from_montgomery` checks both.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_from_montgomery_unchecked(const umilib_math_bigint_BoxedUint* montgomery, umilib_math_modular_BoxedResidue** out);

/**
 * Creates a copy of `residue`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_clone(const umilib_math_modular_BoxedResidue* residue, umilib_math_modular_BoxedResidue** out);

/**
 * Creates a copy of the Montgomery form of `residue`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_as_montgomery(const umilib_math_modular_BoxedResidue* residue, umilib_math_bigint_BoxedUint** out);

/**
 * Writes the precision in bits of `residue` into `out`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_precision(const umilib_math_modular_BoxedResidue* residue, uint32_t* out);

/**
 * Writes whether the residues are equal, as a choice, into `out`.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_ct_eq(const umilib_math_modular_BoxedResidue* a, const umilib_math_modular_BoxedResidue* b, uint8_t* out);

/**
 * Sets `residue` to zero.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_zeroize(umilib_math_modular_BoxedResidue* residue);

/**
 * Sets `target` to `source` if `choice` is 1 (other values are rejected); both must have
 * the same precision. Does nothing if they are the same object.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_conditional_assign(umilib_math_modular_BoxedResidue* target, const umilib_math_modular_BoxedResidue* source, uint8_t choice);

/**
 * Swaps `a` and `b` if `choice` is 1 (other values are rejected); both must have the same
 * precision. Does nothing if they are the same object.
 */
const umilib_ffi_Status* umilib_math_modular_boxed_residue_conditional_swap(umilib_math_modular_BoxedResidue* a, umilib_math_modular_BoxedResidue* b, uint8_t choice);

#ifdef __cplusplus
}
#endif

#endif
