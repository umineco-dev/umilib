/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_MATH_LATTICE_H
#define UMILIB_MATH_LATTICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the NTT of the polynomial of the n coefficients `a` (n of them, reduced modulo q) in the ring named
 * by `ring` into `out` (n elements).
 */
const umilib_ffi_Status* umilib_math_lattice_polynomial_ntt(const uint8_t* ring, size_t ring_length, const uint32_t* a, size_t a_count, uint32_t* out, size_t out_count);

/**
 * Writes the inverse NTT of the representation `a` (n elements) into `out` (n elements).
 */
const umilib_ffi_Status* umilib_math_lattice_polynomial_inverse_ntt(const uint8_t* ring, size_t ring_length, const uint32_t* a, size_t a_count, uint32_t* out, size_t out_count);

/**
 * Writes the product in T_q of the NTT representations `a` and `b` (n elements each) into `out` (n elements).
 */
const umilib_ffi_Status* umilib_math_lattice_polynomial_multiply_ntt(const uint8_t* ring, size_t ring_length, const uint32_t* a, size_t a_count, const uint32_t* b, size_t b_count, uint32_t* out, size_t out_count);

#ifdef __cplusplus
}
#endif

#endif
