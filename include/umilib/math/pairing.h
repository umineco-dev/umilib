/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_MATH_PAIRING_H
#define UMILIB_MATH_PAIRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Writes the sizes in bytes of an uncompressed point of G_1, a point of G_2 and an element of G_T of the
 * curve named by `curve` into `sizes` (three elements).
 */
const umilib_ffi_Status* umilib_math_pairing_pairing_sizes(const uint8_t* curve, size_t curve_length, size_t* sizes);

/**
 * Writes e(P, Q) on the curve named by `curve` into `out` of the size of an element of G_T; fails with
 * InvalidArgument for points that are not on the curve or not in their subgroups of order r.
 */
const umilib_ffi_Status* umilib_math_pairing_pairing_pairing(const uint8_t* curve, size_t curve_length, const uint8_t* p, size_t p_length, const uint8_t* q, size_t q_length, uint8_t* out, size_t out_length);

#ifdef __cplusplus
}
#endif

#endif
