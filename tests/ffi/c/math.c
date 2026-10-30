/* Modular arithmetic through the generated headers: RFC 8032 section 5.1 and the error statuses. */
#include <stdio.h>
#include <string.h>

#include "umilib.h"

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        if (!(condition)) {                                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition);      \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

static int fails_with(const umilib_ffi_Status* status, const char* name) {
    return status != NULL && strcmp(status->domain, "math.bigint") == 0 && strcmp(status->name, name) == 0;
}

static int hex(const char* text, umilib_math_bigint_BoxedUint** out) {
    return umilib_math_bigint_boxed_uint_from_hex_vartime((const uint8_t*)text, strlen(text), 256, out) == NULL;
}

int main(void) {
    /* p = 2^255 - 19, and d = -121665 / 121666 mod p (RFC 8032 section 5.1). */
    umilib_math_bigint_BoxedUint* p = NULL;
    CHECK(hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", &p));
    umilib_math_modular_BoxedModulus* field = NULL;
    CHECK(umilib_math_modular_boxed_modulus_new(p, &field) == NULL);

    umilib_math_bigint_BoxedUint* numerator = NULL;
    umilib_math_bigint_BoxedUint* denominator = NULL;
    CHECK(umilib_math_bigint_boxed_uint_from_u64(121665, 64, &numerator) == NULL);
    CHECK(umilib_math_bigint_boxed_uint_from_u64(121666, 64, &denominator) == NULL);
    umilib_math_modular_BoxedResidue* a = NULL;
    umilib_math_modular_BoxedResidue* b = NULL;
    umilib_math_modular_BoxedResidue* negated = NULL;
    umilib_math_modular_BoxedResidue* inverse = NULL;
    umilib_math_modular_BoxedResidue* d = NULL;
    CHECK(umilib_math_modular_boxed_modulus_residue(field, numerator, &a) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_residue(field, denominator, &b) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_neg(field, a, &negated) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_invert(field, b, &inverse) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_mul(field, negated, inverse, &d) == NULL);
    umilib_math_bigint_BoxedUint* value = NULL;
    CHECK(umilib_math_modular_boxed_modulus_retrieve(field, d, &value) == NULL);
    umilib_ffi_Buffer bytes = {0};
    CHECK(umilib_math_bigint_boxed_uint_to_be_bytes(value, &bytes) == NULL);
    const uint8_t expected[32] = {0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40,
                                  0x79, 0x77, 0x79, 0xe8, 0x98, 0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41,
                                  0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3};
    CHECK(bytes.length == 32 && memcmp(bytes.data, expected, 32) == 0);
    umilib_ffi_buffer_free(&bytes);

    /* Fermat: 2^(p-1) = 1. */
    umilib_math_bigint_BoxedUint* one = NULL;
    umilib_math_bigint_BoxedUint* exponent = NULL;
    umilib_math_bigint_BoxedUint* two = NULL;
    umilib_math_modular_BoxedResidue* base = NULL;
    umilib_math_modular_BoxedResidue* power = NULL;
    umilib_math_modular_BoxedResidue* expected_one = NULL;
    CHECK(umilib_math_bigint_boxed_uint_one(64, &one) == NULL);
    CHECK(umilib_math_bigint_boxed_uint_wrapping_sub(p, one, &exponent) == NULL);
    CHECK(umilib_math_bigint_boxed_uint_from_u64(2, 64, &two) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_residue(field, two, &base) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_pow(field, base, exponent, &power) == NULL);
    CHECK(umilib_math_modular_boxed_modulus_one(field, &expected_one) == NULL);
    uint8_t equal = 0;
    CHECK(umilib_math_modular_boxed_residue_ct_eq(power, expected_one, &equal) == NULL && equal == 1);

    /* Errors. */
    umilib_math_modular_BoxedModulus* invalid = NULL;
    CHECK(fails_with(umilib_math_modular_boxed_modulus_new(two, &invalid), "InvalidModulus") && invalid == NULL);
    umilib_math_bigint_BoxedUint* zero = NULL;
    umilib_math_bigint_BoxedUint* remainder = NULL;
    CHECK(umilib_math_bigint_boxed_uint_zero(64, &zero) == NULL);
    CHECK(fails_with(umilib_math_bigint_boxed_uint_rem(p, zero, &remainder), "DivisionByZero"));
    umilib_math_modular_BoxedResidue* zero_residue = NULL;
    umilib_math_modular_BoxedResidue* no_inverse = NULL;
    CHECK(umilib_math_modular_boxed_modulus_zero(field, &zero_residue) == NULL);
    CHECK(fails_with(umilib_math_modular_boxed_modulus_invert(field, zero_residue, &no_inverse), "NotInvertible"));
    umilib_math_bigint_BoxedUint* wide = NULL;
    CHECK(umilib_math_bigint_boxed_uint_from_u64(1, 512, &wide) == NULL);
    umilib_math_modular_BoxedResidue* wrong = NULL;
    CHECK(fails_with(umilib_math_modular_boxed_modulus_from_montgomery(field, wide, &wrong), "SizeMismatch"));
    umilib_math_bigint_BoxedUint* unparsed = NULL;
    CHECK(fails_with(umilib_math_bigint_boxed_uint_from_hex_vartime((const uint8_t*)"0x1", 3, 64, &unparsed), "InvalidDigit"));
    CHECK(unparsed == NULL);

    umilib_math_bigint_boxed_uint_free(wide);
    umilib_math_modular_boxed_residue_free(zero_residue);
    umilib_math_bigint_boxed_uint_free(zero);
    umilib_math_modular_boxed_residue_free(expected_one);
    umilib_math_modular_boxed_residue_free(power);
    umilib_math_modular_boxed_residue_free(base);
    umilib_math_bigint_boxed_uint_free(two);
    umilib_math_bigint_boxed_uint_free(exponent);
    umilib_math_bigint_boxed_uint_free(one);
    umilib_math_bigint_boxed_uint_free(value);
    umilib_math_modular_boxed_residue_free(d);
    umilib_math_modular_boxed_residue_free(inverse);
    umilib_math_modular_boxed_residue_free(negated);
    umilib_math_modular_boxed_residue_free(b);
    umilib_math_modular_boxed_residue_free(a);
    umilib_math_bigint_boxed_uint_free(denominator);
    umilib_math_bigint_boxed_uint_free(numerator);
    umilib_math_modular_boxed_modulus_free(field);
    umilib_math_bigint_boxed_uint_free(p);
    puts("math: ok");
    return 0;
}
