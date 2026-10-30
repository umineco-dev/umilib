use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::math::bigint::*;
#[cfg(umilib_feature = "math-modular")]
use umilib::ffi::math::modular::*;
use umilib::math::bigint::BoxedUint;
#[cfg(umilib_feature = "math-modular")]
use umilib::math::modular::{BoxedModulus, BoxedResidue};

use super::Check;

unsafe fn number(value: u64, precision: u32) -> *mut BoxedUint {
    let mut out = ptr::null_mut();
    Check::ok(unsafe { umilib_math_bigint_boxed_uint_from_u64(value, precision, &mut out) });
    out
}

unsafe fn bytes(value: *const BoxedUint) -> Vec<u8> {
    let mut buffer = Buffer::EMPTY;
    Check::ok(unsafe { umilib_math_bigint_boxed_uint_to_be_bytes(value, &mut buffer) });
    let bytes = buffer.as_slice().to_vec();
    unsafe { umilib::ffi::umilib_ffi_buffer_free(&mut buffer) };
    bytes
}

#[test]
fn integers_through_the_c_abi() {
    unsafe {
        let (a, b) = (number(u64::MAX, 64), number(1, 64));
        let (mut sum, mut carry) = (ptr::null_mut(), 0u8);
        Check::ok(umilib_math_bigint_boxed_uint_overflowing_add(a, b, &mut sum, &mut carry));
        assert_eq!((bytes(sum), carry), (vec![0; 8], 1));
        let (mut quotient, mut remainder) = (ptr::null_mut(), ptr::null_mut());
        let seven = number(7, 64);
        Check::ok(umilib_math_bigint_boxed_uint_div_rem(a, seven, &mut quotient, &mut remainder));
        assert_eq!(bytes(quotient), (u64::MAX / 7).to_be_bytes());
        assert_eq!(bytes(remainder), (u64::MAX % 7).to_be_bytes());
        let mut ordering = 0i8;
        Check::ok(umilib_math_bigint_boxed_uint_compare_vartime(b, a, &mut ordering));
        assert_eq!(ordering, -1);
        let mut out = ptr::null_mut();
        Check::fails(umilib_math_bigint_boxed_uint_zero(u32::MAX, &mut out), "math.bigint", "InvalidPrecision");
        Check::fails(
            umilib_math_bigint_boxed_uint_from_be_bytes([1; 9].as_ptr(), 9, 64, &mut out),
            "math.bigint",
            "Overflow",
        );
        assert!(out.is_null());
        // The same object as both operands of a mutation is a no-op, not an aliasing violation.
        Check::ok(umilib_math_bigint_boxed_uint_conditional_assign(a, a, 1));
        Check::ok(umilib_math_bigint_boxed_uint_conditional_swap(a, a, 1));
        assert_eq!(bytes(a), u64::MAX.to_be_bytes());
        Check::ok(umilib_math_bigint_boxed_uint_conditional_swap(a, b, 1));
        assert_eq!((bytes(a), bytes(b)), (1u64.to_be_bytes().to_vec(), u64::MAX.to_be_bytes().to_vec()));
        let wide = number(1, 128);
        Check::fails(umilib_math_bigint_boxed_uint_conditional_assign(a, wide, 1), "math.bigint", "SizeMismatch");
        Check::fails(umilib_math_bigint_boxed_uint_conditional_assign(a, b, 2), "ffi", "InvalidArgument");
        Check::fails(umilib_math_bigint_boxed_uint_conditional_swap(a, b, 0xFF), "ffi", "InvalidArgument");
        assert_eq!((bytes(a), bytes(b)), (1u64.to_be_bytes().to_vec(), u64::MAX.to_be_bytes().to_vec()));
        // One output for both halves would overwrite, and leak, the first.
        let mut same = ptr::null_mut();
        Check::fails(umilib_math_bigint_boxed_uint_widening_mul(a, b, &mut same, &mut same), "ffi", "InvalidArgument");
        Check::fails(umilib_math_bigint_boxed_uint_div_rem(a, b, &mut same, &mut same), "ffi", "InvalidArgument");
        assert!(same.is_null());
        Check::fails(umilib_math_bigint_boxed_uint_precision(ptr::null(), &mut 0), "ffi", "NullPointer");
        for value in [a, b, sum, quotient, remainder, seven, wide] {
            umilib_math_bigint_boxed_uint_free(value);
        }
        umilib_math_bigint_boxed_uint_free(ptr::null_mut());
    }
}

#[cfg(umilib_feature = "math-modular")]
#[test]
fn modular_arithmetic_through_the_c_abi() {
    unsafe {
        let value = number(101, 64);
        let mut modulus: *mut BoxedModulus = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_new(value, &mut modulus));
        let three = number(3, 64);
        let mut residue: *mut BoxedResidue = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_residue(modulus, three, &mut residue));
        let exponent = number(100, 64);
        let mut power = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_pow(modulus, residue, exponent, &mut power));
        let mut one = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_one(modulus, &mut one));
        let mut equal = 0u8;
        Check::ok(umilib_math_modular_boxed_residue_ct_eq(power, one, &mut equal));
        assert_eq!(equal, 1, "3^100 = 1 (mod 101)");
        let mut inverse = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_invert(modulus, residue, &mut inverse));
        let mut retrieved = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_modulus_retrieve(modulus, inverse, &mut retrieved));
        assert_eq!(bytes(retrieved), 34u64.to_be_bytes(), "3 * 34 = 102 = 1 (mod 101)");
        let even = number(100, 64);
        let mut invalid = ptr::null_mut();
        Check::fails(umilib_math_modular_boxed_modulus_new(even, &mut invalid), "math.bigint", "InvalidModulus");
        let wide = number(5, 128);
        let mut wrong = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_residue_from_montgomery_unchecked(wide, &mut wrong));
        Check::fails(umilib_math_modular_boxed_modulus_check(modulus, wrong), "math.bigint", "SizeMismatch");
        let mut product = ptr::null_mut();
        Check::fails(
            umilib_math_modular_boxed_modulus_mul(modulus, wrong, residue, &mut product),
            "math.bigint",
            "SizeMismatch",
        );
        assert!(product.is_null());
        let mut copy = ptr::null_mut();
        Check::ok(umilib_math_modular_boxed_residue_clone(one, &mut copy));
        Check::ok(umilib_math_modular_boxed_residue_conditional_swap(copy, residue, 1));
        Check::ok(umilib_math_modular_boxed_residue_ct_eq(copy, one, &mut equal));
        assert_eq!(equal, 0);
        Check::ok(umilib_math_modular_boxed_residue_conditional_assign(copy, one, 1));
        Check::ok(umilib_math_modular_boxed_residue_ct_eq(copy, one, &mut equal));
        assert_eq!(equal, 1);
        Check::fails(
            umilib_math_modular_boxed_residue_conditional_assign(copy, wrong, 1),
            "math.bigint",
            "SizeMismatch",
        );
        Check::fails(umilib_math_modular_boxed_residue_conditional_swap(copy, residue, 3), "ffi", "InvalidArgument");
        for residue in [residue, power, one, inverse, wrong, copy] {
            umilib_math_modular_boxed_residue_free(residue);
        }
        for value in [value, three, exponent, retrieved, even, wide] {
            umilib_math_bigint_boxed_uint_free(value);
        }
        umilib_math_modular_boxed_modulus_free(modulus);
    }
}

/// The pairing of the C ABI is that of `umilib::math::pairing`, bilinear,
/// and refuses points outside the groups.
#[cfg(umilib_feature = "math-pairing")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn pairing_through_the_c_abi() {
    use umilib::ffi::math::pairing::*;
    use umilib::math::ec::{AffinePoint, FieldElement};
    use umilib::math::pairing::{BN254, BN254Scalar, G2Affine, G2Projective, GT, Pairing};

    let curve = b"umilib_math_pairing_BN254";
    let mut sizes = [0usize; 3];
    Check::ok(unsafe { umilib_math_pairing_pairing_sizes(curve.as_ptr(), curve.len(), sizes.as_mut_ptr()) });
    assert_eq!(sizes, [65, 128, 384]);
    let pair = |p: &[u8], q: &[u8]| {
        let mut out = vec![0u8; 384];
        let status = unsafe {
            umilib_math_pairing_pairing_pairing(
                curve.as_ptr(),
                curve.len(),
                p.as_ptr(),
                p.len(),
                q.as_ptr(),
                q.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        (status, out)
    };
    let scalar = FieldElement::<BN254Scalar>::from_be_bytes(&[[0u8; 31].as_slice(), &[6]].concat()).unwrap();
    let p = AffinePoint::<<BN254 as umilib::math::pairing::PairingCurve>::G1>::generator();
    let mut p_bytes = vec![0u8; 65];
    p.write_encoded(&mut p_bytes, false).unwrap();
    let mut p6_bytes = vec![0u8; 65];
    p.to_projective().mul(&scalar).to_affine().write_encoded(&mut p6_bytes, false).unwrap();
    let mut q_bytes = vec![0u8; 128];
    G2Affine::<BN254>::generator().write_encoded(&mut q_bytes).unwrap();
    let mut q6_bytes = vec![0u8; 128];
    G2Projective::<BN254>::generator().mul(&scalar).to_affine().write_encoded(&mut q6_bytes).unwrap();

    let (status, value) = pair(&p_bytes, &q_bytes);
    Check::ok(status);
    let mut expected = vec![0u8; GT::<BN254>::encoded_length()];
    Pairing::<BN254>::pairing(&p, &G2Affine::generator()).unwrap().write_bytes(&mut expected).unwrap();
    assert_eq!(value, expected);
    // e(6P, Q) = e(P, 6Q) = e(P, Q)^6.
    let (status, left) = pair(&p6_bytes, &q_bytes);
    Check::ok(status);
    let (status, right) = pair(&p_bytes, &q6_bytes);
    Check::ok(status);
    assert_eq!(left, right);
    assert_ne!(left, value);
    // A point off the curve and an unknown curve are refused.
    let mut off = p_bytes.clone();
    off[64] ^= 1;
    Check::fails(pair(&off, &q_bytes).0, "ffi", "InvalidArgument");
    let unknown = b"umilib_math_pairing_BN256";
    let mut out = [0u8; 384];
    Check::fails(
        unsafe {
            umilib_math_pairing_pairing_pairing(
                unknown.as_ptr(),
                unknown.len(),
                p_bytes.as_ptr(),
                65,
                q_bytes.as_ptr(),
                128,
                out.as_mut_ptr(),
                384,
            )
        },
        "ffi",
        "InvalidArgument",
    );
}
