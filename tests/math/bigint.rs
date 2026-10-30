use umilib::math::bigint::{BoxedUint, Limb, Limbs, MathError, U64, U128, U256, U576, U8192};
use umilib::secret::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::Values;

/// Fewer under Miri, which interprets the code (for example on a 32-bit target).
const ITERATIONS: usize = if cfg!(miri) { 200 } else { 20_000 };

fn uint(value: u128) -> U128 {
    U128::from_le_bytes(&value.to_le_bytes()).unwrap()
}

fn int(value: &U128) -> u128 {
    u128::from_le_bytes(value.to_le_bytes().try_into().unwrap())
}

fn boxed(value: u128) -> BoxedUint {
    BoxedUint::from_le_bytes(&value.to_le_bytes(), 128).unwrap()
}

fn boxed_int(value: &BoxedUint) -> u128 {
    int(&value.to_uint().unwrap())
}

/// The full product of two `u128`, as the low and the high half.
fn widening_mul(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = (a as u64 as u128, a >> 64);
    let (b0, b1) = (b as u64 as u128, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let middle = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let low = (p00 as u64 as u128) | (middle << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (middle >> 64);
    (low, high)
}

#[test]
fn precisions_are_the_same_on_every_platform() {
    assert_eq!((U64::BITS, U128::BITS, U256::BITS, U576::BITS, U8192::BITS), (64, 128, 256, 576, 8192));
    assert_eq!((U64::BYTES, U256::BYTES, U8192::BYTES), (8, 32, 1024));
    assert_eq!(Limbs::BYTES as u32 * 8, Limb::BITS);
    assert_eq!(Limbs::count(1), 1);
    assert_eq!(Limbs::count(Limb::BITS + 1), 2);
    for (requested, precision) in [(0, 64), (1, 64), (64, 64), (65, 128), (2048, 2048), (2049, 2112)] {
        assert_eq!(BoxedUint::zero(requested).unwrap().precision(), precision, "{requested}");
        assert_eq!(BoxedUint::zero(requested).unwrap().to_be_bytes().len(), precision as usize / 8);
    }
    assert_eq!(BoxedUint::from_limbs(&[1]).unwrap().precision(), 64);
    let maximum = BoxedUint::MAXIMUM_PRECISION;
    assert_eq!(
        BoxedUint::zero(maximum + 1).unwrap_err(),
        MathError::InvalidPrecision { precision: maximum + 1, maximum }
    );
    assert_eq!(
        BoxedUint::from_be_bytes(&[1], u32::MAX).unwrap_err(),
        MathError::InvalidPrecision { precision: u32::MAX, maximum }
    );
}

#[test]
fn limb_operations_carry_and_borrow() {
    assert_eq!(Limbs::carrying_add(Limb::MAX, Limb::MAX, 1), (Limb::MAX, 1));
    assert_eq!(Limbs::carrying_add(Limb::MAX, 0, 1), (0, 1));
    assert_eq!(Limbs::carrying_add(1, 2, 0), (3, 0));
    assert_eq!(Limbs::borrowing_sub(0, Limb::MAX, 1), (0, 1));
    assert_eq!(Limbs::borrowing_sub(0, 0, 1), (Limb::MAX, 1));
    assert_eq!(Limbs::borrowing_sub(5, 3, 1), (1, 0));
    // (2^w - 1)^2 + 2 * (2^w - 1) = 2^2w - 1.
    assert_eq!(Limbs::carrying_mul_add(Limb::MAX, Limb::MAX, Limb::MAX, Limb::MAX), (Limb::MAX, Limb::MAX));
    assert_eq!(Limbs::mask(Choice::TRUE), Limb::MAX);
    assert_eq!(Limbs::mask(Choice::FALSE), 0);
}

#[test]
fn arithmetic_matches_u128() {
    let mut values = Values::new(1);
    for _ in 0..ITERATIONS {
        let (a, b) = (values.next_u128(), values.next_u128());
        let (x, y) = (uint(a), uint(b));
        let (sum, carry) = a.overflowing_add(b);
        assert_eq!(x.overflowing_add(&y).0, uint(sum));
        assert_eq!(x.overflowing_add(&y).1.into_bool(), carry);
        let (difference, borrow) = a.overflowing_sub(b);
        assert_eq!(x.overflowing_sub(&y).0, uint(difference));
        assert_eq!(x.overflowing_sub(&y).1.into_bool(), borrow);
        assert_eq!(x.wrapping_add(&y), uint(a.wrapping_add(b)));
        assert_eq!(x.wrapping_sub(&y), uint(a.wrapping_sub(b)));
        let (low, high) = widening_mul(a, b);
        assert_eq!(x.widening_mul(&y), (uint(low), uint(high)));
        assert_eq!(x.wrapping_mul(&y), uint(a.wrapping_mul(b)));
        match (a.checked_div(b), a.checked_rem(b)) {
            (Some(quotient), Some(remainder)) => {
                assert_eq!(x.div_rem(&y).unwrap(), (uint(quotient), uint(remainder)));
                assert_eq!(x.rem(&y).unwrap(), uint(remainder));
            }
            _ => assert_eq!(x.div_rem(&y).unwrap_err(), MathError::DivisionByZero),
        }
        assert_eq!(x.ct_eq(&y).into_bool(), a == b);
        assert_eq!(x == y, a == b);
        assert_eq!(x.ct_lt(&y).into_bool(), a < b);
        assert_eq!(x.ct_gt(&y).into_bool(), a > b);
        assert_eq!(x.compare_vartime(&y), a.cmp(&b));
        assert_eq!(x.is_zero().into_bool(), a == 0);
        assert_eq!(x.is_odd().into_bool(), a % 2 == 1);
        assert_eq!(x.bit_length(), 128 - a.leading_zeros());
        assert_eq!(x & y, uint(a & b));
        assert_eq!(x | y, uint(a | b));
        assert_eq!(x ^ y, uint(a ^ b));
        assert_eq!(!x, uint(!a));
        let shift = (values.next_u64() % 160) as u32;
        assert_eq!(x.shl(shift), uint(a.checked_shl(shift).unwrap_or(0)));
        assert_eq!(x.shr(shift), uint(a.checked_shr(shift).unwrap_or(0)));
        let index = (values.next_u64() % 140) as u32;
        assert_eq!(x.bit(index).into_bool(), index < 128 && (a >> index) & 1 == 1);
    }
}

#[test]
fn boxed_arithmetic_matches_u128() {
    let mut values = Values::new(2);
    for _ in 0..ITERATIONS / 4 {
        let (a, b) = (values.next_u128(), values.next_u128());
        let (x, y) = (boxed(a), boxed(b));
        let (sum, carry) = a.overflowing_add(b);
        let (boxed_sum, boxed_carry) = x.overflowing_add(&y);
        assert_eq!((boxed_int(&boxed_sum), boxed_carry.into_bool()), (sum, carry));
        let (difference, borrow) = a.overflowing_sub(b);
        let (boxed_difference, boxed_borrow) = x.overflowing_sub(&y);
        assert_eq!((boxed_int(&boxed_difference), boxed_borrow.into_bool()), (difference, borrow));
        let (low, high) = x.widening_mul(&y);
        assert_eq!((boxed_int(&low), boxed_int(&high)), widening_mul(a, b));
        assert_eq!(boxed_int(&x.wrapping_mul(&y)), a.wrapping_mul(b));
        match (a.checked_div(b), a.checked_rem(b)) {
            (Some(quotient), Some(remainder)) => {
                let (boxed_quotient, boxed_remainder) = x.div_rem(&y).unwrap();
                assert_eq!((boxed_int(&boxed_quotient), boxed_int(&boxed_remainder)), (quotient, remainder));
            }
            _ => assert_eq!(x.div_rem(&y).unwrap_err(), MathError::DivisionByZero),
        }
        assert_eq!(x == y, a == b);
        assert_eq!(x.ct_lt(&y).into_bool(), a < b);
        assert_eq!(x.ct_gt(&y).into_bool(), a > b);
        assert_eq!(x.compare_vartime(&y), a.cmp(&b));
        assert_eq!(x.bit_length(), 128 - a.leading_zeros());
        assert_eq!(boxed_int(&(&x & &y)), a & b);
        assert_eq!(boxed_int(&(&x | &y)), a | b);
        assert_eq!(boxed_int(&(&x ^ &y)), a ^ b);
        assert_eq!(boxed_int(&!&x), !a);
        let shift = (values.next_u64() % 160) as u32;
        assert_eq!(boxed_int(&x.shl(shift)), a.checked_shl(shift).unwrap_or(0));
        assert_eq!(boxed_int(&x.shr(shift)), a.checked_shr(shift).unwrap_or(0));
    }
}

#[test]
fn boxed_operands_of_different_precisions_are_zero_extended() {
    let small = BoxedUint::from_u64(u64::MAX, 64).unwrap();
    let large = BoxedUint::from_u64(1, 256).unwrap();
    let (sum, carry) = small.overflowing_add(&large);
    assert_eq!(sum.precision(), 256);
    assert!(!carry.into_bool());
    assert_eq!(sum, BoxedUint::from_be_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0], 128).unwrap());
    let (difference, borrow) = small.overflowing_sub(&large);
    assert_eq!((difference.precision(), borrow.into_bool()), (256, false));
    let (_, borrow) = large.overflowing_sub(&BoxedUint::from_u64(2, 64).unwrap());
    assert!(borrow.into_bool());
    // Equality and order compare values, whatever the precisions.
    assert_eq!(BoxedUint::from_u64(5, 64).unwrap(), BoxedUint::from_u64(5, 512).unwrap());
    assert_ne!(BoxedUint::from_u64(5, 64).unwrap(), BoxedUint::from_u64(6, 512).unwrap());
    assert!(small.ct_gt(&large).into_bool());
    let (low, high) = small.widening_mul(&large);
    assert_eq!((low.precision(), high.precision()), (256, 256));
    assert_eq!(low, small);
    assert!(high.is_zero().into_bool());
    // The quotient has the precision of the dividend, the remainder that of the divisor.
    let (quotient, remainder) = large.div_rem(&BoxedUint::from_u64(3, 64).unwrap()).unwrap();
    assert_eq!((quotient.precision(), remainder.precision()), (256, 64));
    assert_eq!(remainder, BoxedUint::from_u64(1, 64).unwrap());
}

#[test]
fn bytes_round_trip_in_both_orders() {
    let mut values = Values::new(3);
    for _ in 0..ITERATIONS / 20 {
        let value = values.next_u128();
        let x = uint(value);
        assert_eq!(x.to_be_bytes(), value.to_be_bytes());
        assert_eq!(x.to_le_bytes(), value.to_le_bytes());
        assert_eq!(U128::from_be_bytes(&value.to_be_bytes()).unwrap(), x);
        let y = boxed(value);
        assert_eq!(y.to_be_bytes(), value.to_be_bytes());
        assert_eq!(BoxedUint::from_be_bytes(&value.to_be_bytes(), 128).unwrap(), y);
    }
    // Leading zeros beyond the precision are allowed, other bytes are not.
    let mut padded = vec![0; 8];
    padded.extend_from_slice(&u128::MAX.to_be_bytes());
    assert_eq!(U128::from_be_bytes(&padded).unwrap(), U128::MAX);
    padded[0] = 1;
    assert_eq!(U128::from_be_bytes(&padded).unwrap_err(), MathError::Overflow);
    let mut padded = u128::MAX.to_le_bytes().to_vec();
    padded.extend_from_slice(&[0; 8]);
    assert_eq!(U128::from_le_bytes(&padded).unwrap(), U128::MAX);
    padded.push(1);
    assert_eq!(U128::from_le_bytes(&padded).unwrap_err(), MathError::Overflow);
    assert_eq!(BoxedUint::from_be_bytes(&[1; 9], 64).unwrap_err(), MathError::Overflow);
    assert_eq!(U128::from_be_bytes(&[]).unwrap(), U128::ZERO);
    // Writing into a shorter or longer output.
    let mut short = [0xAA; 2];
    uint(0x1234).write_be_bytes(&mut short).unwrap();
    assert_eq!(short, [0x12, 0x34]);
    uint(0x1234).write_le_bytes(&mut short).unwrap();
    assert_eq!(short, [0x34, 0x12]);
    let mut short = [0xAA; 2];
    assert_eq!(uint(0x12345).write_be_bytes(&mut short).unwrap_err(), MathError::Overflow);
    assert_eq!(short, [0, 0]);
    let mut long = [0xAA; 20];
    uint(0x1234).write_be_bytes(&mut long).unwrap();
    assert_eq!(long[..18], [0; 18]);
    assert_eq!(long[18..], [0x12, 0x34]);
    assert_eq!(U128::from_u64(7).unwrap(), uint(7));
    assert_eq!(BoxedUint::from_u64(7, 64).unwrap(), boxed(7));
}

#[test]
fn hexadecimal_text() {
    const CONSTANT: U256 =
        U256::from_hex_vartime_or_panic("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    assert_eq!(CONSTANT.to_be_bytes()[..5], [0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    assert_eq!(U128::from_hex_vartime("0").unwrap(), U128::ZERO);
    assert_eq!(U128::from_hex_vartime("fF").unwrap(), uint(255));
    assert_eq!(U128::from_hex_vartime(&format!("0{:x}", u128::MAX)).unwrap(), U128::MAX);
    assert_eq!(U128::from_hex_vartime(&format!("1{:x}", u128::MAX)).unwrap_err(), MathError::Overflow);
    assert_eq!(U128::from_hex_vartime("").unwrap_err(), MathError::InvalidDigit { position: 0 });
    assert_eq!(U128::from_hex_vartime("0x1").unwrap_err(), MathError::InvalidDigit { position: 1 });
    assert_eq!(U128::from_hex_vartime("1 2").unwrap_err(), MathError::InvalidDigit { position: 1 });
    assert_eq!(U128::from_hex_vartime("-1").unwrap_err(), MathError::InvalidDigit { position: 0 });
    assert_eq!(BoxedUint::from_hex_vartime("123", 64).unwrap(), boxed(0x123));
    let mut values = Values::new(4);
    for _ in 0..ITERATIONS / 20 {
        let value = values.next_u128();
        assert_eq!(format!("{:x}", uint(value)), format!("{value:032x}"));
        assert_eq!(format!("{:X}", uint(value)), format!("{value:032X}"));
        assert_eq!(format!("{:x}", boxed(value)), format!("{value:032x}"));
        assert_eq!(U128::from_hex_vartime(&format!("{value:x}")).unwrap(), uint(value));
    }
    assert_eq!(format!("{:?}", uint(1)), format!("Uint(0x{:032x})", 1));
    assert_eq!(format!("{:?}", BoxedUint::one(64).unwrap()), format!("BoxedUint(0x{:016x})", 1));
}

#[test]
fn division_by_zero_fails() {
    assert_eq!(uint(1).div_rem(&U128::ZERO).unwrap_err(), MathError::DivisionByZero);
    assert_eq!(uint(1).rem(&U128::ZERO).unwrap_err(), MathError::DivisionByZero);
    assert_eq!(U128::rem_wide(&uint(1), &uint(1), &U128::ZERO).unwrap_err(), MathError::DivisionByZero);
    let zero = BoxedUint::zero(64).unwrap();
    assert_eq!(boxed(1).div_rem(&zero).unwrap_err(), MathError::DivisionByZero);
    assert_eq!(boxed(1).rem(&zero).unwrap_err(), MathError::DivisionByZero);
}

#[test]
fn wide_remainder_reduces_full_products() {
    let mut values = Values::new(5);
    for _ in 0..ITERATIONS {
        let (a, b, modulus) = (values.next_u64(), values.next_u64(), values.next_u64() | 1);
        let (x, y, m) = (U64::from_u64(a).unwrap(), U64::from_u64(b).unwrap(), U64::from_u64(modulus).unwrap());
        let (low, high) = x.widening_mul(&y);
        let expected = (a as u128 * b as u128 % modulus as u128) as u64;
        assert_eq!(U64::rem_wide(&low, &high, &m).unwrap(), U64::from_u64(expected).unwrap());
        let (low, high) = (BoxedUint::from_u64(a, 64).unwrap(), BoxedUint::from_u64(b, 64).unwrap());
        let reduced = BoxedUint::rem_wide(&low, &high, &BoxedUint::from_u64(modulus, 64).unwrap()).unwrap();
        let expected = ((((b as u128) << 64) | a as u128) % modulus as u128) as u64;
        assert_eq!(reduced, BoxedUint::from_u64(expected, 64).unwrap());
    }
    // (2^256 - 1)^2 = 2^512 - 2^257 + 1.
    let (low, high) = U256::MAX.widening_mul(&U256::MAX);
    assert_eq!(low, U256::ONE);
    assert_eq!(high, U256::MAX.wrapping_sub(&U256::ONE));
}

#[test]
fn bit_lengths_of_every_single_bit() {
    assert_eq!(U256::ZERO.bit_length(), 0);
    for index in 0..256 {
        assert_eq!(U256::ONE.shl(index).bit_length(), index + 1);
        assert_eq!(U256::MAX.shr(index).bit_length(), 256 - index);
        assert!(U256::ONE.shl(index).bit(index).into_bool());
    }
    assert_eq!(Limbs::limb_bit_length(0), 0);
    for index in 0..Limb::BITS {
        assert_eq!(Limbs::limb_bit_length(1 << index), index + 1);
        assert_eq!(Limbs::limb_bit_length(Limb::MAX >> index), Limb::BITS - index);
    }
    assert_eq!(BoxedUint::one(2048).unwrap().shl(2047).bit_length(), 2048);
}

#[test]
fn shifts_beyond_the_precision_give_zero() {
    for bits in [128, 129, 1000, u32::MAX] {
        assert_eq!(U128::MAX.shl(bits), U128::ZERO);
        assert_eq!(U128::MAX.shr(bits), U128::ZERO);
        assert!(boxed(u128::MAX).shl(bits).is_zero().into_bool());
        assert!(boxed(u128::MAX).shr(bits).is_zero().into_bool());
    }
    assert_eq!(U128::MAX.shl(0), U128::MAX);
}

#[test]
fn resizing_keeps_values_that_fit() {
    let value = uint(u64::MAX as u128);
    assert_eq!(value.resize::<{ Limbs::count(64) }>().unwrap(), U64::from_u64(u64::MAX).unwrap());
    assert_eq!(uint(1 << 64).resize::<{ Limbs::count(64) }>().unwrap_err(), MathError::Overflow);
    let wide: U256 = value.resize().unwrap();
    assert_eq!(wide.to_be_bytes()[24..], u64::MAX.to_be_bytes());
    assert!(wide.to_be_bytes()[..24].iter().all(|&byte| byte == 0));
    assert_eq!(boxed(5).resize(64).unwrap().precision(), 64);
    assert_eq!(boxed(1 << 64).resize(64).unwrap_err(), MathError::Overflow);
    assert_eq!(BoxedUint::from_uint(&uint(9)).unwrap(), boxed(9));
    assert_eq!(boxed(9).to_uint::<{ Limbs::count(128) }>().unwrap(), uint(9));
    assert_eq!(boxed(1 << 64).to_uint::<{ Limbs::count(64) }>().unwrap_err(), MathError::Overflow);
}

#[test]
fn conditional_selection() {
    let (a, b) = (uint(1), uint(2));
    assert_eq!(U128::select(&a, &b, Choice::FALSE), a);
    assert_eq!(U128::select(&a, &b, Choice::TRUE), b);
    let (mut x, mut y) = (a, b);
    U128::conditional_swap(&mut x, &mut y, Choice::TRUE);
    assert_eq!((x, y), (b, a));
    let (mut x, mut y) = (boxed(1), boxed(2));
    BoxedUint::conditional_swap(&mut x, &mut y, Choice::FALSE).unwrap();
    assert_eq!((boxed_int(&x), boxed_int(&y)), (1, 2));
    BoxedUint::conditional_swap(&mut x, &mut y, Choice::TRUE).unwrap();
    assert_eq!((boxed_int(&x), boxed_int(&y)), (2, 1));
    x.conditional_assign(&y, Choice::TRUE).unwrap();
    assert_eq!(boxed_int(&x), 1);
    let mut other = BoxedUint::zero(256).unwrap();
    assert_eq!(other.conditional_assign(&x, Choice::TRUE).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(BoxedUint::conditional_swap(&mut other, &mut x, Choice::TRUE).unwrap_err(), MathError::SizeMismatch);
}

#[test]
#[should_panic(expected = "precision above the maximum")]
fn limbs_beyond_the_maximum_precision_are_refused() {
    let _ = BoxedUint::with_limbs(BoxedUint::limbs_for(BoxedUint::MAXIMUM_PRECISION) + Limbs::count(64));
}

/// The binary GCD against Euclid's algorithm on `u128`, and the remainder by
/// one limb against `u128`.
#[test]
fn boxed_gcd_and_limb_remainders() {
    fn euclid(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    }
    let mut values = crate::Values::new(77);
    for _ in 0..2000 {
        let (a, b) = (values.next_u128(), values.next_u128());
        let boxed = |value: u128| BoxedUint::from_le_bytes(&value.to_le_bytes(), 128).unwrap();
        let gcd = boxed(a).gcd_vartime(&boxed(b));
        assert_eq!(gcd, boxed(euclid(a, b)), "gcd({a}, {b})");
        let divisor = (values.next_u64() >> (values.next_u64() % 64)) as umilib::math::bigint::Limb;
        match boxed(a).rem_limb_vartime(divisor) {
            None => assert_eq!(divisor, 0),
            Some(remainder) => assert_eq!(remainder as u128, a % divisor as u128, "{a} mod {divisor}"),
        }
    }
    // The precisions of the operands may differ.
    let small = BoxedUint::from_u64(12, 64).unwrap();
    let large = BoxedUint::from_u64(18, 256).unwrap();
    assert_eq!(small.gcd_vartime(&large), BoxedUint::from_u64(6, 256).unwrap());
}
