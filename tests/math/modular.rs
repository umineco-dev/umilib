use umilib::math::bigint::{BoxedUint, Limb, MathError, U64, U128, U256, U384, U576, Uint};
use umilib::math::modular::{BoxedModulus, BoxedResidue, ModularLimbs, Modulus, Residue};

use crate::{Hex, Values};

/// Fewer under Miri, which interprets the code (for example on a 32-bit target).
const ITERATIONS: usize = if cfg!(miri) { 50 } else { 5_000 };

/// `base^exponent mod modulus` for a modulus below 2^64.
fn pow_mod(base: u128, exponent: u128, modulus: u128) -> u128 {
    let mut result = 1 % modulus;
    let mut base = base % modulus;
    let mut exponent = exponent;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

/// `value^-1 mod modulus` by the extended Euclidean algorithm, if it exists.
fn inverse(value: u128, modulus: u128) -> Option<u128> {
    let (mut r0, mut r1) = (modulus as i128, (value % modulus) as i128);
    let (mut t0, mut t1) = (0i128, 1i128);
    while r1 != 0 {
        let quotient = r0 / r1;
        (r0, r1) = (r1, r0 - quotient * r1);
        (t0, t1) = (t1, t0 - quotient * t1);
    }
    (r0 == 1).then(|| t0.rem_euclid(modulus as i128) as u128)
}

fn u64_value(value: u64) -> U64 {
    U64::from_u64(value).unwrap()
}

/// Checks the arithmetic modulo `modulus` (odd, below 2^64) in the precision `N`.
fn check_against_u128<const N: usize>(values: &mut Values, modulus: u64) {
    let wide = |value: u64| Uint::<N>::from_u64(value).unwrap();
    let field = Modulus::new(wide(modulus)).unwrap();
    let m = modulus as u128;
    let (a, b) = (values.next_u64(), values.next_u64());
    let (x, y) = (field.residue(&wide(a)), field.residue(&wide(b)));
    let value = |residue: &Residue<N>| field.retrieve(residue);
    assert_eq!(value(&x), wide((a as u128 % m) as u64));
    assert_eq!(value(&field.add(&x, &y)), wide(((a as u128 + b as u128) % m) as u64));
    assert_eq!(value(&field.sub(&x, &y)), wide(((a as u128 % m + m - b as u128 % m) % m) as u64));
    assert_eq!(value(&field.neg(&x)), wide(((m - a as u128 % m) % m) as u64));
    assert_eq!(value(&field.mul(&x, &y)), wide((a as u128 * b as u128 % m) as u64));
    assert_eq!(value(&field.square(&x)), wide((a as u128 * a as u128 % m) as u64));
    let exponent = values.next_u128();
    let exponent_uint = U128::from_le_bytes(&exponent.to_le_bytes()).unwrap();
    let expected = wide(pow_mod(a as u128, exponent, m) as u64);
    assert_eq!(value(&field.pow(&x, &exponent_uint)), expected);
    assert_eq!(value(&field.pow_vartime(&x, &exponent_uint)), expected);
    match inverse(a as u128, m) {
        Some(expected) => assert_eq!(value(&field.invert(&x).unwrap()), wide(expected as u64)),
        None => assert_eq!(field.invert(&x).unwrap_err(), MathError::NotInvertible),
    }
}

#[test]
fn arithmetic_matches_u128() {
    let mut values = Values::new(10);
    for iteration in 0..ITERATIONS {
        let modulus = match iteration % 4 {
            0 => 3 + 2 * (values.next_u64() % 64),
            1 => u64::MAX - 2 * (values.next_u64() % 64),
            _ => (values.next_u64() >> (values.next_u64() % 60)) | 1,
        }
        .max(3);
        // One limb of 64 bits (two on 32-bit targets), and more limbs than the value needs.
        check_against_u128::<{ umilib::math::bigint::Limbs::count(64) }>(&mut values, modulus);
        check_against_u128::<{ umilib::math::bigint::Limbs::count(192) }>(&mut values, modulus);
    }
}

#[test]
fn boxed_arithmetic_matches_u128() {
    let mut values = Values::new(11);
    for _ in 0..ITERATIONS {
        let modulus = ((values.next_u64() >> (values.next_u64() % 60)) | 1).max(3);
        let m = modulus as u128;
        let field = BoxedModulus::new(BoxedUint::from_u64(modulus, 64).unwrap()).unwrap();
        let (a, b) = (values.next_u64(), values.next_u64());
        let x = field.residue(&BoxedUint::from_u64(a, 64).unwrap());
        let y = field.residue(&BoxedUint::from_u64(b, 64).unwrap());
        let value = |residue: &BoxedResidue| field.retrieve(residue).unwrap();
        let expected = |value: u128| BoxedUint::from_u64(value as u64, 64).unwrap();
        assert_eq!(value(&x), expected(a as u128 % m));
        assert_eq!(value(&field.add(&x, &y).unwrap()), expected((a as u128 + b as u128) % m));
        assert_eq!(value(&field.sub(&x, &y).unwrap()), expected((a as u128 % m + m - b as u128 % m) % m));
        assert_eq!(value(&field.mul(&x, &y).unwrap()), expected(a as u128 * b as u128 % m));
        let exponent = values.next_u128();
        let exponent_uint = BoxedUint::from_le_bytes(&exponent.to_le_bytes(), 128).unwrap();
        let power = expected(pow_mod(a as u128, exponent, m));
        assert_eq!(value(&field.pow(&x, &exponent_uint).unwrap()), power);
        assert_eq!(value(&field.pow_vartime(&x, &exponent_uint).unwrap()), power);
        match inverse(a as u128, m) {
            Some(inverse) => assert_eq!(value(&field.invert(&x).unwrap()), expected(inverse)),
            None => assert_eq!(field.invert(&x).unwrap_err(), MathError::NotInvertible),
        }
    }
}

/// Checks Fermat's little theorem and inversion modulo the prime `hex`.
fn check_prime<const N: usize>(name: &str, hex: &str) {
    let prime = Uint::<N>::from_hex_vartime(hex).unwrap();
    let field = Modulus::new(prime).unwrap();
    let p_minus_1 = prime.wrapping_sub(&Uint::ONE);
    let p_minus_2 = p_minus_1.wrapping_sub(&Uint::ONE);
    let mut values = Values::new(12);
    let mut bases = vec![Uint::<N>::from_u64(2).unwrap(), Uint::from_u64(3).unwrap(), p_minus_1];
    bases.push(Uint::from_le_bytes(&values.next_u128().to_le_bytes()).unwrap());
    // Miri, which interprets the code, runs out of address space on 32-bit targets otherwise.
    bases.truncate(if cfg!(miri) { 1 } else { bases.len() });
    for base in &bases {
        let a = field.residue(base);
        assert_eq!(field.pow(&a, &p_minus_1), field.one(), "{name}: a^(p-1) = 1");
        assert_eq!(field.pow(&a, &prime), a, "{name}: a^p = a");
        let inverse = field.invert(&a).unwrap();
        assert_eq!(field.mul(&a, &inverse), field.one(), "{name}: a * a^-1 = 1");
        assert_eq!(inverse, field.pow(&a, &p_minus_2), "{name}: a^-1 = a^(p-2)");
        assert_eq!(field.pow_vartime(&a, &p_minus_2), inverse, "{name}");
    }
    assert_eq!(field.invert(&field.zero()).unwrap_err(), MathError::NotInvertible);
    // p - 1 is -1, whose square is one.
    assert_eq!(field.square(&field.residue(&p_minus_1)), field.one());
    assert_eq!(field.residue(&p_minus_1), field.neg(&field.one()));
}

#[test]
fn fermat_little_theorem_holds_for_specified_primes() {
    // FIPS 186-5 / SP 800-186 and SEC 2: field primes and group orders.
    check_prime::<{ U256::LIMBS }>("P-256 p", "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    // Under Miri, which interprets the code thousands of times more slowly,
    // one prime covers the code paths; the others repeat them at other sizes.
    if cfg!(miri) {
        return;
    }
    check_prime::<{ U256::LIMBS }>("P-256 n", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    check_prime::<{ U256::LIMBS }>("secp256k1 p", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    check_prime::<{ U256::LIMBS }>("secp256k1 n", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    check_prime::<{ U384::LIMBS }>(
        "P-384 p",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    );
    check_prime::<{ U384::LIMBS }>(
        "P-384 n",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    );
    check_prime::<{ U576::LIMBS }>("P-521 p", &format!("1{}", "f".repeat(130)));
    check_prime::<{ U576::LIMBS }>(
        "P-521 n",
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    );
    // RFC 7748 and RFC 8032: 2^255 - 19.
    check_prime::<{ U256::LIMBS }>("2^255 - 19", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
}

#[test]
fn edwards25519_constants_of_rfc8032() {
    let p = U256::from_hex_vartime("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed").unwrap();
    let field = Modulus::new(p).unwrap();
    let value = |number: u64| field.residue(&U256::from_u64(number).unwrap());
    // Section 5.1: d = -121665/121666, given in decimal as
    // 37095705934669439343138083508754565189542113879843219016388785533085940283555.
    let d = field.mul(&field.neg(&value(121665)), &field.invert(&value(121666)).unwrap());
    let expected = U256::from_hex_vartime("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3").unwrap();
    assert_eq!(field.retrieve(&d), expected);
    // Section 5.1.3: 2^((p-1)/4) is a square root of -1.
    let exponent = p.wrapping_sub(&U256::ONE).shr(2);
    let root = field.pow(&value(2), &exponent);
    assert_eq!(field.square(&root), field.neg(&field.one()));
}

#[test]
fn composite_and_invalid_moduli() {
    let field = Modulus::new(u64_value(15)).unwrap();
    let value = |number: u64| field.residue(&u64_value(number));
    assert_eq!(field.invert(&value(5)).unwrap_err(), MathError::NotInvertible);
    assert_eq!(field.invert(&value(0)).unwrap_err(), MathError::NotInvertible);
    assert_eq!(field.retrieve(&field.invert(&value(2)).unwrap()), u64_value(8));
    assert_eq!(field.retrieve(&field.pow(&value(2), &u64_value(14))), u64_value(4));
    for invalid in [0, 1, 2, 4, 1 << 40] {
        assert_eq!(Modulus::new(u64_value(invalid)).unwrap_err(), MathError::InvalidModulus, "{invalid}");
        let boxed = BoxedUint::from_u64(invalid, 128).unwrap();
        assert_eq!(BoxedModulus::new(boxed).unwrap_err(), MathError::InvalidModulus, "{invalid}");
    }
    assert!(Modulus::new(u64_value(3)).is_ok());
    assert!(Modulus::new(U64::MAX).is_ok());
}

#[test]
fn residues_of_values_above_the_modulus_are_reduced() {
    let field = Modulus::new(u64_value(1_000_003)).unwrap();
    assert_eq!(field.retrieve(&field.residue(&U64::MAX)), u64_value(u64::MAX % 1_000_003));
    let boxed = BoxedModulus::new(BoxedUint::from_u64(1_000_003, 64).unwrap()).unwrap();
    let large = BoxedUint::from_hex_vartime(&"f".repeat(100), 512).unwrap();
    let mut expected = BoxedUint::from_hex_vartime(&"f".repeat(100), 512).unwrap();
    expected = expected.rem(&BoxedUint::from_u64(1_000_003, 64).unwrap()).unwrap();
    assert_eq!(boxed.retrieve(&boxed.residue(&large)).unwrap(), expected);
}

#[test]
fn montgomery_forms_are_checked() {
    let field = Modulus::new(u64_value(101)).unwrap();
    let residue = field.residue(&u64_value(7));
    assert_eq!(field.from_montgomery(residue.as_montgomery()).unwrap(), residue);
    assert_eq!(field.from_montgomery(&u64_value(101)).unwrap_err(), MathError::Overflow);
    let boxed = BoxedModulus::new(BoxedUint::from_u64(101, 64).unwrap()).unwrap();
    let residue = boxed.residue(&BoxedUint::from_u64(7, 64).unwrap());
    assert_eq!(boxed.from_montgomery(residue.as_montgomery()).unwrap(), residue);
    assert_eq!(boxed.from_montgomery(&BoxedUint::from_u64(101, 64).unwrap()).unwrap_err(), MathError::Overflow);
    assert_eq!(boxed.from_montgomery(&BoxedUint::from_u64(1, 128).unwrap()).unwrap_err(), MathError::SizeMismatch);
}

#[test]
fn boxed_residues_of_another_precision_are_rejected() {
    let small = BoxedModulus::new(BoxedUint::from_u64(101, 64).unwrap()).unwrap();
    let large = BoxedModulus::new(BoxedUint::from_u64(101, 128).unwrap()).unwrap();
    let residue = small.one();
    assert_eq!(large.add(&residue, &large.one()).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(large.sub(&large.one(), &residue).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(large.mul(&residue, &residue).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(large.pow(&residue, &BoxedUint::one(64).unwrap()).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(large.invert(&residue).unwrap_err(), MathError::SizeMismatch);
    assert_eq!(large.retrieve(&residue).unwrap_err(), MathError::SizeMismatch);
}

#[test]
fn powers_with_zero_exponents_and_bases() {
    let field = Modulus::new(u64_value(101)).unwrap();
    assert_eq!(field.pow(&field.residue(&u64_value(5)), &U64::ZERO), field.one());
    assert_eq!(field.pow(&field.zero(), &U64::ZERO), field.one());
    assert_eq!(field.pow(&field.zero(), &u64_value(3)), field.zero());
    assert_eq!(field.pow_vartime(&field.zero(), &U64::ZERO), field.one());
}

#[test]
fn montgomery_n_prime_is_the_negated_inverse() {
    let mut values = Values::new(13);
    for _ in 0..ITERATIONS {
        let n0 = (values.next_u64() as Limb) | 1;
        assert_eq!(n0.wrapping_mul(ModularLimbs::montgomery_n_prime(n0)), Limb::MAX);
    }
}

/// The primes of RFC 3526, in the order of the RFC.
fn modp_primes() -> Vec<Vec<u8>> {
    let text = crate::Vectors::read("math/modular/rfc3526.txt");
    let mut primes = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim_end().ends_with("hexadecimal value is:") {
            let digits: String = lines.by_ref().skip(1).take_while(|line| !line.trim().is_empty()).collect();
            primes.push(Hex::decode(&digits));
        }
    }
    primes
}

#[test]
#[cfg_attr(
    miri,
    ignore = "1536-bit exponentiations take hours under Miri; the code paths are covered at smaller sizes"
)]
fn modp_groups_of_rfc3526() {
    let primes = modp_primes();
    assert_eq!(primes.iter().map(|prime| prime.len() * 8).collect::<Vec<_>>(), [1536, 2048, 3072, 4096, 6144, 8192]);
    // The 6144- and 8192-bit groups are left out to keep the test fast without
    // optimizations; no algorithm depends on the size beyond its loop counts.
    for prime in &primes[..4] {
        let bits = prime.len() as u32 * 8;
        let p = BoxedUint::from_be_bytes(prime, bits).unwrap();
        let field = BoxedModulus::new(p.clone()).unwrap();
        let generator = field.residue(&BoxedUint::from_u64(2, 64).unwrap());
        let p_minus_1 = p.wrapping_sub(&BoxedUint::one(64).unwrap());
        // Each p is a safe prime, p = 2q + 1, and p ≡ 7 (mod 8), so 2 is a square:
        // it generates the subgroup of order q.
        assert_eq!(field.pow(&generator, &p_minus_1).unwrap(), field.one(), "{bits}");
        assert_eq!(field.pow(&generator, &p_minus_1.shr(1)).unwrap(), field.one(), "{bits}");
        let mut values = Values::new(bits as u64);
        let exponent_bytes: Vec<u8> = (0..prime.len() / 8).flat_map(|_| values.next_u64().to_be_bytes()).collect();
        let exponent = BoxedUint::from_be_bytes(&exponent_bytes, bits).unwrap();
        let power = field.pow(&generator, &exponent).unwrap();
        assert_eq!(field.pow_vartime(&generator, &exponent).unwrap(), power, "{bits}");
        let inverse = field.invert(&power).unwrap();
        assert_eq!(field.mul(&inverse, &power).unwrap(), field.one(), "{bits}");
    }
}

#[test]
fn boxed_residues_select_without_branching() {
    use umilib::secret::Choice;
    let field = BoxedModulus::new(BoxedUint::from_u64(101, 64).unwrap()).unwrap();
    let (mut a, mut b) = (field.residue(&BoxedUint::from_u64(3, 64).unwrap()), field.one());
    BoxedResidue::conditional_swap(&mut a, &mut b, Choice::FALSE).unwrap();
    assert_eq!(
        (field.retrieve(&a).unwrap(), field.retrieve(&b).unwrap()),
        (BoxedUint::from_u64(3, 64).unwrap(), BoxedUint::one(64).unwrap())
    );
    BoxedResidue::conditional_swap(&mut a, &mut b, Choice::TRUE).unwrap();
    assert_eq!(a, field.one());
    a.conditional_assign(&b, Choice::TRUE).unwrap();
    assert_eq!(field.retrieve(&a).unwrap(), BoxedUint::from_u64(3, 64).unwrap());
    let other = BoxedModulus::new(BoxedUint::from_u64(101, 128).unwrap()).unwrap().one();
    assert_eq!(a.conditional_assign(&other, Choice::TRUE).unwrap_err(), MathError::SizeMismatch);
}

#[test]
fn long_operations_leave_the_timing_mode_as_they_found_it() {
    use umilib::secret::DataIndependentTiming;
    let field = Modulus::new(u64_value(1_000_003)).unwrap();
    let before = DataIndependentTiming::is_enabled();
    let x = field.residue(&u64_value(12345));
    let _ = field.pow(&x, &u64_value(77));
    let _ = field.invert(&x).unwrap();
    let _ = u64_value(10).div_rem(&u64_value(3)).unwrap();
    assert_eq!(DataIndependentTiming::is_enabled(), before);
}

/// The modulus of P-256 (FIPS 186-5), built at compile time.
const P256: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
));

#[test]
fn moduli_built_at_compile_time_equal_those_built_at_run_time() {
    let mut values = Values::new(41);
    for modulus in [P256.value().to_owned(), U256::from_hex_vartime_or_panic("3"), U256::MAX] {
        let at_run_time = Modulus::new(modulus).unwrap();
        let at_compile_time = Modulus::new_vartime(modulus).unwrap();
        for _ in 0..ITERATIONS / 50 {
            let bytes: Vec<u8> = (0..4).flat_map(|_| values.next_u64().to_be_bytes()).collect();
            let x = U256::from_be_bytes(&bytes).unwrap().rem(&modulus).unwrap();
            // The same Montgomery constants give the same residues and results.
            assert_eq!(at_compile_time.residue(&x), at_run_time.residue(&x));
            assert_eq!(at_compile_time.residue_vartime(&x), at_run_time.residue(&x));
            assert_eq!(at_compile_time.one(), at_run_time.one());
            let square = at_run_time.square(&at_run_time.residue(&x));
            assert_eq!(
                at_compile_time.retrieve(&at_compile_time.square(&at_compile_time.residue(&x))),
                at_run_time.retrieve(&square)
            );
        }
    }
    for invalid in [U256::ZERO, U256::ONE, U256::from_hex_vartime_or_panic("2"), U256::from_hex_vartime_or_panic("100")]
    {
        assert_eq!(Modulus::new_vartime(invalid).unwrap_err(), MathError::InvalidModulus, "{invalid:x}");
        assert_eq!(Modulus::new(invalid).unwrap_err(), MathError::InvalidModulus, "{invalid:x}");
    }
}

/// FIPS 186-5 appendix B.3.1: primes pass every round; composites fail for
/// some base, and the strong pseudoprimes to base 2 pass that base alone.
#[test]
fn miller_rabin_rounds() {
    let round = |n: u64, base: u64| {
        let modulus = BoxedModulus::new(BoxedUint::from_u64(n, 64).unwrap()).unwrap();
        modulus.miller_rabin(&BoxedUint::from_u64(base, 64).unwrap()).unwrap().into_bool()
    };
    for prime in [3u64, 5, 7, 13, 65537, 2_147_483_647, 1_000_000_007, 18_446_744_073_709_551_557] {
        for base in [2u64, 3, 5, 7, 11] {
            if base < prime - 1 {
                assert!(round(prime, base), "{prime} base {base}");
            }
        }
    }
    // 2047 = 23 × 89 and 3277 = 29 × 113 are strong pseudoprimes to base 2 (OEIS A001262).
    for pseudoprime in [2047u64, 3277, 4033, 4681, 8321] {
        assert!(round(pseudoprime, 2), "{pseudoprime}");
        assert!(!round(pseudoprime, 3), "{pseudoprime}");
    }
    // Carmichael numbers fail a strong test.
    for composite in [9u64, 15, 561, 1105, 1729, 2465, 6601, 1_000_000_007 * 3] {
        assert!(!round(composite, 2) || !round(composite, 3), "{composite}");
    }
    // The safe primes of RFC 3526 pass.
    let text = crate::Vectors::read("math/modular/rfc3526.txt");
    let start = text.find("1536-bit MODP Group").unwrap();
    let hex: String = text[start..]
        .lines()
        .skip_while(|line| !line.trim().starts_with("FFFFFFFF FFFFFFFF C90FDAA2"))
        .take_while(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("")
        .split_whitespace()
        .collect();
    let prime = BoxedUint::from_hex_vartime(&hex, 1536).unwrap();
    let modulus = BoxedModulus::new(prime).unwrap();
    assert!(modulus.miller_rabin(&BoxedUint::from_u64(2, 64).unwrap()).unwrap().into_bool());
    assert!(modulus.miller_rabin(&BoxedUint::from_u64(12345, 64).unwrap()).unwrap().into_bool());
}
