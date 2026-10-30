use crate::math::bigint::{Limb, Limbs, MathError};
use crate::secret::{ConstantTimeEq, DataIndependentTiming, Zeroize};

/// Modular arithmetic on little-endian slices of limbs, shared by
/// [`Modulus`](super::Modulus) and [`BoxedModulus`](super::BoxedModulus).
///
/// The modulus is odd, and values in the Montgomery form `x * R mod modulus`
/// with `R = 2^(Limb::BITS * modulus.len())`. Slices passed together must have
/// the lengths each function states; otherwise the function panics. As in
/// [`Limbs`], timing depends only on the lengths, except in functions whose
/// names end in `_vartime`; exponentiation and inversion set the
/// [`DataIndependentTiming`] mode themselves.
pub struct ModularLimbs;

impl ModularLimbs {
    /// The number of exponent bits [`ModularLimbs::pow`] handles per step.
    pub const WINDOW: u32 = 4;
    /// The number of powers of the base [`ModularLimbs::pow`] precomputes.
    pub const TABLE: usize = 1 << ModularLimbs::WINDOW;

    /// The number of scratch limbs [`ModularLimbs::pow`] needs for a modulus of `size` limbs.
    pub const fn pow_scratch(size: usize) -> usize {
        (ModularLimbs::TABLE + 2) * size
    }

    /// The number of scratch limbs [`ModularLimbs::invert_odd`] needs for a modulus of `size` limbs.
    pub const fn invert_scratch(size: usize) -> usize {
        3 * size
    }

    /// `out = a + b mod modulus` for `a` and `b` below the modulus, all of the same length.
    pub fn add(out: &mut [Limb], a: &[Limb], b: &[Limb], modulus: &[Limb]) {
        assert!(out.len() == modulus.len() && a.len() == modulus.len() && b.len() == modulus.len());
        let carry = Limbs::add(out, a, b);
        let subtract = Limbs::choice(carry) | !Limbs::less_than(out, modulus);
        Limbs::conditional_sub(out, modulus, subtract);
    }

    /// `out = a - b mod modulus` for `a` and `b` below the modulus, all of the same length.
    pub fn sub(out: &mut [Limb], a: &[Limb], b: &[Limb], modulus: &[Limb]) {
        assert!(out.len() == modulus.len() && a.len() == modulus.len() && b.len() == modulus.len());
        let borrow = Limbs::sub(out, a, b);
        Limbs::conditional_add(out, modulus, Limbs::choice(borrow));
    }

    /// `-n0^-1 mod 2^Limb::BITS` for an odd `n0`, by Newton iteration: each
    /// step doubles the number of correct low bits.
    pub const fn montgomery_n_prime(n0: Limb) -> Limb {
        // Every odd number is its own inverse modulo 8: three bits are correct.
        let mut inverse = n0;
        let mut correct = 3;
        while correct < Limb::BITS {
            inverse = inverse.wrapping_mul((2 as Limb).wrapping_sub(n0.wrapping_mul(inverse)));
            correct *= 2;
        }
        inverse.wrapping_neg()
    }

    /// `out = a * b * R^-1 mod modulus` by the coarsely integrated operand
    /// scanning (CIOS) method, where `n_prime` is
    /// [`ModularLimbs::montgomery_n_prime`] of the lowest limb of the odd
    /// modulus. It requires `a * b < modulus * R`, which holds when either
    /// operand is below the modulus; all four slices have the same length.
    pub fn montgomery_mul(out: &mut [Limb], a: &[Limb], b: &[Limb], modulus: &[Limb], n_prime: Limb) {
        let size = modulus.len();
        assert!(size > 0 && out.len() == size && a.len() == size && b.len() == size);
        out.fill(0);
        // `out` holds t[0..size] and `top` holds t[size], which stays 0 or 1
        // because t < a + modulus < 2R; the limb above it lives only within
        // one iteration.
        let mut top: Limb = 0;
        for &b_limb in b {
            let mut carry = 0;
            for index in 0..size {
                (out[index], carry) = Limbs::carrying_mul_add(a[index], b_limb, out[index], carry);
            }
            let (sum, overflow) = Limbs::carrying_add(top, carry, 0);
            let m = out[0].wrapping_mul(n_prime);
            let (_, mut carry) = Limbs::carrying_mul_add(m, modulus[0], out[0], 0);
            for index in 1..size {
                (out[index - 1], carry) = Limbs::carrying_mul_add(m, modulus[index], out[index], carry);
            }
            let (last, extra) = Limbs::carrying_add(sum, carry, 0);
            out[size - 1] = last;
            top = overflow + extra;
        }
        // The result is below 2 * modulus: subtract the modulus once if needed.
        let subtract = Limbs::choice(top) | !Limbs::less_than(out, modulus);
        Limbs::conditional_sub(out, modulus, subtract);
    }

    /// `a = a * R^-1 mod modulus` for any `a` as long as the odd modulus
    /// (Montgomery reduction, which leaves the Montgomery form).
    pub fn montgomery_reduce(a: &mut [Limb], modulus: &[Limb], n_prime: Limb) {
        let size = modulus.len();
        assert!(size > 0 && a.len() == size);
        let mut top: Limb = 0;
        for _ in 0..size {
            let m = a[0].wrapping_mul(n_prime);
            let (_, mut carry) = Limbs::carrying_mul_add(m, modulus[0], a[0], 0);
            for index in 1..size {
                (a[index - 1], carry) = Limbs::carrying_mul_add(m, modulus[index], a[index], carry);
            }
            let (last, extra) = Limbs::carrying_add(top, carry, 0);
            a[size - 1] = last;
            top = extra;
        }
        let subtract = Limbs::choice(top) | !Limbs::less_than(a, modulus);
        Limbs::conditional_sub(a, modulus, subtract);
    }

    /// `out = base^exponent` in the Montgomery form, by a fixed window of
    /// [`ModularLimbs::WINDOW`] bits over every bit of the exponent's
    /// precision; each step reads every table entry, so neither the time nor
    /// the memory accesses depend on the exponent's value. `one` is `R mod
    /// modulus`, and `scratch` holds [`ModularLimbs::pow_scratch`] limbs and is
    /// zeroed on return.
    #[allow(clippy::too_many_arguments)]
    pub fn pow(
        out: &mut [Limb],
        base: &[Limb],
        exponent: &[Limb],
        modulus: &[Limb],
        n_prime: Limb,
        one: &[Limb],
        scratch: &mut [Limb],
    ) {
        let size = modulus.len();
        assert!(base.len() == size && one.len() == size && scratch.len() == ModularLimbs::pow_scratch(size));
        let _timing = DataIndependentTiming::enable();
        let (table, rest) = scratch.split_at_mut(ModularLimbs::TABLE * size);
        let (selected, temporary) = rest.split_at_mut(size);
        table[..size].copy_from_slice(one);
        for index in 1..ModularLimbs::TABLE {
            let (previous, current) = table.split_at_mut(index * size);
            ModularLimbs::montgomery_mul(&mut current[..size], &previous[(index - 1) * size..], base, modulus, n_prime);
        }
        out.copy_from_slice(one);
        let windows = (exponent.len() as u32 * Limb::BITS).div_ceil(ModularLimbs::WINDOW);
        for window in (0..windows).rev() {
            for _ in 0..ModularLimbs::WINDOW {
                temporary.copy_from_slice(out);
                ModularLimbs::montgomery_mul(out, temporary, temporary, modulus, n_prime);
            }
            let mut digit: usize = 0;
            for bit in 0..ModularLimbs::WINDOW {
                digit |= (Limbs::bit(exponent, window * ModularLimbs::WINDOW + bit).bit() as usize) << bit;
            }
            selected.fill(0);
            for (index, entry) in table.chunks_exact(size).enumerate() {
                Limbs::conditional_assign(selected, entry, digit.ct_eq(&index));
            }
            temporary.copy_from_slice(out);
            ModularLimbs::montgomery_mul(out, temporary, selected, modulus, n_prime);
        }
        scratch.zeroize();
    }

    /// `out = base^exponent` in the Montgomery form, by square-and-multiply
    /// over the bits of the exponent: the time depends on the exponent, which
    /// must be public (such as an RSA public exponent). `scratch` holds `size` limbs.
    pub fn pow_vartime(
        out: &mut [Limb],
        base: &[Limb],
        exponent: &[Limb],
        modulus: &[Limb],
        n_prime: Limb,
        one: &[Limb],
        scratch: &mut [Limb],
    ) {
        let size = modulus.len();
        assert!(base.len() == size && one.len() == size && scratch.len() == size);
        out.copy_from_slice(one);
        for bit in (0..Limbs::bit_length(exponent)).rev() {
            scratch.copy_from_slice(out);
            ModularLimbs::montgomery_mul(out, scratch, scratch, modulus, n_prime);
            if Limbs::bit(exponent, bit).into_bool() {
                scratch.copy_from_slice(out);
                ModularLimbs::montgomery_mul(out, scratch, base, modulus, n_prime);
            }
        }
        scratch.zeroize();
    }

    /// `out = a^-1 mod modulus` for an odd `modulus` and any `a` of the same
    /// length (not in the Montgomery form), by a binary extended GCD with a
    /// fixed number of iterations (twice the length in bits); fails (leaving
    /// `out` zeroed) if `a` is not invertible, which is the one fact the time
    /// reveals. `scratch` holds [`ModularLimbs::invert_scratch`] limbs and is
    /// zeroed on return.
    pub fn invert_odd(out: &mut [Limb], a: &[Limb], modulus: &[Limb], scratch: &mut [Limb]) -> Result<(), MathError> {
        let size = modulus.len();
        assert!(
            size > 0 && out.len() == size && a.len() == size && scratch.len() == ModularLimbs::invert_scratch(size)
        );
        out.fill(0);
        if modulus[0] & 1 == 0 {
            return Err(MathError::InvalidModulus);
        }
        let _timing = DataIndependentTiming::enable();
        // Invariants: x ≡ u * a and y ≡ v * a (mod modulus), with y odd;
        // `out` holds v. Each iteration shortens x or y by at least one bit,
        // so at the end x is zero and y is gcd(a, modulus).
        let (x, rest) = scratch.split_at_mut(size);
        let (y, u) = rest.split_at_mut(size);
        x.copy_from_slice(a);
        y.copy_from_slice(modulus);
        u.fill(0);
        u[0] = 1;
        for _ in 0..2 * size as u32 * Limb::BITS {
            let odd = Limbs::choice(x[0]);
            // If x is odd and below y, swap x with y and u with v.
            let swap = odd & Limbs::less_than(x, y);
            Limbs::conditional_swap(x, y, swap);
            Limbs::conditional_swap(u, out, swap);
            // If x is odd, x -= y and u -= v (mod modulus); then x is even.
            Limbs::conditional_sub(x, y, odd);
            let borrow = Limbs::conditional_sub(u, out, odd);
            Limbs::conditional_add(u, modulus, Limbs::choice(borrow));
            // Halve x, and u modulo the odd modulus.
            Limbs::shr_1(x);
            let carry = Limbs::conditional_add(u, modulus, Limbs::choice(u[0]));
            Limbs::shr_1(u);
            u[size - 1] |= carry << (Limb::BITS - 1);
        }
        let invertible = Limbs::is_one(y);
        scratch.zeroize();
        if !invertible.into_bool() {
            out.fill(0);
            return Err(MathError::NotInvertible);
        }
        Ok(())
    }
}
