use core::fmt;

use super::{ModularLimbs, Residue};
use crate::math::bigint::{Limb, MathError, Uint};
use crate::secret::{ConstantTimeEq, Zeroize};

/// An odd modulus of `N` limbs, at least 3, with its Montgomery constants.
///
/// It is `Copy`, so it cannot zeroize itself when dropped: call
/// [`Zeroize::zeroize`] on a secret modulus (or keep it in a
/// [`Secret`](crate::secret::Secret)), which [`BoxedModulus`](super::BoxedModulus) does on its own.
#[derive(Clone, Copy)]
pub struct Modulus<const N: usize> {
    value: Uint<N>,
    n_prime: Limb,
    /// `R mod value`, the Montgomery form of one.
    one: Uint<N>,
    /// `R^2 mod value`, which converts into the Montgomery form.
    r2: Uint<N>,
}

impl<const N: usize> Modulus<N> {
    /// Prepares `value`; fails if it is even or below 3. The time depends
    /// only on the precision, so the modulus may be secret (an RSA prime).
    pub fn new(value: Uint<N>) -> Result<Modulus<N>, MathError> {
        if N == 0 || !(value.is_odd() & value.ct_gt(&Uint::ONE)).into_bool() {
            return Err(MathError::InvalidModulus);
        }
        // R mod value and R^2 mod value, as remainders of R * 1 and R * (R mod value).
        let one = Uint::rem_wide(&Uint::ZERO, &Uint::ONE, &value)?;
        let r2 = Uint::rem_wide(&Uint::ZERO, &one, &value)?;
        Ok(Modulus { value, n_prime: ModularLimbs::montgomery_n_prime(value.as_limbs()[0]), one, r2 })
    }

    /// Prepares the public `value` in a `const` context, for constants such as
    /// the field of an elliptic curve; fails like [`Modulus::new`]. The time
    /// depends on the value, which must be public.
    pub const fn new_vartime(value: Uint<N>) -> Result<Modulus<N>, MathError> {
        let limbs = value.as_limbs();
        if N == 0 || limbs[0] & 1 == 0 || Modulus::less_than_vartime(&value, &Uint::from_limb(3)) {
            return Err(MathError::InvalidModulus);
        }
        // R mod value: 1 doubled BITS times modulo value; R^2 mod value: BITS more doublings.
        let one = Modulus::double_times_vartime(Uint::ONE, &value, Uint::<N>::BITS);
        let r2 = Modulus::double_times_vartime(one, &value, Uint::<N>::BITS);
        Ok(Modulus { value, n_prime: ModularLimbs::montgomery_n_prime(limbs[0]), one, r2 })
    }

    /// [`Modulus::new_vartime`] for constants: an invalid modulus fails the compilation.
    pub const fn new_vartime_or_panic(value: Uint<N>) -> Modulus<N> {
        match Modulus::new_vartime(value) {
            Ok(modulus) => modulus,
            Err(_) => panic!("the modulus is even or below 3"),
        }
    }

    /// The residue of the public `x`, which must be below the modulus, in a
    /// `const` context: for constants such as the coefficients of a curve. The
    /// time depends on the value; a value not below the modulus fails the
    /// compilation.
    pub const fn residue_vartime(&self, x: &Uint<N>) -> Residue<N> {
        assert!(Modulus::less_than_vartime(x, &self.value), "the value is not below the modulus");
        Residue::from_montgomery_unchecked(Modulus::double_times_vartime(*x, &self.value, Uint::<N>::BITS))
    }

    /// `x × 2^times mod modulus` for `x` below the modulus, by doublings in a `const` context.
    pub const fn double_times_vartime(x: Uint<N>, modulus: &Uint<N>, times: u32) -> Uint<N> {
        let mut limbs = x.into_limbs();
        let modulus = modulus.as_limbs();
        let mut step = 0;
        while step < times {
            // Shift left by one bit, keeping the bit shifted out.
            let mut carry = 0;
            let mut index = 0;
            while index < N {
                let next = limbs[index] >> (Limb::BITS - 1);
                limbs[index] = (limbs[index] << 1) | carry;
                carry = next;
                index += 1;
            }
            // 2x < 2 × modulus: subtract the modulus once if the carry is set or 2x ≥ modulus.
            if carry == 1 || !Modulus::less_than_vartime(&Uint::from_limbs(limbs), &Uint::from_limbs(*modulus)) {
                let mut borrow = 0;
                let mut index = 0;
                while index < N {
                    let (difference, first) = limbs[index].overflowing_sub(modulus[index]);
                    let (difference, second) = difference.overflowing_sub(borrow);
                    limbs[index] = difference;
                    borrow = (first | second) as Limb;
                    index += 1;
                }
            }
            step += 1;
        }
        Uint::from_limbs(limbs)
    }

    /// `a < b`, in a `const` context, in time that depends on the values.
    pub const fn less_than_vartime(a: &Uint<N>, b: &Uint<N>) -> bool {
        let (a, b) = (a.as_limbs(), b.as_limbs());
        let mut index = N;
        while index > 0 {
            index -= 1;
            if a[index] != b[index] {
                return a[index] < b[index];
            }
        }
        false
    }

    pub const fn value(&self) -> &Uint<N> {
        &self.value
    }

    pub fn zero(&self) -> Residue<N> {
        Residue::from_montgomery_unchecked(Uint::ZERO)
    }

    pub fn one(&self) -> Residue<N> {
        Residue::from_montgomery_unchecked(self.one)
    }

    /// `x mod modulus` as a residue; `x` may be any value of the precision.
    pub fn residue(&self, x: &Uint<N>) -> Residue<N> {
        // x < R and r2 < modulus, so the product is below modulus * R.
        let mut montgomery = Uint::ZERO;
        ModularLimbs::montgomery_mul(
            montgomery.as_limbs_mut(),
            x.as_limbs(),
            self.r2.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
        );
        Residue::from_montgomery_unchecked(montgomery)
    }

    /// The value of `residue`, below the modulus.
    pub fn retrieve(&self, residue: &Residue<N>) -> Uint<N> {
        let mut value = *residue.as_montgomery();
        ModularLimbs::montgomery_reduce(value.as_limbs_mut(), self.value.as_limbs(), self.n_prime);
        value
    }

    /// The residue whose Montgomery form is `montgomery`; fails if it is not below the modulus.
    pub fn from_montgomery(&self, montgomery: &Uint<N>) -> Result<Residue<N>, MathError> {
        if !montgomery.ct_lt(&self.value).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(Residue::from_montgomery_unchecked(*montgomery))
    }

    pub fn add(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        let mut sum = Uint::ZERO;
        ModularLimbs::add(
            sum.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
        );
        Residue::from_montgomery_unchecked(sum)
    }

    pub fn sub(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        let mut difference = Uint::ZERO;
        ModularLimbs::sub(
            difference.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
        );
        Residue::from_montgomery_unchecked(difference)
    }

    pub fn neg(&self, a: &Residue<N>) -> Residue<N> {
        self.sub(&self.zero(), a)
    }

    pub fn mul(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        let mut product = Uint::ZERO;
        ModularLimbs::montgomery_mul(
            product.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
        );
        Residue::from_montgomery_unchecked(product)
    }

    pub fn square(&self, a: &Residue<N>) -> Residue<N> {
        self.mul(a, a)
    }

    /// `base^exponent`, over every bit of the exponent's precision, in constant time.
    pub fn pow<const M: usize>(&self, base: &Residue<N>, exponent: &Uint<M>) -> Residue<N> {
        let mut power = Uint::ZERO;
        let mut scratch = [[0 as Limb; N]; ModularLimbs::TABLE + 2];
        ModularLimbs::pow(
            power.as_limbs_mut(),
            base.as_montgomery().as_limbs(),
            exponent.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
            self.one.as_limbs(),
            scratch.as_flattened_mut(),
        );
        Residue::from_montgomery_unchecked(power)
    }

    /// `base^exponent`, in time that depends on the exponent, which must be public.
    pub fn pow_vartime<const M: usize>(&self, base: &Residue<N>, exponent: &Uint<M>) -> Residue<N> {
        let mut power = Uint::ZERO;
        let mut scratch = [0 as Limb; N];
        ModularLimbs::pow_vartime(
            power.as_limbs_mut(),
            base.as_montgomery().as_limbs(),
            exponent.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
            self.one.as_limbs(),
            &mut scratch,
        );
        Residue::from_montgomery_unchecked(power)
    }

    /// `a^-1`; fails if `a` is not invertible (shares a factor with the
    /// modulus), which is the one fact the time reveals.
    pub fn invert(&self, a: &Residue<N>) -> Result<Residue<N>, MathError> {
        let mut value = self.retrieve(a);
        let mut inverse = Uint::ZERO;
        let mut scratch = [[0 as Limb; N]; 3];
        let result = ModularLimbs::invert_odd(
            inverse.as_limbs_mut(),
            value.as_limbs(),
            self.value.as_limbs(),
            scratch.as_flattened_mut(),
        );
        value.zeroize();
        result?;
        let residue = self.residue(&inverse);
        inverse.zeroize();
        Ok(residue)
    }
}

impl<const N: usize> ConstantTimeEq for Modulus<N> {
    fn ct_eq(&self, other: &Modulus<N>) -> crate::secret::Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<const N: usize> PartialEq for Modulus<N> {
    fn eq(&self, other: &Modulus<N>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<const N: usize> Eq for Modulus<N> {}

impl<const N: usize> Zeroize for Modulus<N> {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.n_prime.zeroize();
        self.one.zeroize();
        self.r2.zeroize();
    }
}

impl<const N: usize> fmt::Debug for Modulus<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Modulus(0x{:x})", self.value)
    }
}
