use alloc::vec::Vec;
use core::fmt;

use super::{BoxedResidue, ModularLimbs};
use crate::math::bigint::{BoxedUint, Limb, MathError};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// An odd modulus of a precision chosen at run time, at least 3, with its
/// Montgomery constants. Residues have the precision of the modulus. Every
/// field is zeroed when the modulus is dropped.
#[derive(Clone)]
pub struct BoxedModulus {
    value: BoxedUint,
    n_prime: Limb,
    /// `R mod value`, the Montgomery form of one.
    one: BoxedUint,
    /// `R^2 mod value`, which converts into the Montgomery form.
    r2: BoxedUint,
}

impl BoxedModulus {
    /// Prepares `value`, keeping its precision; fails if it is even or below
    /// 3. The time depends only on the precision, so the modulus may be
    /// secret (an RSA prime).
    pub fn new(value: BoxedUint) -> Result<BoxedModulus, MathError> {
        let size = value.as_limbs().len();
        let unit = BoxedUint::one(0)?;
        if !(value.is_odd() & value.ct_gt(&unit)).into_bool() {
            return Err(MathError::InvalidModulus);
        }
        // R mod value and R^2 mod value, as remainders of R * 1 and R * (R mod value).
        let zero = BoxedUint::with_limbs(size);
        let one = BoxedUint::rem_wide(&zero, &unit, &value)?;
        let r2 = BoxedUint::rem_wide(&zero, &one, &value)?;
        let n_prime = ModularLimbs::montgomery_n_prime(value.as_limbs()[0]);
        Ok(BoxedModulus { value, n_prime, one, r2 })
    }

    pub fn value(&self) -> &BoxedUint {
        &self.value
    }

    /// The precision in bits of the modulus and its residues.
    pub fn precision(&self) -> u32 {
        self.value.precision()
    }

    pub fn zero(&self) -> BoxedResidue {
        BoxedResidue::from_montgomery_unchecked(BoxedUint::with_limbs(self.size()))
    }

    pub fn one(&self) -> BoxedResidue {
        BoxedResidue::from_montgomery_unchecked(self.one.clone())
    }

    /// The number of limbs of the modulus.
    pub fn size(&self) -> usize {
        self.value.as_limbs().len()
    }

    /// Zeroed scratch memory of `limbs` limbs for [`ModularLimbs`], whose
    /// functions zero it again on return; fails if it cannot be allocated,
    /// because it may be much larger than the modulus.
    pub fn scratch(limbs: usize) -> Result<Vec<Limb>, MathError> {
        let mut scratch = Vec::new();
        scratch.try_reserve_exact(limbs).map_err(|_| MathError::AllocationFailed)?;
        scratch.resize(limbs, 0);
        Ok(scratch)
    }

    /// Fails unless `residue` has the precision of the modulus.
    pub fn check(&self, residue: &BoxedResidue) -> Result<(), MathError> {
        if residue.as_montgomery().as_limbs().len() != self.size() {
            return Err(MathError::SizeMismatch);
        }
        Ok(())
    }

    /// `x mod modulus` as a residue; `x` may have any precision.
    pub fn residue(&self, x: &BoxedUint) -> BoxedResidue {
        // A value longer than the modulus is reduced first, so that it is
        // below R; then x < R and r2 < modulus keep the product below modulus * R.
        let reduced = if x.as_limbs().len() > self.size() {
            // The modulus is not zero.
            x.rem(&self.value).unwrap_or_else(|_| BoxedUint::with_limbs(self.size()))
        } else {
            let mut extended = BoxedUint::with_limbs(self.size());
            extended.as_limbs_mut()[..x.as_limbs().len()].copy_from_slice(x.as_limbs());
            extended
        };
        let mut montgomery = BoxedUint::with_limbs(self.size());
        ModularLimbs::montgomery_mul(
            montgomery.as_limbs_mut(),
            reduced.as_limbs(),
            self.r2.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
        );
        BoxedResidue::from_montgomery_unchecked(montgomery)
    }

    /// The value of `residue`, below the modulus, in its precision.
    pub fn retrieve(&self, residue: &BoxedResidue) -> Result<BoxedUint, MathError> {
        self.check(residue)?;
        let mut value = residue.as_montgomery().clone();
        ModularLimbs::montgomery_reduce(value.as_limbs_mut(), self.value.as_limbs(), self.n_prime);
        Ok(value)
    }

    /// The residue whose Montgomery form is `montgomery`; fails if it is not
    /// below the modulus or has another precision.
    pub fn from_montgomery(&self, montgomery: &BoxedUint) -> Result<BoxedResidue, MathError> {
        if montgomery.as_limbs().len() != self.size() {
            return Err(MathError::SizeMismatch);
        }
        if !montgomery.ct_lt(&self.value).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(BoxedResidue::from_montgomery_unchecked(montgomery.clone()))
    }

    pub fn add(&self, a: &BoxedResidue, b: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        self.check(a)?;
        self.check(b)?;
        let mut sum = BoxedUint::with_limbs(self.size());
        ModularLimbs::add(
            sum.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
        );
        Ok(BoxedResidue::from_montgomery_unchecked(sum))
    }

    pub fn sub(&self, a: &BoxedResidue, b: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        self.check(a)?;
        self.check(b)?;
        let mut difference = BoxedUint::with_limbs(self.size());
        ModularLimbs::sub(
            difference.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
        );
        Ok(BoxedResidue::from_montgomery_unchecked(difference))
    }

    pub fn neg(&self, a: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        self.sub(&self.zero(), a)
    }

    pub fn mul(&self, a: &BoxedResidue, b: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        self.check(a)?;
        self.check(b)?;
        let mut product = BoxedUint::with_limbs(self.size());
        ModularLimbs::montgomery_mul(
            product.as_limbs_mut(),
            a.as_montgomery().as_limbs(),
            b.as_montgomery().as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
        );
        Ok(BoxedResidue::from_montgomery_unchecked(product))
    }

    pub fn square(&self, a: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        self.mul(a, a)
    }

    /// `base^exponent`, over every bit of the exponent's precision, in constant time.
    pub fn pow(&self, base: &BoxedResidue, exponent: &BoxedUint) -> Result<BoxedResidue, MathError> {
        self.check(base)?;
        let mut power = BoxedUint::with_limbs(self.size());
        let mut scratch = BoxedModulus::scratch(ModularLimbs::pow_scratch(self.size()))?;
        ModularLimbs::pow(
            power.as_limbs_mut(),
            base.as_montgomery().as_limbs(),
            exponent.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
            self.one.as_limbs(),
            &mut scratch,
        );
        Ok(BoxedResidue::from_montgomery_unchecked(power))
    }

    /// `base^exponent`, in time that depends on the exponent, which must be public.
    pub fn pow_vartime(&self, base: &BoxedResidue, exponent: &BoxedUint) -> Result<BoxedResidue, MathError> {
        self.check(base)?;
        let mut power = BoxedUint::with_limbs(self.size());
        let mut scratch = BoxedModulus::scratch(self.size())?;
        ModularLimbs::pow_vartime(
            power.as_limbs_mut(),
            base.as_montgomery().as_limbs(),
            exponent.as_limbs(),
            self.value.as_limbs(),
            self.n_prime,
            self.one.as_limbs(),
            &mut scratch,
        );
        Ok(BoxedResidue::from_montgomery_unchecked(power))
    }

    /// One round of the Miller–Rabin test (FIPS 186-5 appendix B.3.1) of the
    /// modulus with the base `base`, which should be in 2..modulus - 1:
    /// whether the modulus is a strong probable prime to that base. The
    /// exponentiation is constant time; the time depends on the number of
    /// trailing zero bits of modulus - 1 and on nothing else.
    pub fn miller_rabin(&self, base: &BoxedUint) -> Result<Choice, MathError> {
        let one = self.one();
        let minus_one = self.neg(&one)?;
        let value_minus_one = self.value.wrapping_sub(&BoxedUint::one(self.value.precision())?);
        let mut twos = 0;
        while twos < value_minus_one.bit_length() && !value_minus_one.bit(twos).into_bool() {
            twos += 1;
        }
        let mut odd = value_minus_one.shr(twos);
        let mut z = self.pow(&self.residue(base), &odd)?;
        odd.zeroize();
        // Prime if z = 1 or z = -1 now, or z = -1 after some squaring before z = 1.
        let mut probable = z.ct_eq(&one) | z.ct_eq(&minus_one);
        let mut decided = probable;
        for _ in 1..twos {
            z = self.square(&z)?;
            let minus = z.ct_eq(&minus_one);
            probable |= !decided & minus;
            decided |= minus | z.ct_eq(&one);
        }
        z.zeroize();
        Ok(probable)
    }

    /// `a^-1`; fails if `a` is not invertible (shares a factor with the
    /// modulus), which is the one fact the time reveals.
    pub fn invert(&self, a: &BoxedResidue) -> Result<BoxedResidue, MathError> {
        let value = self.retrieve(a)?;
        let mut inverse = BoxedUint::with_limbs(self.size());
        let mut scratch = BoxedModulus::scratch(ModularLimbs::invert_scratch(self.size()))?;
        ModularLimbs::invert_odd(inverse.as_limbs_mut(), value.as_limbs(), self.value.as_limbs(), &mut scratch)?;
        Ok(self.residue(&inverse))
    }
}

impl Drop for BoxedModulus {
    /// Zeroizes `n_prime`; the values zeroize themselves.
    fn drop(&mut self) {
        self.n_prime.zeroize();
    }
}

impl ConstantTimeEq for BoxedModulus {
    fn ct_eq(&self, other: &BoxedModulus) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl PartialEq for BoxedModulus {
    fn eq(&self, other: &BoxedModulus) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl Eq for BoxedModulus {}

impl Zeroize for BoxedModulus {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.n_prime.zeroize();
        self.one.zeroize();
        self.r2.zeroize();
    }
}

impl fmt::Debug for BoxedModulus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BoxedModulus(0x{:x})", self.value)
    }
}
