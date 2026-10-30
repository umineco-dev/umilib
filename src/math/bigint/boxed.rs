use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitXor, Not};

use super::{Limb, Limbs, MathError, Uint, WideLimb};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// An unsigned integer whose precision is chosen at run time, on the heap.
///
/// The precision is a multiple of [`BoxedUint::PRECISION_UNIT`] bits, the
/// same on every platform. Operands of different precisions are zero-extended
/// to the larger one, which is the precision of the result unless a method
/// says otherwise. The limbs are zeroed when the value is dropped.
pub struct BoxedUint {
    limbs: Box<[Limb]>,
}

impl BoxedUint {
    /// Precisions are rounded up to a multiple of this many bits (at least one).
    pub const PRECISION_UNIT: u32 = 64;
    /// The largest precision, so that bit counts of double-width values fit a `u32`.
    pub const MAXIMUM_PRECISION: u32 = 1 << 30;

    /// The number of limbs that hold `precision` bits, rounded up to the unit.
    pub const fn limbs_for(precision: u32) -> usize {
        let units = if precision == 0 { 1 } else { precision.div_ceil(BoxedUint::PRECISION_UNIT) };
        units as usize * Limbs::count(BoxedUint::PRECISION_UNIT)
    }

    /// Zero of the given precision; fails if it exceeds the maximum or cannot be allocated.
    pub fn zero(precision: u32) -> Result<BoxedUint, MathError> {
        if precision > BoxedUint::MAXIMUM_PRECISION {
            return Err(MathError::InvalidPrecision { precision, maximum: BoxedUint::MAXIMUM_PRECISION });
        }
        let size = BoxedUint::limbs_for(precision);
        let mut limbs = Vec::new();
        limbs.try_reserve_exact(size).map_err(|_| MathError::AllocationFailed)?;
        limbs.resize(size, 0);
        Ok(BoxedUint { limbs: limbs.into_boxed_slice() })
    }

    pub fn one(precision: u32) -> Result<BoxedUint, MathError> {
        let mut value = BoxedUint::zero(precision)?;
        value.limbs[0] = 1;
        Ok(value)
    }

    /// The value of `limbs`, least significant first, in the smallest precision that holds them.
    pub fn from_limbs(limbs: &[Limb]) -> Result<BoxedUint, MathError> {
        let precision =
            u32::try_from(limbs.len()).ok().and_then(|length| length.checked_mul(Limb::BITS)).unwrap_or(u32::MAX);
        let mut value = BoxedUint::zero(precision)?;
        value.limbs[..limbs.len()].copy_from_slice(limbs);
        Ok(value)
    }

    /// The limbs, least significant first.
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    pub fn as_limbs_mut(&mut self) -> &mut [Limb] {
        &mut self.limbs
    }

    /// The precision in bits.
    pub fn precision(&self) -> u32 {
        self.limbs.len() as u32 * Limb::BITS
    }

    /// The number of bytes of the precision.
    pub fn bytes(&self) -> usize {
        self.limbs.len() * Limbs::BYTES
    }

    /// The value `value`; fails if it does not fit the precision.
    pub fn from_u64(value: u64, precision: u32) -> Result<BoxedUint, MathError> {
        BoxedUint::from_le_bytes(&value.to_le_bytes(), precision)
    }

    /// Reads big-endian bytes; fails if the value does not fit the precision.
    /// Leading zero bytes beyond the precision are allowed.
    pub fn from_be_bytes(bytes: &[u8], precision: u32) -> Result<BoxedUint, MathError> {
        let mut value = BoxedUint::zero(precision)?;
        Limbs::from_be_bytes(&mut value.limbs, bytes)?;
        Ok(value)
    }

    /// Reads little-endian bytes; fails if the value does not fit the
    /// precision. Trailing zero bytes beyond the precision are allowed.
    pub fn from_le_bytes(bytes: &[u8], precision: u32) -> Result<BoxedUint, MathError> {
        let mut value = BoxedUint::zero(precision)?;
        Limbs::from_le_bytes(&mut value.limbs, bytes)?;
        Ok(value)
    }

    /// Writes the value big-endian into all of `out`, with leading zeros;
    /// fails if it needs more bytes.
    pub fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        Limbs::write_be_bytes(&self.limbs, out)
    }

    /// Writes the value little-endian into all of `out`, with trailing zeros;
    /// fails if it needs more bytes.
    pub fn write_le_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        Limbs::write_le_bytes(&self.limbs, out)
    }

    /// The value big-endian in [`BoxedUint::bytes`] bytes.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.bytes()];
        // Every value fits its own precision.
        let _ = Limbs::write_be_bytes(&self.limbs, &mut bytes);
        bytes
    }

    /// The value little-endian in [`BoxedUint::bytes`] bytes.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.bytes()];
        let _ = Limbs::write_le_bytes(&self.limbs, &mut bytes);
        bytes
    }

    /// Reads big-endian hexadecimal digits, as [`Limbs::from_hex_vartime`] does.
    pub fn from_hex_vartime(text: &str, precision: u32) -> Result<BoxedUint, MathError> {
        let mut value = BoxedUint::zero(precision)?;
        Limbs::from_hex_vartime(&mut value.limbs, text)?;
        Ok(value)
    }

    /// The value of a [`Uint`], in its precision.
    pub fn from_uint<const N: usize>(value: &Uint<N>) -> Result<BoxedUint, MathError> {
        BoxedUint::from_limbs(value.as_limbs())
    }

    /// The value as a [`Uint`]; fails if it does not fit.
    pub fn to_uint<const N: usize>(&self) -> Result<Uint<N>, MathError> {
        let mut value = Uint::<N>::ZERO;
        let shared = N.min(self.limbs.len());
        value.as_limbs_mut()[..shared].copy_from_slice(&self.limbs[..shared]);
        if !Limbs::is_zero(&self.limbs[shared..]).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(value)
    }

    /// The value in another precision; fails if it does not fit.
    pub fn resize(&self, precision: u32) -> Result<BoxedUint, MathError> {
        let mut value = BoxedUint::zero(precision)?;
        let shared = value.limbs.len().min(self.limbs.len());
        value.limbs[..shared].copy_from_slice(&self.limbs[..shared]);
        if !Limbs::is_zero(&self.limbs[shared..]).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(value)
    }

    /// Zero of `size` limbs, rounded up to the precision unit, for results
    /// as long as existing values. Like `vec!`, it aborts if the memory cannot
    /// be allocated: use [`BoxedUint::zero`] for precisions that come from input.
    ///
    /// # Panics
    ///
    /// If `size` limbs exceed [`BoxedUint::MAXIMUM_PRECISION`].
    pub fn with_limbs(size: usize) -> BoxedUint {
        assert!(size <= BoxedUint::limbs_for(BoxedUint::MAXIMUM_PRECISION), "precision above the maximum");
        let unit = Limbs::count(BoxedUint::PRECISION_UNIT);
        BoxedUint { limbs: vec![0; size.max(1).next_multiple_of(unit)].into_boxed_slice() }
    }

    pub fn is_zero(&self) -> Choice {
        Limbs::is_zero(&self.limbs)
    }

    pub fn is_odd(&self) -> Choice {
        Limbs::bit(&self.limbs, 0)
    }

    /// Whether `self < other`.
    pub fn ct_lt(&self, other: &BoxedUint) -> Choice {
        Limbs::less_than(&self.limbs, &other.limbs)
    }

    /// Whether `self > other`.
    pub fn ct_gt(&self, other: &BoxedUint) -> Choice {
        Limbs::less_than(&other.limbs, &self.limbs)
    }

    /// Compares the values; the time depends on them.
    pub fn compare_vartime(&self, other: &BoxedUint) -> Ordering {
        Limbs::compare_vartime(&self.limbs, &other.limbs)
    }

    /// Bit `index`, counted from the least significant; false beyond the precision.
    pub fn bit(&self, index: u32) -> Choice {
        Limbs::bit(&self.limbs, index)
    }

    /// The number of bits up to the highest set bit (0 for zero).
    pub fn bit_length(&self) -> u32 {
        Limbs::bit_length(&self.limbs)
    }

    /// `self + other` and whether it carried out of the precision.
    pub fn overflowing_add(&self, other: &BoxedUint) -> (BoxedUint, Choice) {
        let mut sum = BoxedUint::with_limbs(self.limbs.len().max(other.limbs.len()));
        let carry = Limbs::add(&mut sum.limbs, &self.limbs, &other.limbs);
        (sum, Limbs::choice(carry))
    }

    /// `self - other` and whether it borrowed (`other` was larger).
    pub fn overflowing_sub(&self, other: &BoxedUint) -> (BoxedUint, Choice) {
        let mut difference = BoxedUint::with_limbs(self.limbs.len().max(other.limbs.len()));
        let borrow = Limbs::sub(&mut difference.limbs, &self.limbs, &other.limbs);
        (difference, Limbs::choice(borrow))
    }

    /// `self + other` modulo `2^precision`.
    pub fn wrapping_add(&self, other: &BoxedUint) -> BoxedUint {
        self.overflowing_add(other).0
    }

    /// `self - other` modulo `2^precision`.
    pub fn wrapping_sub(&self, other: &BoxedUint) -> BoxedUint {
        self.overflowing_sub(other).0
    }

    /// `self * other` as the low and the high half of the full product.
    pub fn widening_mul(&self, other: &BoxedUint) -> (BoxedUint, BoxedUint) {
        let size = self.limbs.len().max(other.limbs.len());
        let mut low = BoxedUint::with_limbs(size);
        let mut high = BoxedUint::with_limbs(size);
        let (high_used, _) = high.limbs.split_at_mut(self.limbs.len() + other.limbs.len() - size);
        Limbs::mul(&mut low.limbs, high_used, &self.limbs, &other.limbs);
        (low, high)
    }

    /// `self * other` in full, in the sum of the precisions of the operands.
    pub fn mul_wide(&self, other: &BoxedUint) -> BoxedUint {
        let mut product = BoxedUint::with_limbs(self.limbs.len() + other.limbs.len());
        let (low, high) = product.limbs.split_at_mut(self.limbs.len());
        Limbs::mul(low, high, &self.limbs, &other.limbs);
        product
    }

    /// `self * other` modulo `2^precision`.
    pub fn wrapping_mul(&self, other: &BoxedUint) -> BoxedUint {
        self.widening_mul(other).0
    }

    /// The quotient, in the precision of `self`, and the remainder, in the
    /// precision of the divisor, of `self / divisor`; fails only if the
    /// divisor is zero, which is the one fact the time reveals.
    pub fn div_rem(&self, divisor: &BoxedUint) -> Result<(BoxedUint, BoxedUint), MathError> {
        let mut quotient = BoxedUint::with_limbs(self.limbs.len());
        let mut remainder = BoxedUint::with_limbs(divisor.limbs.len());
        Limbs::div_rem(Some(&mut quotient.limbs), &mut remainder.limbs, &self.limbs, &[], &divisor.limbs)?;
        Ok((quotient, remainder))
    }

    /// `self mod modulus`, in the precision of the modulus; fails only if it is zero.
    pub fn rem(&self, modulus: &BoxedUint) -> Result<BoxedUint, MathError> {
        let mut remainder = BoxedUint::with_limbs(modulus.limbs.len());
        Limbs::rem(&mut remainder.limbs, &self.limbs, &[], &modulus.limbs)?;
        Ok(remainder)
    }

    /// `(low + high * 2^precision(low)) mod modulus`, in the precision of the
    /// modulus, reducing a double-width value such as a product from
    /// [`BoxedUint::widening_mul`]; fails only if the modulus is zero.
    pub fn rem_wide(low: &BoxedUint, high: &BoxedUint, modulus: &BoxedUint) -> Result<BoxedUint, MathError> {
        let mut remainder = BoxedUint::with_limbs(modulus.limbs.len());
        Limbs::rem(&mut remainder.limbs, &low.limbs, &high.limbs, &modulus.limbs)?;
        Ok(remainder)
    }

    /// `self mod divisor` for a divisor of one limb, in time that depends on
    /// the values (to sieve candidate primes by small primes); `None` for a
    /// divisor of zero.
    pub fn rem_limb_vartime(&self, divisor: Limb) -> Option<Limb> {
        if divisor == 0 {
            return None;
        }
        let mut remainder: WideLimb = 0;
        for limb in self.limbs.iter().rev() {
            remainder = ((remainder << Limb::BITS) | *limb as WideLimb) % divisor as WideLimb;
        }
        Some(remainder as Limb)
    }

    /// The greatest common divisor of `self` and `other` by the binary
    /// algorithm, in the larger precision, in time that depends on the
    /// values; gcd(0, 0) = 0.
    pub fn gcd_vartime(&self, other: &BoxedUint) -> BoxedUint {
        let size = self.limbs.len().max(other.limbs.len());
        let extend = |value: &BoxedUint| {
            let mut extended = BoxedUint::with_limbs(size);
            extended.limbs[..value.limbs.len()].copy_from_slice(&value.limbs);
            extended
        };
        let (mut a, mut b) = (extend(self), extend(other));
        if a.is_zero().into_bool() {
            return b;
        }
        if b.is_zero().into_bool() {
            return a;
        }
        let trailing =
            |value: &BoxedUint| (0..value.bit_length()).find(|&index| value.bit(index).into_bool()).unwrap_or(0);
        let shift = trailing(&a).min(trailing(&b));
        a = a.shr(trailing(&a));
        loop {
            b = b.shr(trailing(&b));
            if a.compare_vartime(&b) == Ordering::Greater {
                core::mem::swap(&mut a, &mut b);
            }
            b = b.wrapping_sub(&a);
            if b.is_zero().into_bool() {
                return a.shl(shift);
            }
        }
    }

    /// `self << bits`, discarding the bits shifted out; the time depends on `bits` only.
    pub fn shl(&self, bits: u32) -> BoxedUint {
        let mut value = self.clone();
        Limbs::shl(&mut value.limbs, bits);
        value
    }

    /// `self >> bits`; the time depends on `bits` only.
    pub fn shr(&self, bits: u32) -> BoxedUint {
        let mut value = self.clone();
        Limbs::shr(&mut value.limbs, bits);
        value
    }

    /// Applies `operation` to each pair of limbs, zero-extending the shorter operand.
    pub fn combine(a: &BoxedUint, b: &BoxedUint, operation: impl Fn(Limb, Limb) -> Limb) -> BoxedUint {
        let mut value = BoxedUint::with_limbs(a.limbs.len().max(b.limbs.len()));
        for (index, limb) in value.limbs.iter_mut().enumerate() {
            *limb = operation(Limbs::limb(&a.limbs, index), Limbs::limb(&b.limbs, index));
        }
        value
    }

    /// `self = other` if `choice`; both must have the same precision.
    pub fn conditional_assign(&mut self, other: &BoxedUint, choice: Choice) -> Result<(), MathError> {
        if self.limbs.len() != other.limbs.len() {
            return Err(MathError::SizeMismatch);
        }
        Limbs::conditional_assign(&mut self.limbs, &other.limbs, choice);
        Ok(())
    }

    /// Swaps `a` and `b` if `choice`; both must have the same precision.
    pub fn conditional_swap(a: &mut BoxedUint, b: &mut BoxedUint, choice: Choice) -> Result<(), MathError> {
        if a.limbs.len() != b.limbs.len() {
            return Err(MathError::SizeMismatch);
        }
        Limbs::conditional_swap(&mut a.limbs, &mut b.limbs, choice);
        Ok(())
    }
}

impl Clone for BoxedUint {
    fn clone(&self) -> BoxedUint {
        BoxedUint { limbs: self.limbs.clone() }
    }
}

impl Drop for BoxedUint {
    fn drop(&mut self) {
        self.limbs.zeroize();
    }
}

impl Zeroize for BoxedUint {
    /// Sets the value to zero, keeping the precision.
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl ConstantTimeEq for BoxedUint {
    /// Whether the values are equal, zero-extending the shorter one.
    fn ct_eq(&self, other: &BoxedUint) -> Choice {
        Limbs::equal(&self.limbs, &other.limbs)
    }
}

impl PartialEq for BoxedUint {
    fn eq(&self, other: &BoxedUint) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl Eq for BoxedUint {}

impl BitAnd for &BoxedUint {
    type Output = BoxedUint;
    fn bitand(self, other: &BoxedUint) -> BoxedUint {
        BoxedUint::combine(self, other, |a, b| a & b)
    }
}

impl BitOr for &BoxedUint {
    type Output = BoxedUint;
    fn bitor(self, other: &BoxedUint) -> BoxedUint {
        BoxedUint::combine(self, other, |a, b| a | b)
    }
}

impl BitXor for &BoxedUint {
    type Output = BoxedUint;
    fn bitxor(self, other: &BoxedUint) -> BoxedUint {
        BoxedUint::combine(self, other, |a, b| a ^ b)
    }
}

impl Not for &BoxedUint {
    type Output = BoxedUint;
    /// Every bit of the precision inverted.
    fn not(self) -> BoxedUint {
        let mut value = self.clone();
        value.limbs.iter_mut().for_each(|limb| *limb = !*limb);
        value
    }
}

impl fmt::LowerHex for BoxedUint {
    /// All digits of the precision, most significant first.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.limbs.iter().rev() {
            write!(formatter, "{limb:0width$x}", width = Limbs::HEX_DIGITS)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for BoxedUint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.limbs.iter().rev() {
            write!(formatter, "{limb:0width$X}", width = Limbs::HEX_DIGITS)?;
        }
        Ok(())
    }
}

impl fmt::Debug for BoxedUint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BoxedUint(0x{self:x})")
    }
}
