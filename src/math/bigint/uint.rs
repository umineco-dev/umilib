use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitXor, Not};

use super::{Limb, Limbs, MathError};
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A [`Uint`] of 64 bits on every platform.
pub type U64 = Uint<{ Limbs::count(64) }>;
/// A [`Uint`] of 128 bits on every platform.
pub type U128 = Uint<{ Limbs::count(128) }>;
/// A [`Uint`] of 192 bits on every platform.
pub type U192 = Uint<{ Limbs::count(192) }>;
/// A [`Uint`] of 256 bits on every platform.
pub type U256 = Uint<{ Limbs::count(256) }>;
/// A [`Uint`] of 320 bits on every platform.
pub type U320 = Uint<{ Limbs::count(320) }>;
/// A [`Uint`] of 384 bits on every platform.
pub type U384 = Uint<{ Limbs::count(384) }>;
/// A [`Uint`] of 448 bits on every platform.
pub type U448 = Uint<{ Limbs::count(448) }>;
/// A [`Uint`] of 512 bits on every platform.
pub type U512 = Uint<{ Limbs::count(512) }>;
/// A [`Uint`] of 576 bits on every platform.
pub type U576 = Uint<{ Limbs::count(576) }>;
/// A [`Uint`] of 640 bits on every platform.
pub type U640 = Uint<{ Limbs::count(640) }>;
/// A [`Uint`] of 768 bits on every platform.
pub type U768 = Uint<{ Limbs::count(768) }>;
/// A [`Uint`] of 896 bits on every platform.
pub type U896 = Uint<{ Limbs::count(896) }>;
/// A [`Uint`] of 1024 bits on every platform.
pub type U1024 = Uint<{ Limbs::count(1024) }>;
/// A [`Uint`] of 1536 bits on every platform.
pub type U1536 = Uint<{ Limbs::count(1536) }>;
/// A [`Uint`] of 2048 bits on every platform.
pub type U2048 = Uint<{ Limbs::count(2048) }>;
/// A [`Uint`] of 3072 bits on every platform.
pub type U3072 = Uint<{ Limbs::count(3072) }>;
/// A [`Uint`] of 4096 bits on every platform.
pub type U4096 = Uint<{ Limbs::count(4096) }>;
/// A [`Uint`] of 6144 bits on every platform.
pub type U6144 = Uint<{ Limbs::count(6144) }>;
/// A [`Uint`] of 8192 bits on every platform.
pub type U8192 = Uint<{ Limbs::count(8192) }>;

/// An unsigned integer of `N` limbs, on the stack.
///
/// A limb has 64 bits on 64-bit targets and 32 bits elsewhere, so name a
/// precision in bits with the aliases such as [`U256`], or with
/// `Uint<{ Limbs::count(bits) }>`, to get the same precision on every platform.
///
/// Arithmetic wraps around or reports the carry explicitly; there are no
/// operators that could panic or wrap silently, except the bitwise ones.
/// `==` compares in constant time and reveals only the result.
#[derive(Clone, Copy)]
pub struct Uint<const N: usize> {
    limbs: [Limb; N],
}

impl<const N: usize> Uint<N> {
    pub const LIMBS: usize = N;
    pub const BITS: u32 = N as u32 * Limb::BITS;
    pub const BYTES: usize = N * Limbs::BYTES;
    pub const ZERO: Uint<N> = Uint { limbs: [0; N] };
    pub const ONE: Uint<N> = Uint::from_limb(1);
    pub const MAX: Uint<N> = Uint { limbs: [Limb::MAX; N] };

    pub const fn from_limbs(limbs: [Limb; N]) -> Uint<N> {
        Uint { limbs }
    }

    /// The value `limb` (zero if `N` is zero).
    pub const fn from_limb(limb: Limb) -> Uint<N> {
        let mut limbs = [0; N];
        if N > 0 {
            limbs[0] = limb;
        }
        Uint { limbs }
    }

    /// The value `value`; fails if it does not fit.
    pub fn from_u64(value: u64) -> Result<Uint<N>, MathError> {
        Uint::from_le_bytes(&value.to_le_bytes())
    }

    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.limbs
    }

    pub const fn as_limbs_mut(&mut self) -> &mut [Limb; N] {
        &mut self.limbs
    }

    pub const fn into_limbs(self) -> [Limb; N] {
        self.limbs
    }

    /// Reads big-endian bytes; fails if the value does not fit. Leading zero
    /// bytes beyond the precision are allowed.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Uint<N>, MathError> {
        let mut value = Uint::ZERO;
        Limbs::from_be_bytes(&mut value.limbs, bytes)?;
        Ok(value)
    }

    /// Reads little-endian bytes; fails if the value does not fit. Trailing
    /// zero bytes beyond the precision are allowed.
    pub fn from_le_bytes(bytes: &[u8]) -> Result<Uint<N>, MathError> {
        let mut value = Uint::ZERO;
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

    /// The value big-endian in [`Uint::BYTES`] bytes.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; Uint::<N>::BYTES];
        // Every value fits its own precision.
        let _ = Limbs::write_be_bytes(&self.limbs, &mut bytes);
        bytes
    }

    /// The value little-endian in [`Uint::BYTES`] bytes.
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; Uint::<N>::BYTES];
        let _ = Limbs::write_le_bytes(&self.limbs, &mut bytes);
        bytes
    }

    /// Reads big-endian hexadecimal digits, as [`Limbs::from_hex_vartime`] does.
    pub const fn from_hex_vartime(text: &str) -> Result<Uint<N>, MathError> {
        let mut value = Uint::ZERO;
        match Limbs::from_hex_vartime(&mut value.limbs, text) {
            Ok(()) => Ok(value),
            Err(error) => Err(error),
        }
    }

    /// Like [`Uint::from_hex_vartime`], panicking if the text is not a number
    /// that fits: meant for constants, where the panic happens at compile time.
    pub const fn from_hex_vartime_or_panic(text: &str) -> Uint<N> {
        match Uint::from_hex_vartime(text) {
            Ok(value) => value,
            Err(_) => panic!("invalid hexadecimal constant"),
        }
    }

    /// The value in precision `M`; fails if it does not fit.
    pub fn resize<const M: usize>(&self) -> Result<Uint<M>, MathError> {
        let mut value = Uint::<M>::ZERO;
        let shared = N.min(M);
        value.limbs[..shared].copy_from_slice(&self.limbs[..shared]);
        if !Limbs::is_zero(&self.limbs[shared..]).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(value)
    }

    pub fn is_zero(&self) -> Choice {
        Limbs::is_zero(&self.limbs)
    }

    pub fn is_odd(&self) -> Choice {
        Limbs::bit(&self.limbs, 0)
    }

    /// Whether `self < other`.
    pub fn ct_lt(&self, other: &Uint<N>) -> Choice {
        Limbs::less_than(&self.limbs, &other.limbs)
    }

    /// Whether `self > other`.
    pub fn ct_gt(&self, other: &Uint<N>) -> Choice {
        Limbs::less_than(&other.limbs, &self.limbs)
    }

    /// Compares the values; the time depends on them.
    pub fn compare_vartime(&self, other: &Uint<N>) -> Ordering {
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
    pub fn overflowing_add(&self, other: &Uint<N>) -> (Uint<N>, Choice) {
        let mut sum = Uint::ZERO;
        let carry = Limbs::add(&mut sum.limbs, &self.limbs, &other.limbs);
        (sum, Limbs::choice(carry))
    }

    /// `self - other` and whether it borrowed (`other` was larger).
    pub fn overflowing_sub(&self, other: &Uint<N>) -> (Uint<N>, Choice) {
        let mut difference = Uint::ZERO;
        let borrow = Limbs::sub(&mut difference.limbs, &self.limbs, &other.limbs);
        (difference, Limbs::choice(borrow))
    }

    /// `self + other` modulo `2^BITS`.
    pub fn wrapping_add(&self, other: &Uint<N>) -> Uint<N> {
        self.overflowing_add(other).0
    }

    /// `self - other` modulo `2^BITS`.
    pub fn wrapping_sub(&self, other: &Uint<N>) -> Uint<N> {
        self.overflowing_sub(other).0
    }

    /// `self * other` as the low and the high half of the full product.
    pub fn widening_mul(&self, other: &Uint<N>) -> (Uint<N>, Uint<N>) {
        let mut low = Uint::ZERO;
        let mut high = Uint::ZERO;
        Limbs::mul(&mut low.limbs, &mut high.limbs, &self.limbs, &other.limbs);
        (low, high)
    }

    /// `self * other` modulo `2^BITS`.
    pub fn wrapping_mul(&self, other: &Uint<N>) -> Uint<N> {
        self.widening_mul(other).0
    }

    /// The quotient and the remainder of `self / divisor`; fails only if the
    /// divisor is zero, which is the one fact the time reveals.
    pub fn div_rem(&self, divisor: &Uint<N>) -> Result<(Uint<N>, Uint<N>), MathError> {
        let mut quotient = Uint::ZERO;
        let mut remainder = Uint::ZERO;
        Limbs::div_rem(Some(&mut quotient.limbs), &mut remainder.limbs, &self.limbs, &[], &divisor.limbs)?;
        Ok((quotient, remainder))
    }

    /// `self mod modulus`; fails only if the modulus is zero.
    pub fn rem(&self, modulus: &Uint<N>) -> Result<Uint<N>, MathError> {
        let mut remainder = Uint::ZERO;
        Limbs::rem(&mut remainder.limbs, &self.limbs, &[], &modulus.limbs)?;
        Ok(remainder)
    }

    /// `(low + high * 2^BITS) mod modulus`, reducing a double-width value such
    /// as a product from [`Uint::widening_mul`]; fails only if the modulus is zero.
    pub fn rem_wide(low: &Uint<N>, high: &Uint<N>, modulus: &Uint<N>) -> Result<Uint<N>, MathError> {
        let mut remainder = Uint::ZERO;
        Limbs::rem(&mut remainder.limbs, &low.limbs, &high.limbs, &modulus.limbs)?;
        Ok(remainder)
    }

    /// `self << bits`, discarding the bits shifted out; the time depends on `bits` only.
    pub fn shl(&self, bits: u32) -> Uint<N> {
        let mut value = *self;
        Limbs::shl(&mut value.limbs, bits);
        value
    }

    /// `self >> bits`; the time depends on `bits` only.
    pub fn shr(&self, bits: u32) -> Uint<N> {
        let mut value = *self;
        Limbs::shr(&mut value.limbs, bits);
        value
    }
}

impl<const N: usize> Default for Uint<N> {
    fn default() -> Uint<N> {
        Uint::ZERO
    }
}

impl<const N: usize> ConstantTimeEq for Uint<N> {
    fn ct_eq(&self, other: &Uint<N>) -> Choice {
        Limbs::equal(&self.limbs, &other.limbs)
    }
}

impl<const N: usize> PartialEq for Uint<N> {
    fn eq(&self, other: &Uint<N>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<const N: usize> Eq for Uint<N> {}

impl<const N: usize> ConditionallySelectable for Uint<N> {
    fn select(a: &Uint<N>, b: &Uint<N>, choice: Choice) -> Uint<N> {
        Uint { limbs: <[Limb; N]>::select(&a.limbs, &b.limbs, choice) }
    }
}

impl<const N: usize> Zeroize for Uint<N> {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl<const N: usize> BitAnd for Uint<N> {
    type Output = Uint<N>;
    fn bitand(self, other: Uint<N>) -> Uint<N> {
        Uint { limbs: core::array::from_fn(|index| self.limbs[index] & other.limbs[index]) }
    }
}

impl<const N: usize> BitOr for Uint<N> {
    type Output = Uint<N>;
    fn bitor(self, other: Uint<N>) -> Uint<N> {
        Uint { limbs: core::array::from_fn(|index| self.limbs[index] | other.limbs[index]) }
    }
}

impl<const N: usize> BitXor for Uint<N> {
    type Output = Uint<N>;
    fn bitxor(self, other: Uint<N>) -> Uint<N> {
        Uint { limbs: core::array::from_fn(|index| self.limbs[index] ^ other.limbs[index]) }
    }
}

impl<const N: usize> Not for Uint<N> {
    type Output = Uint<N>;
    fn not(self) -> Uint<N> {
        Uint { limbs: self.limbs.map(|limb| !limb) }
    }
}

impl<const N: usize> fmt::LowerHex for Uint<N> {
    /// All digits of the precision, most significant first.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.limbs.iter().rev() {
            write!(formatter, "{limb:0width$x}", width = Limbs::HEX_DIGITS)?;
        }
        Ok(())
    }
}

impl<const N: usize> fmt::UpperHex for Uint<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.limbs.iter().rev() {
            write!(formatter, "{limb:0width$X}", width = Limbs::HEX_DIGITS)?;
        }
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for Uint<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Uint(0x{self:x})")
    }
}
