use core::cmp::Ordering;
use core::fmt;

use super::{MathError, Uint};
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// An unsigned integer of fixed precision, for code generic over the
/// precision (the fields of elliptic curves): the operations of [`Uint`],
/// with the same meaning and the same timing guarantees.
pub trait UnsignedInteger:
    Copy + Default + Eq + ConstantTimeEq + ConditionallySelectable + Zeroize + fmt::Debug + fmt::LowerHex + 'static
{
    const BITS: u32;
    const BYTES: usize;
    const ZERO: Self;
    const ONE: Self;

    fn from_u64(value: u64) -> Result<Self, MathError>;
    fn from_be_bytes(bytes: &[u8]) -> Result<Self, MathError>;
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, MathError>;
    fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), MathError>;
    fn write_le_bytes(&self, out: &mut [u8]) -> Result<(), MathError>;
    fn is_zero(&self) -> Choice;
    fn is_odd(&self) -> Choice;
    fn ct_lt(&self, other: &Self) -> Choice;
    fn ct_gt(&self, other: &Self) -> Choice;
    fn compare_vartime(&self, other: &Self) -> Ordering;
    fn bit(&self, index: u32) -> Choice;
    fn bit_length(&self) -> u32;
    fn overflowing_add(&self, other: &Self) -> (Self, Choice);
    fn overflowing_sub(&self, other: &Self) -> (Self, Choice);
    fn wrapping_add(&self, other: &Self) -> Self;
    fn wrapping_sub(&self, other: &Self) -> Self;
    fn shl(&self, bits: u32) -> Self;
    fn shr(&self, bits: u32) -> Self;
    /// `(high × 2^BITS + low) mod modulus`.
    fn rem_wide(low: &Self, high: &Self, modulus: &Self) -> Result<Self, MathError>;

    /// The integer of every bit of the precision, from the bytes `fill`
    /// writes four at a time, most significant word first: a random integer
    /// when `fill` reads a source of random bytes. Fails with the error of
    /// `fill`, zeroizing what was read.
    fn from_byte_source<E>(mut fill: impl FnMut(&mut [u8]) -> Result<(), E>) -> Result<Self, E> {
        let mut value = Self::ZERO;
        let mut word = [0u8; 4];
        for index in 0..Self::BITS.div_ceil(32) {
            if let Err(error) = fill(&mut word) {
                value.zeroize();
                word.zeroize();
                return Err(error);
            }
            if index > 0 {
                value = value.shl(32);
            }
            // A word of 32 bits fits every precision, a multiple of 32 bits.
            value = value.wrapping_add(&Self::from_u64(u32::from_le_bytes(word) as u64).unwrap_or(Self::ZERO));
        }
        word.zeroize();
        Ok(value)
    }
}

impl<const N: usize> UnsignedInteger for Uint<N> {
    const BITS: u32 = Uint::<N>::BITS;
    const BYTES: usize = Uint::<N>::BYTES;
    const ZERO: Uint<N> = Uint::<N>::ZERO;
    const ONE: Uint<N> = Uint::<N>::ONE;

    fn from_u64(value: u64) -> Result<Uint<N>, MathError> {
        Uint::from_u64(value)
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Uint<N>, MathError> {
        Uint::from_be_bytes(bytes)
    }

    fn from_le_bytes(bytes: &[u8]) -> Result<Uint<N>, MathError> {
        Uint::from_le_bytes(bytes)
    }

    fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        Uint::write_be_bytes(self, out)
    }

    fn write_le_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        Uint::write_le_bytes(self, out)
    }

    fn is_zero(&self) -> Choice {
        Uint::is_zero(self)
    }

    fn is_odd(&self) -> Choice {
        Uint::is_odd(self)
    }

    fn ct_lt(&self, other: &Uint<N>) -> Choice {
        Uint::ct_lt(self, other)
    }

    fn ct_gt(&self, other: &Uint<N>) -> Choice {
        Uint::ct_gt(self, other)
    }

    fn compare_vartime(&self, other: &Uint<N>) -> Ordering {
        Uint::compare_vartime(self, other)
    }

    fn bit(&self, index: u32) -> Choice {
        Uint::bit(self, index)
    }

    fn bit_length(&self) -> u32 {
        Uint::bit_length(self)
    }

    fn overflowing_add(&self, other: &Uint<N>) -> (Uint<N>, Choice) {
        Uint::overflowing_add(self, other)
    }

    fn overflowing_sub(&self, other: &Uint<N>) -> (Uint<N>, Choice) {
        Uint::overflowing_sub(self, other)
    }

    fn wrapping_add(&self, other: &Uint<N>) -> Uint<N> {
        Uint::wrapping_add(self, other)
    }

    fn wrapping_sub(&self, other: &Uint<N>) -> Uint<N> {
        Uint::wrapping_sub(self, other)
    }

    fn shl(&self, bits: u32) -> Uint<N> {
        Uint::shl(self, bits)
    }

    fn shr(&self, bits: u32) -> Uint<N> {
        Uint::shr(self, bits)
    }

    fn rem_wide(low: &Uint<N>, high: &Uint<N>, modulus: &Uint<N>) -> Result<Uint<N>, MathError> {
        Uint::rem_wide(low, high, modulus)
    }
}
