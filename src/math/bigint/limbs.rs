use core::cmp::Ordering;

use super::{Limb, MathError, WideLimb};
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, DataIndependentTiming};

/// Algorithms on little-endian slices of limbs (the first limb is the least
/// significant), shared by [`Uint`](super::Uint) and [`BoxedUint`](super::BoxedUint).
///
/// Slices passed together must have the lengths each function states;
/// otherwise the function panics. Timing depends only on the lengths and on
/// public arguments such as shift amounts, never on the values of the limbs,
/// except in functions whose names end in `_vartime`. On processors that need
/// a mode for that (see [`DataIndependentTiming`]), division sets it itself;
/// hold a guard around computations made of the short functions.
pub struct Limbs;

impl Limbs {
    /// The number of bytes in a limb.
    pub const BYTES: usize = (Limb::BITS / 8) as usize;
    /// The number of hexadecimal digits in a limb.
    pub const HEX_DIGITS: usize = 2 * Limbs::BYTES;

    /// The number of limbs that hold `bits` bits.
    pub const fn count(bits: u32) -> usize {
        bits.div_ceil(Limb::BITS) as usize
    }

    /// `a + b + carry` and the carry out (0 or 1).
    pub const fn carrying_add(a: Limb, b: Limb, carry: Limb) -> (Limb, Limb) {
        let sum = a as WideLimb + b as WideLimb + carry as WideLimb;
        (sum as Limb, (sum >> Limb::BITS) as Limb)
    }

    /// `a - b - borrow` and the borrow out (0 or 1).
    pub const fn borrowing_sub(a: Limb, b: Limb, borrow: Limb) -> (Limb, Limb) {
        let difference = (a as WideLimb).wrapping_sub(b as WideLimb + borrow as WideLimb);
        (difference as Limb, (difference >> (2 * Limb::BITS - 1)) as Limb)
    }

    /// `a * b + addend + carry` as the low and the high limb; it never overflows.
    pub const fn carrying_mul_add(a: Limb, b: Limb, addend: Limb, carry: Limb) -> (Limb, Limb) {
        let value = (a as WideLimb) * (b as WideLimb) + addend as WideLimb + carry as WideLimb;
        (value as Limb, (value >> Limb::BITS) as Limb)
    }

    /// All ones if `choice` is true, zero otherwise.
    pub fn mask(choice: Choice) -> Limb {
        (0 as Limb).wrapping_sub(choice.bit() as Limb)
    }

    /// The choice that the lowest bit of `limb` stands for.
    pub fn choice(limb: Limb) -> Choice {
        Choice::from_bit((limb & 1) as u8)
    }

    /// Limb `index` of `a`, or zero beyond its end: shorter operands are zero-extended.
    pub fn limb(a: &[Limb], index: usize) -> Limb {
        a.get(index).copied().unwrap_or(0)
    }

    /// `out = a + b` modulo `2^(Limb::BITS * out.len())`, with `a` and `b` no
    /// longer than `out`; returns the carry.
    pub fn add(out: &mut [Limb], a: &[Limb], b: &[Limb]) -> Limb {
        assert!(a.len() <= out.len() && b.len() <= out.len());
        let mut carry = 0;
        for (index, limb) in out.iter_mut().enumerate() {
            (*limb, carry) = Limbs::carrying_add(Limbs::limb(a, index), Limbs::limb(b, index), carry);
        }
        carry
    }

    /// `out = a - b` modulo `2^(Limb::BITS * out.len())`, with `a` and `b` no
    /// longer than `out`; returns the borrow.
    pub fn sub(out: &mut [Limb], a: &[Limb], b: &[Limb]) -> Limb {
        assert!(a.len() <= out.len() && b.len() <= out.len());
        let mut borrow = 0;
        for (index, limb) in out.iter_mut().enumerate() {
            (*limb, borrow) = Limbs::borrowing_sub(Limbs::limb(a, index), Limbs::limb(b, index), borrow);
        }
        borrow
    }

    /// `a += b` if `choice`, with `b` no longer than `a`; returns the carry (0 if not added).
    pub fn conditional_add(a: &mut [Limb], b: &[Limb], choice: Choice) -> Limb {
        assert!(b.len() <= a.len());
        let mask = Limbs::mask(choice);
        let mut carry = 0;
        for (index, limb) in a.iter_mut().enumerate() {
            (*limb, carry) = Limbs::carrying_add(*limb, Limbs::limb(b, index) & mask, carry);
        }
        carry
    }

    /// `a -= b` if `choice`, with `b` no longer than `a`; returns the borrow (0 if not subtracted).
    pub fn conditional_sub(a: &mut [Limb], b: &[Limb], choice: Choice) -> Limb {
        assert!(b.len() <= a.len());
        let mask = Limbs::mask(choice);
        let mut borrow = 0;
        for (index, limb) in a.iter_mut().enumerate() {
            (*limb, borrow) = Limbs::borrowing_sub(*limb, Limbs::limb(b, index) & mask, borrow);
        }
        borrow
    }

    /// `a = b` if `choice`, with `b` as long as `a`.
    pub fn conditional_assign(a: &mut [Limb], b: &[Limb], choice: Choice) {
        assert!(a.len() == b.len());
        for (a, b) in a.iter_mut().zip(b) {
            a.conditional_assign(b, choice);
        }
    }

    /// Swaps `a` and `b`, of the same length, if `choice`.
    pub fn conditional_swap(a: &mut [Limb], b: &mut [Limb], choice: Choice) {
        assert!(a.len() == b.len());
        for (a, b) in a.iter_mut().zip(b.iter_mut()) {
            Limb::conditional_swap(a, b, choice);
        }
    }

    pub fn is_zero(a: &[Limb]) -> Choice {
        a.iter().fold(0, |combined, &limb| combined | limb).ct_eq(&0)
    }

    pub fn is_one(a: &[Limb]) -> Choice {
        match a.split_first() {
            Some((&first, rest)) => first.ct_eq(&1) & Limbs::is_zero(rest),
            None => Choice::FALSE,
        }
    }

    /// Whether `a == b`, of any lengths.
    pub fn equal(a: &[Limb], b: &[Limb]) -> Choice {
        let mut difference = 0;
        for index in 0..a.len().max(b.len()) {
            difference |= Limbs::limb(a, index) ^ Limbs::limb(b, index);
        }
        difference.ct_eq(&0)
    }

    /// Whether `a < b`, of any lengths: the borrow of `a - b`.
    pub fn less_than(a: &[Limb], b: &[Limb]) -> Choice {
        let mut borrow = 0;
        for index in 0..a.len().max(b.len()) {
            (_, borrow) = Limbs::borrowing_sub(Limbs::limb(a, index), Limbs::limb(b, index), borrow);
        }
        Limbs::choice(borrow)
    }

    /// Compares `a` and `b`, of any lengths; the time depends on the values.
    pub fn compare_vartime(a: &[Limb], b: &[Limb]) -> Ordering {
        for index in (0..a.len().max(b.len())).rev() {
            match Limbs::limb(a, index).cmp(&Limbs::limb(b, index)) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }

    /// `(low, high) = a * b` (schoolbook multiplication), where the product's
    /// less significant limbs go to `low` and the rest to `high`, which
    /// together hold `a.len() + b.len()` limbs. To write the product into one
    /// slice, split it: `let (low, high) = out.split_at_mut(a.len())`.
    pub fn mul(low: &mut [Limb], high: &mut [Limb], a: &[Limb], b: &[Limb]) {
        assert!(low.len() + high.len() == a.len() + b.len());
        low.fill(0);
        high.fill(0);
        let split = low.len();
        for (i, &b_limb) in b.iter().enumerate() {
            let mut carry = 0;
            for (j, &a_limb) in a.iter().enumerate() {
                let index = i + j;
                let limb = if index < split { &mut low[index] } else { &mut high[index - split] };
                (*limb, carry) = Limbs::carrying_mul_add(a_limb, b_limb, *limb, carry);
            }
            let index = i + a.len();
            *(if index < split { &mut low[index] } else { &mut high[index - split] }) = carry;
        }
    }

    /// Shifts `a` left by `bits`, discarding the bits shifted out (all of them
    /// if `bits` is at least the length in bits).
    pub fn shl(a: &mut [Limb], bits: u32) {
        let limbs = (bits / Limb::BITS) as usize;
        let shift = bits % Limb::BITS;
        for index in (0..a.len()).rev() {
            let low = if index >= limbs { a[index - limbs] } else { 0 };
            let lower = if index > limbs { a[index - limbs - 1] } else { 0 };
            a[index] = if shift == 0 { low } else { (low << shift) | (lower >> (Limb::BITS - shift)) };
        }
    }

    /// Shifts `a` right by `bits`, discarding the bits shifted out (all of them
    /// if `bits` is at least the length in bits).
    pub fn shr(a: &mut [Limb], bits: u32) {
        let limbs = (bits / Limb::BITS) as usize;
        let shift = bits % Limb::BITS;
        for index in 0..a.len() {
            let high = index.checked_add(limbs).and_then(|index| a.get(index)).copied().unwrap_or(0);
            let higher = index.checked_add(limbs + 1).and_then(|index| a.get(index)).copied().unwrap_or(0);
            a[index] = if shift == 0 { high } else { (high >> shift) | (higher << (Limb::BITS - shift)) };
        }
    }

    /// Shifts `a` left by one bit and returns the bit shifted out.
    pub fn shl_1(a: &mut [Limb]) -> Limb {
        let mut carry = 0;
        for limb in a.iter_mut() {
            let next = *limb >> (Limb::BITS - 1);
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        carry
    }

    /// Shifts `a` right by one bit and returns the bit shifted out.
    pub fn shr_1(a: &mut [Limb]) -> Limb {
        let mut carry = 0;
        for limb in a.iter_mut().rev() {
            let next = *limb & 1;
            *limb = (*limb >> 1) | (carry << (Limb::BITS - 1));
            carry = next;
        }
        carry
    }

    /// Bit `index` of `a`, counted from the least significant; false beyond the end.
    pub fn bit(a: &[Limb], index: u32) -> Choice {
        match a.get((index / Limb::BITS) as usize) {
            Some(&limb) => Limbs::choice(limb >> (index % Limb::BITS)),
            None => Choice::FALSE,
        }
    }

    /// The number of bits of `limb` up to its highest set bit, by a branchless
    /// binary search (`leading_zeros` may branch on targets without such an instruction).
    // `Limb` is `u32` on 32-bit targets, where the casts to `u32` change nothing; they are needed elsewhere.
    #[allow(clippy::unnecessary_cast)]
    pub fn limb_bit_length(limb: Limb) -> u32 {
        let mut value = limb;
        let mut length = 0;
        let mut shift = Limb::BITS / 2;
        while shift > 0 {
            let high = value >> shift;
            let nonzero = high.ct_ne(&0);
            length |= shift & Limbs::mask(nonzero) as u32;
            value = Limb::select(&value, &high, nonzero);
            shift /= 2;
        }
        // `value` is now 0 or 1.
        length + value as u32
    }

    /// The number of bits of `a` up to its highest set bit (0 for zero).
    pub fn bit_length(a: &[Limb]) -> u32 {
        let mut length: u32 = 0;
        for (index, &limb) in a.iter().enumerate() {
            let candidate = index as u32 * Limb::BITS + Limbs::limb_bit_length(limb);
            length = u32::select(&length, &candidate, limb.ct_ne(&0));
        }
        length
    }

    /// Byte `position` of `a`, counted from the least significant; zero beyond the end.
    pub fn byte(a: &[Limb], position: usize) -> u8 {
        match a.get(position / Limbs::BYTES) {
            Some(&limb) => (limb >> (8 * (position % Limbs::BYTES))) as u8,
            None => 0,
        }
    }

    /// Whether `a` has a set bit at or above byte `length`, revealing only that.
    pub fn exceeds_bytes(a: &[Limb], length: usize) -> bool {
        let mut overflow = 0u8;
        for position in length..a.len() * Limbs::BYTES {
            overflow |= Limbs::byte(a, position);
        }
        overflow != 0
    }

    /// Reads the big-endian `bytes` into `out`; fails (leaving `out` zeroed)
    /// if the value needs more limbs. Leading zero bytes beyond the precision are allowed.
    pub fn from_be_bytes(out: &mut [Limb], bytes: &[u8]) -> Result<(), MathError> {
        out.fill(0);
        let capacity = out.len() * Limbs::BYTES;
        let mut overflow = 0u8;
        for (position, &byte) in bytes.iter().rev().enumerate() {
            if position < capacity {
                out[position / Limbs::BYTES] |= (byte as Limb) << (8 * (position % Limbs::BYTES));
            } else {
                overflow |= byte;
            }
        }
        if overflow != 0 {
            out.fill(0);
            return Err(MathError::Overflow);
        }
        Ok(())
    }

    /// Reads the little-endian `bytes` into `out`; fails (leaving `out` zeroed)
    /// if the value needs more limbs. Trailing zero bytes beyond the precision are allowed.
    pub fn from_le_bytes(out: &mut [Limb], bytes: &[u8]) -> Result<(), MathError> {
        out.fill(0);
        let capacity = out.len() * Limbs::BYTES;
        let mut overflow = 0u8;
        for (position, &byte) in bytes.iter().enumerate() {
            if position < capacity {
                out[position / Limbs::BYTES] |= (byte as Limb) << (8 * (position % Limbs::BYTES));
            } else {
                overflow |= byte;
            }
        }
        if overflow != 0 {
            out.fill(0);
            return Err(MathError::Overflow);
        }
        Ok(())
    }

    /// Writes `a` big-endian into all of `out`, with leading zeros; fails
    /// (leaving `out` zeroed) if the value needs more bytes.
    pub fn write_be_bytes(a: &[Limb], out: &mut [u8]) -> Result<(), MathError> {
        if Limbs::exceeds_bytes(a, out.len()) {
            out.fill(0);
            return Err(MathError::Overflow);
        }
        let length = out.len();
        for (position, byte) in out.iter_mut().enumerate() {
            *byte = Limbs::byte(a, length - 1 - position);
        }
        Ok(())
    }

    /// Writes `a` little-endian into all of `out`, with trailing zeros; fails
    /// (leaving `out` zeroed) if the value needs more bytes.
    pub fn write_le_bytes(a: &[Limb], out: &mut [u8]) -> Result<(), MathError> {
        if Limbs::exceeds_bytes(a, out.len()) {
            out.fill(0);
            return Err(MathError::Overflow);
        }
        for (position, byte) in out.iter_mut().enumerate() {
            *byte = Limbs::byte(a, position);
        }
        Ok(())
    }

    /// The value of the hexadecimal digit `character`, if it is one.
    pub const fn hex_digit(character: u8) -> Option<u8> {
        match character {
            b'0'..=b'9' => Some(character - b'0'),
            b'a'..=b'f' => Some(character - b'a' + 10),
            b'A'..=b'F' => Some(character - b'A' + 10),
            _ => None,
        }
    }

    /// Reads the big-endian hexadecimal `text` (one digit or more, nothing
    /// else) into `out`; fails (leaving `out` zeroed) if a character is not a
    /// digit or the value needs more limbs. Leading zeros beyond the precision
    /// are allowed. The time depends on the digits: hexadecimal text is meant
    /// for public values such as constants. It is a `const fn` for them.
    pub const fn from_hex_vartime(out: &mut [Limb], text: &str) -> Result<(), MathError> {
        let bytes = text.as_bytes();
        let mut index = 0;
        while index < out.len() {
            out[index] = 0;
            index += 1;
        }
        if bytes.is_empty() {
            return Err(MathError::InvalidDigit { position: 0 });
        }
        let mut position = 0;
        let mut result = Ok(());
        while position < bytes.len() {
            let place = bytes.len() - 1 - position;
            match Limbs::hex_digit(bytes[position]) {
                None => {
                    result = Err(MathError::InvalidDigit { position });
                    break;
                }
                Some(value) if place / Limbs::HEX_DIGITS < out.len() => {
                    out[place / Limbs::HEX_DIGITS] |= (value as Limb) << (4 * (place % Limbs::HEX_DIGITS));
                }
                Some(0) => {}
                Some(_) => {
                    result = Err(MathError::Overflow);
                    break;
                }
            }
            position += 1;
        }
        if result.is_err() {
            let mut index = 0;
            while index < out.len() {
                out[index] = 0;
                index += 1;
            }
        }
        result
    }

    /// `remainder = (low, high) mod divisor` for the number whose less
    /// significant limbs are `low` and more significant limbs are `high` (the
    /// order of [`Limbs::mul`]), by restoring shift-and-subtract division, one
    /// step per bit. `remainder` is as long as `divisor`, which must not be zero.
    pub fn rem(remainder: &mut [Limb], low: &[Limb], high: &[Limb], divisor: &[Limb]) -> Result<(), MathError> {
        Limbs::div_rem(None, remainder, low, high, divisor)
    }

    /// Like [`Limbs::rem`], and writes the quotient into `quotient` if given,
    /// which must be as long as `low` and `high` together.
    pub fn div_rem(
        mut quotient: Option<&mut [Limb]>,
        remainder: &mut [Limb],
        low: &[Limb],
        high: &[Limb],
        divisor: &[Limb],
    ) -> Result<(), MathError> {
        assert!(remainder.len() == divisor.len());
        if let Some(quotient) = &quotient {
            assert!(quotient.len() == high.len() + low.len());
        }
        remainder.fill(0);
        if let Some(quotient) = quotient.as_deref_mut() {
            quotient.fill(0);
        }
        if Limbs::is_zero(divisor).into_bool() {
            return Err(MathError::DivisionByZero);
        }
        let _timing = DataIndependentTiming::enable();
        let low_bits = low.len() as u32 * Limb::BITS;
        let total = (high.len() + low.len()) as u32 * Limb::BITS;
        for step in (0..total).rev() {
            let bit = if step >= low_bits { Limbs::bit(high, step - low_bits) } else { Limbs::bit(low, step) };
            // remainder = 2 * remainder + bit, which is below 2 * divisor.
            let carry = Limbs::shl_1(remainder);
            remainder[0] |= bit.bit() as Limb;
            // Subtract the divisor if the value is at least the divisor: when a
            // bit was shifted out, or when the subtraction does not borrow.
            let subtract = Limbs::choice(carry) | !Limbs::less_than(remainder, divisor);
            Limbs::conditional_sub(remainder, divisor, subtract);
            if let Some(quotient) = quotient.as_deref_mut() {
                quotient[(step / Limb::BITS) as usize] |= (subtract.bit() as Limb) << (step % Limb::BITS);
            }
        }
        Ok(())
    }
}
