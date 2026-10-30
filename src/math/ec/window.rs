use crate::math::bigint::UnsignedInteger;
use crate::secret::Zeroize;

/// The fixed windows of the constant-time scalar multiplications: the bits
/// of a scalar are read [`Window::BITS`] at a time, from the most
/// significant, over every bit of its precision.
pub struct Window;

impl Window {
    /// The bits of a window.
    pub const BITS: u32 = 4;
    /// The multiples 0 to 2^BITS - 1 of a table.
    pub const ENTRIES: usize = 1 << Window::BITS;

    /// The number of windows of an integer of type `V`.
    pub fn count<V: UnsignedInteger>() -> u32 {
        V::BITS.div_ceil(Window::BITS)
    }

    /// The digit of window `window` of `value` (bits `BITS × window` and up),
    /// read without branches.
    pub fn digit<V: UnsignedInteger>(value: &V, window: u32) -> u8 {
        let mut digit = 0u8;
        for offset in 0..Window::BITS {
            let index = window * Window::BITS + offset;
            if index < V::BITS {
                digit |= value.bit(index).bit() << offset;
            }
        }
        digit
    }

    /// Erases a digit once used.
    pub fn erase(digit: &mut u8) {
        digit.zeroize();
    }
}
