use core::fmt;
use core::ops::BitXor;

/// An unsigned integer that holds a CRC register: [`u8`], [`u16`], [`u32`],
/// [`u64`] or [`u128`], the smallest that holds the width saving memory in
/// the tables.
pub trait CRCRegister: Copy + Eq + fmt::Debug + fmt::LowerHex + BitXor<Output = Self> {
    const BITS: u32;
    const ZERO: Self;
    /// The size in bytes, of the output of [`CRC`](super::CRC) as a [`Digest`](crate::hash::Digest).
    const SIZE: usize;
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + Eq + fmt::Debug;

    fn from_byte(byte: u8) -> Self;
    /// The lowest eight bits.
    fn low_byte(self) -> u8;
    /// The highest eight bits.
    fn high_byte(self) -> u8;
    /// Shifts left by `bits`, giving zero when `bits` is the whole register.
    fn shift_left(self, bits: u32) -> Self;
    /// Shifts right by `bits`, giving zero when `bits` is the whole register.
    fn shift_right(self, bits: u32) -> Self;
    /// The lowest `width` bits in reverse order.
    fn reflect(self, width: u32) -> Self;
    fn to_be_bytes(self) -> Self::Bytes;
}

/// Implements [`CRCRegister`] for an unsigned integer type.
macro_rules! crc_register {
    ($($type:ty),*) => {$(
        impl CRCRegister for $type {
            const BITS: u32 = <$type>::BITS;
            const ZERO: $type = 0;
            const SIZE: usize = core::mem::size_of::<$type>();
            type Bytes = [u8; core::mem::size_of::<$type>()];

            fn from_byte(byte: u8) -> $type {
                byte as $type
            }

            fn low_byte(self) -> u8 {
                self as u8
            }

            fn high_byte(self) -> u8 {
                (self >> (<$type>::BITS - 8)) as u8
            }

            fn shift_left(self, bits: u32) -> $type {
                self.checked_shl(bits).unwrap_or(0)
            }

            fn shift_right(self, bits: u32) -> $type {
                self.checked_shr(bits).unwrap_or(0)
            }

            fn reflect(self, width: u32) -> $type {
                self.reverse_bits().shift_right(<$type>::BITS - width)
            }

            fn to_be_bytes(self) -> Self::Bytes {
                <$type>::to_be_bytes(self)
            }
        }
    )*};
}

crc_register!(u8, u16, u32, u64, u128);
