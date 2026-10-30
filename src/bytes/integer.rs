/// A fixed-size integer that converts to and from big- and little-endian bytes.
///
/// [`Integer::SIZE`] must be at most [`Integer::MAXIMUM_SIZE`]; reads and
/// writes of larger implementations fail with
/// [`BytesError::InvalidLength`](super::BytesError::InvalidLength).
pub trait Integer: Copy + Sized {
    /// The largest supported [`Integer::SIZE`], the size of `u128`.
    const MAXIMUM_SIZE: usize = 16;

    /// The number of bytes in the encoding.
    const SIZE: usize;
    /// Whether the integer is signed (sign-extended when read from fewer bytes).
    const SIGNED: bool;

    /// Decodes the integer from exactly [`Self::SIZE`] big-endian bytes.
    fn from_be_slice(bytes: &[u8]) -> Self;
    /// Decodes the integer from exactly [`Self::SIZE`] little-endian bytes.
    fn from_le_slice(bytes: &[u8]) -> Self;
    /// Encodes the integer into exactly [`Self::SIZE`] big-endian bytes.
    fn to_be_slice(self, bytes: &mut [u8]);
    /// Encodes the integer into exactly [`Self::SIZE`] little-endian bytes.
    fn to_le_slice(self, bytes: &mut [u8]);
}

macro_rules! integer {
    ($($type:ty: $signed:literal),* $(,)?) => {
        $(
            impl Integer for $type {
                const SIZE: usize = core::mem::size_of::<$type>();
                const SIGNED: bool = $signed;

                fn from_be_slice(bytes: &[u8]) -> Self {
                    let mut array = [0u8; core::mem::size_of::<$type>()];
                    array.copy_from_slice(bytes);
                    <$type>::from_be_bytes(array)
                }

                fn from_le_slice(bytes: &[u8]) -> Self {
                    let mut array = [0u8; core::mem::size_of::<$type>()];
                    array.copy_from_slice(bytes);
                    <$type>::from_le_bytes(array)
                }

                fn to_be_slice(self, bytes: &mut [u8]) {
                    bytes.copy_from_slice(&self.to_be_bytes());
                }

                fn to_le_slice(self, bytes: &mut [u8]) {
                    bytes.copy_from_slice(&self.to_le_bytes());
                }
            }
        )*
    };
}

integer!(u8: false, u16: false, u32: false, u64: false, u128: false, i8: true, i16: true, i32: true, i64: true, i128: true);
