use super::{BytesError, Integer, Reader};

/// A sink of bytes. Every write either succeeds completely or writes nothing.
pub trait Writer {
    /// Appends `bytes`.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BytesError>;

    /// Appends one byte.
    fn write_u8(&mut self, value: u8) -> Result<(), BytesError> {
        self.write(&[value])
    }

    /// Appends `value` as [`Integer::SIZE`] big-endian bytes.
    fn write_be<T: Integer>(&mut self, value: T) -> Result<(), BytesError> {
        Reader::check_length::<T>(T::SIZE)?;
        let mut bytes = [0u8; 16];
        value.to_be_slice(&mut bytes[..T::SIZE]);
        self.write(&bytes[..T::SIZE])
    }

    /// Appends `value` as [`Integer::SIZE`] little-endian bytes.
    fn write_le<T: Integer>(&mut self, value: T) -> Result<(), BytesError> {
        Reader::check_length::<T>(T::SIZE)?;
        let mut bytes = [0u8; 16];
        value.to_le_slice(&mut bytes[..T::SIZE]);
        self.write(&bytes[..T::SIZE])
    }

    /// Appends `value` as `length` big-endian bytes. Fails if the value does
    /// not fit, so that [`Reader::read_be_sized`] reads back the same value.
    fn write_be_sized<T: Integer>(&mut self, value: T, length: usize) -> Result<(), BytesError> {
        Reader::check_length::<T>(length)?;
        let mut bytes = [0u8; 16];
        let bytes = &mut bytes[..T::SIZE];
        value.to_be_slice(bytes);
        let (dropped, kept) = bytes.split_at(T::SIZE - length);
        let extension = if T::SIGNED && kept[0] & 0x80 != 0 { 0xFF } else { 0x00 };
        if dropped.iter().any(|&byte| byte != extension) {
            return Err(BytesError::ValueTooLarge { length });
        }
        self.write(kept)
    }

    /// Appends `value` as `length` little-endian bytes. Fails if the value does
    /// not fit, so that [`Reader::read_le_sized`] reads back the same value.
    fn write_le_sized<T: Integer>(&mut self, value: T, length: usize) -> Result<(), BytesError> {
        Reader::check_length::<T>(length)?;
        let mut bytes = [0u8; 16];
        let bytes = &mut bytes[..T::SIZE];
        value.to_le_slice(bytes);
        let (kept, dropped) = bytes.split_at(length);
        let extension = if T::SIGNED && kept[length - 1] & 0x80 != 0 { 0xFF } else { 0x00 };
        if dropped.iter().any(|&byte| byte != extension) {
            return Err(BytesError::ValueTooLarge { length });
        }
        self.write(kept)
    }
}
