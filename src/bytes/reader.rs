use super::{BytesError, Integer};

/// A cursor that reads from a borrowed byte slice without copying.
///
/// Every read either succeeds completely or fails without moving the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, position: 0 }
    }

    /// The number of bytes already read.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// The number of bytes left to read.
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Whether every byte has been read.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the next `length` bytes without consuming them.
    pub fn peek(&self, length: usize) -> Result<&'a [u8], BytesError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(BytesError::UnexpectedEnd { needed: length, remaining });
        }
        Ok(&self.bytes[self.position..self.position + length])
    }

    /// Consumes and returns the next `length` bytes.
    pub fn read_slice(&mut self, length: usize) -> Result<&'a [u8], BytesError> {
        let slice = self.peek(length)?;
        self.position += length;
        Ok(slice)
    }

    /// Consumes the next `N` bytes into an array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], BytesError> {
        let mut array = [0u8; N];
        array.copy_from_slice(self.read_slice(N)?);
        Ok(array)
    }

    /// Consumes the next `length` bytes as a new reader over them.
    pub fn read_reader(&mut self, length: usize) -> Result<Reader<'a>, BytesError> {
        self.read_slice(length).map(Reader::new)
    }

    /// Consumes and returns every remaining byte.
    pub fn read_rest(&mut self) -> &'a [u8] {
        let rest = &self.bytes[self.position..];
        self.position = self.bytes.len();
        rest
    }

    /// Consumes `length` bytes without returning them.
    pub fn skip(&mut self, length: usize) -> Result<(), BytesError> {
        self.read_slice(length).map(|_| ())
    }

    /// Consumes one byte.
    pub fn read_u8(&mut self) -> Result<u8, BytesError> {
        Ok(self.read_slice(1)?[0])
    }

    /// Consumes a big-endian integer of [`Integer::SIZE`] bytes.
    pub fn read_be<T: Integer>(&mut self) -> Result<T, BytesError> {
        self.read_slice(T::SIZE).map(T::from_be_slice)
    }

    /// Consumes a little-endian integer of [`Integer::SIZE`] bytes.
    pub fn read_le<T: Integer>(&mut self) -> Result<T, BytesError> {
        self.read_slice(T::SIZE).map(T::from_le_slice)
    }

    /// Consumes a big-endian integer encoded in `length` bytes (for example the
    /// 24-bit lengths of TLS). Signed integers are sign-extended.
    pub fn read_be_sized<T: Integer>(&mut self, length: usize) -> Result<T, BytesError> {
        Reader::check_length::<T>(length)?;
        let bytes = self.peek(length)?;
        let mut full = [0u8; 16];
        let full = &mut full[..T::SIZE];
        if T::SIGNED && bytes[0] & 0x80 != 0 {
            full.fill(0xFF);
        }
        full[T::SIZE - length..].copy_from_slice(bytes);
        self.position += length;
        Ok(T::from_be_slice(full))
    }

    /// Consumes a little-endian integer encoded in `length` bytes. Signed
    /// integers are sign-extended.
    pub fn read_le_sized<T: Integer>(&mut self, length: usize) -> Result<T, BytesError> {
        Reader::check_length::<T>(length)?;
        let bytes = self.peek(length)?;
        let mut full = [0u8; 16];
        let full = &mut full[..T::SIZE];
        if T::SIGNED && bytes[length - 1] & 0x80 != 0 {
            full.fill(0xFF);
        }
        full[..length].copy_from_slice(bytes);
        self.position += length;
        Ok(T::from_le_slice(full))
    }

    /// Checks that an integer of type `T` can be encoded in `length` bytes.
    pub fn check_length<T: Integer>(length: usize) -> Result<(), BytesError> {
        let maximum = T::SIZE.min(T::MAXIMUM_SIZE);
        if length == 0 || length > maximum || T::SIZE > T::MAXIMUM_SIZE {
            return Err(BytesError::InvalidLength { length, maximum });
        }
        Ok(())
    }
}
