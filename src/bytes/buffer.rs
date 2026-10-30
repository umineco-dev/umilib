use alloc::vec::Vec;

use super::{BytesError, Writer};

/// A growable byte buffer with an optional size limit.
///
/// The limit bounds the memory an untrusted peer can make the buffer use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Buffer {
    bytes: Vec<u8>,
    limit: Option<usize>,
}

impl Buffer {
    /// Creates an empty buffer without a limit.
    pub const fn new() -> Buffer {
        Buffer { bytes: Vec::new(), limit: None }
    }

    /// Creates an empty buffer that never holds more than `limit` bytes.
    pub const fn with_limit(limit: usize) -> Buffer {
        Buffer { bytes: Vec::new(), limit: Some(limit) }
    }

    /// Creates an empty buffer that can hold `capacity` bytes without reallocating.
    ///
    /// Panics if the allocation fails, like [`Vec::with_capacity`]; use
    /// [`Buffer::try_with_capacity`] when `capacity` comes from untrusted input.
    pub fn with_capacity(capacity: usize) -> Buffer {
        Buffer { bytes: Vec::with_capacity(capacity), limit: None }
    }

    /// Like [`Buffer::with_capacity`], but fails instead of panicking if the
    /// memory cannot be allocated.
    pub fn try_with_capacity(capacity: usize) -> Result<Buffer, BytesError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| BytesError::CapacityExceeded { requested: capacity, limit: isize::MAX as usize })?;
        Ok(Buffer { bytes, limit: None })
    }

    /// The number of bytes the buffer can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// The maximum number of bytes, if any.
    pub const fn limit(&self) -> Option<usize> {
        self.limit
    }

    /// Changes the maximum number of bytes. Fails if the buffer already holds more.
    pub fn set_limit(&mut self, limit: Option<usize>) -> Result<(), BytesError> {
        if let Some(limit) = limit
            && self.bytes.len() > limit
        {
            return Err(BytesError::CapacityExceeded { requested: self.bytes.len(), limit });
        }
        self.limit = limit;
        Ok(())
    }

    /// The number of bytes written.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The bytes written.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Removes every byte, keeping the allocation and the limit.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Shortens the buffer to `length` bytes. Does nothing if it is already shorter.
    pub fn truncate(&mut self, length: usize) {
        self.bytes.truncate(length);
    }

    /// Returns the written bytes, consuming the buffer.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(bytes: Vec<u8>) -> Buffer {
        Buffer { bytes, limit: None }
    }
}

impl Writer for Buffer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BytesError> {
        if let Some(limit) = self.limit
            && bytes.len() > limit - self.bytes.len()
        {
            return Err(BytesError::CapacityExceeded { requested: bytes.len(), limit });
        }
        self.bytes.try_reserve(bytes.len()).map_err(|_| BytesError::CapacityExceeded {
            requested: bytes.len(),
            limit: self.limit.unwrap_or(isize::MAX as usize),
        })?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

/// A vector takes what is written, growing as needed; an allocation that
/// fails is `CapacityExceeded`, as for an unlimited [`Buffer`].
impl Writer for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BytesError> {
        self.try_reserve(bytes.len())
            .map_err(|_| BytesError::CapacityExceeded { requested: bytes.len(), limit: isize::MAX as usize })?;
        self.extend_from_slice(bytes);
        Ok(())
    }
}
