use super::{BytesError, Writer};

/// A writer that fills a caller-provided slice from the start.
#[derive(Debug, PartialEq, Eq)]
pub struct SliceWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> SliceWriter<'a> {
    /// Creates a writer positioned at the start of `bytes`.
    pub fn new(bytes: &'a mut [u8]) -> SliceWriter<'a> {
        SliceWriter { bytes, position: 0 }
    }

    /// The number of bytes written.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The length of the whole slice.
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// The number of bytes that can still be written.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// The whole slice, written or not.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    /// The bytes written.
    pub fn written(&self) -> &[u8] {
        &self.bytes[..self.position]
    }

    /// Returns the written part of the slice, consuming the writer.
    pub fn into_written(self) -> &'a mut [u8] {
        &mut self.bytes[..self.position]
    }
}

impl Writer for SliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BytesError> {
        if bytes.len() > self.remaining() {
            return Err(BytesError::CapacityExceeded { requested: bytes.len(), limit: self.bytes.len() });
        }
        self.bytes[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
        Ok(())
    }
}
