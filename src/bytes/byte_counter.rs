use super::{BytesError, Writer};

/// A [`Writer`] that keeps only the number of bytes written: the length an
/// encoding will take, found without allocating.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ByteCounter {
    pub count: usize,
}

impl Writer for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), BytesError> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or(BytesError::CapacityExceeded { requested: bytes.len(), limit: usize::MAX - self.count })?;
        Ok(())
    }
}
