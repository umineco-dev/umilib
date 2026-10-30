use super::RandomError;

/// A source of random bytes.
pub trait Random {
    /// Fills `out` with random bytes, or fails without a guarantee about its contents.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;

    fn next_u32(&mut self) -> Result<u32, RandomError> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn next_u64(&mut self) -> Result<u64, RandomError> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

/// A source borrowed mutably is a source, so that `&mut dyn Random` can be
/// passed where a sized `R: Random` is taken.
impl<R: Random + ?Sized> Random for &mut R {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        (**self).fill(out)
    }
}

/// A boxed source is a source, so that `Box<dyn Random>` can be held and passed.
impl<R: Random + ?Sized> Random for alloc::boxed::Box<R> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        (**self).fill(out)
    }
}
