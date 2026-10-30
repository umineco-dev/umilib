use std::io;

use super::sys;

/// The random bytes of the system: `ProcessPrng`, the generator of the
/// process the system seeds (Windows 10 and later), which does not fail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Random;

impl Random {
    pub const fn new() -> Random {
        Random
    }

    /// Fills `buffer` with random bytes.
    pub fn fill(&self, buffer: &mut [u8]) -> io::Result<()> {
        // SAFETY: the bytes are writable for their length.
        if unsafe { sys::ProcessPrng(buffer.as_mut_ptr(), buffer.len()) } == 0 {
            return Err(io::Error::other("ProcessPrng failed"));
        }
        Ok(())
    }
}

#[cfg(umilib_feature = "crypto-random")]
impl crate::crypto::random::Random for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::crypto::random::RandomError> {
        Random::fill(self, out).map_err(|_| crate::crypto::random::RandomError::EntropySource)
    }
}
