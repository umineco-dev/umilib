use std::io;

use super::sys::{self, Darwin};

/// The random bytes of the system: `getentropy` (at most 256 bytes a call).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Random;

impl Random {
    pub const fn new() -> Random {
        Random
    }

    /// Fills `buffer` with random bytes.
    pub fn fill(&self, buffer: &mut [u8]) -> io::Result<()> {
        for chunk in buffer.chunks_mut(Darwin::ENTROPY_MAXIMUM) {
            // SAFETY: the chunk is writable for its length; the result is checked.
            if unsafe { sys::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
                return Err(io::Error::last_os_error());
            }
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
