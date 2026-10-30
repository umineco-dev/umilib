use std::fs::File;
use std::io::{self, Read};

use super::sys::{self, Linux};

/// The random bytes of the kernel: the `getrandom` system call (which
/// waits once at boot until the kernel's generator is seeded), or
/// `/dev/urandom` on kernels older than 3.17 and architectures whose call
/// number is not known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Random;

impl Random {
    pub const fn new() -> Random {
        Random
    }

    /// Fills `buffer` with random bytes.
    pub fn fill(&self, buffer: &mut [u8]) -> io::Result<()> {
        let Some(number) = Linux::SYS_GETRANDOM else { return Random::fill_from_device(buffer) };
        let mut done = 0;
        while done < buffer.len() {
            let rest = &mut buffer[done..];
            // SAFETY: the bytes are writable for their length; the result is checked.
            let result = unsafe { sys::syscall(number, rest.as_mut_ptr(), rest.len(), 0usize) };
            if result < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(Linux::EINTR) => continue,
                    Some(Linux::ENOSYS) => return Random::fill_from_device(rest),
                    _ => return Err(error),
                }
            }
            done += result as usize;
        }
        Ok(())
    }

    /// Fills `buffer` from `/dev/urandom`.
    pub fn fill_from_device(buffer: &mut [u8]) -> io::Result<()> {
        File::open("/dev/urandom")?.read_exact(buffer)
    }
}

#[cfg(umilib_feature = "crypto-random")]
impl crate::crypto::random::Random for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::crypto::random::RandomError> {
        Random::fill(self, out).map_err(|_| crate::crypto::random::RandomError::EntropySource)
    }
}
