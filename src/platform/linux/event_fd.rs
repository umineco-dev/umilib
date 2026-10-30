use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use super::sys::{self, Linux};
use crate::platform::unix::Socket;

/// A nonblocking `eventfd`: a counter that [`EventFD::notify`] increments
/// and [`EventFD::drain`] resets, readable while it is not zero.
#[derive(Debug)]
pub struct EventFD {
    file: File,
}

impl EventFD {
    pub fn new() -> io::Result<EventFD> {
        // SAFETY: plain values; the result is checked.
        let descriptor = Socket::check(unsafe { sys::eventfd(0, Linux::EFD_CLOEXEC | Linux::EFD_NONBLOCK) })?;
        // SAFETY: the descriptor was just created and is owned by nothing else.
        Ok(EventFD { file: File::from(unsafe { OwnedFd::from_raw_fd(descriptor) }) })
    }

    /// Adds 1 to the counter.
    pub fn notify(&self) -> io::Result<()> {
        match (&self.file).write(&1u64.to_ne_bytes()) {
            Ok(_) => Ok(()),
            // The counter is at its maximum: it is readable anyway.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Resets the counter; the notifications since the last drain.
    pub fn drain(&self) -> io::Result<u64> {
        let mut value = [0u8; 8];
        match (&self.file).read(&mut value) {
            Ok(_) => Ok(u64::from_ne_bytes(value)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error),
        }
    }
}

impl AsRawFd for EventFD {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
