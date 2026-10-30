use std::ffi::CString;
use std::io;

use super::sys;

/// The network interfaces of the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInterface;

impl NetworkInterface {
    /// The index of the interface `name` (such as `lo` or `en0`): the scope
    /// of link-local IPv6 addresses and the interface of packet sockets.
    pub fn index(name: &str) -> io::Result<u32> {
        let name = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: a NUL-terminated string that lives during the call.
        match unsafe { sys::if_nametoindex(name.as_ptr()) } {
            0 => Err(io::Error::from(io::ErrorKind::NotFound)),
            index => Ok(index),
        }
    }
}
