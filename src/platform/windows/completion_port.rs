use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::time::Duration;
use std::vec::Vec;

use super::sys::{self, OverlappedEntry, Windows};

/// A completion of a [`CompletionPort`]: the key of the handle (or of the
/// post), the address of the operation's `OVERLAPPED` (0 for a post without
/// one) and the bytes transferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Completion {
    pub key: usize,
    pub overlapped: usize,
    pub bytes: u32,
}

impl Completion {
    /// The key of the port's own notification ([`CompletionPort::notify`]).
    pub const NOTIFY: usize = usize::MAX;
}

/// An I/O completion port: handles associated with it (sockets created
/// overlapped) report their completed operations, and threads wait for
/// them. It may be shared by threads.
#[derive(Debug)]
pub struct CompletionPort {
    port: OwnedHandle,
    maximum_completions: usize,
}

// SAFETY: a completion port handle may be used from any thread.
unsafe impl Send for CompletionPort {}
// SAFETY: as above; its functions are thread-safe.
unsafe impl Sync for CompletionPort {}

impl CompletionPort {
    /// The most completions one wait returns, by default.
    pub const DEFAULT_MAXIMUM_COMPLETIONS: usize = 256;

    /// A port that lets at most `threads` threads run its completions at
    /// once (0 for as many as processors), whose waits return at most
    /// [`CompletionPort::DEFAULT_MAXIMUM_COMPLETIONS`] completions.
    pub fn new(threads: u32) -> io::Result<CompletionPort> {
        CompletionPort::with_maximum_completions(threads, CompletionPort::DEFAULT_MAXIMUM_COMPLETIONS)
    }

    /// A port as [`CompletionPort::new`] gives, whose waits return at most
    /// `maximum_completions` completions (1 to `u32::MAX`, the range
    /// `GetQueuedCompletionStatusEx` takes; `InvalidInput` otherwise).
    pub fn with_maximum_completions(threads: u32, maximum_completions: usize) -> io::Result<CompletionPort> {
        if maximum_completions == 0 || u32::try_from(maximum_completions).is_err() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let invalid = -1isize as sys::Handle;
        // SAFETY: a new port (no file); the result is checked.
        let port = unsafe { sys::CreateIoCompletionPort(invalid, core::ptr::null_mut(), 0, threads) };
        if port.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handle was just created and is owned by nothing else.
        Ok(CompletionPort { port: unsafe { OwnedHandle::from_raw_handle(port as RawHandle) }, maximum_completions })
    }

    /// Associates `handle` (a socket or file opened overlapped) with the
    /// port: its completions report `key` (not [`Completion::NOTIFY`]).
    pub fn associate(&self, handle: RawHandle, key: usize) -> io::Result<()> {
        if key == Completion::NOTIFY {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // SAFETY: the caller's handle and this port; the result is checked.
        let result = unsafe { sys::CreateIoCompletionPort(handle as sys::Handle, self.raw(), key, 0) };
        if result.is_null() { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn raw(&self) -> sys::Handle {
        self.port.as_raw_handle() as sys::Handle
    }

    /// Queues a completion of `key`, `bytes` and no `OVERLAPPED`.
    pub fn post(&self, key: usize, bytes: u32) -> io::Result<()> {
        // SAFETY: this port, plain values; the result is checked.
        if unsafe { sys::PostQueuedCompletionStatus(self.raw(), bytes, key, core::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The most completions one wait returns.
    pub fn maximum_completions(&self) -> usize {
        self.maximum_completions
    }

    /// Ends the current wait, or the next one, from any thread: a completion of key [`Completion::NOTIFY`].
    pub fn notify(&self) -> io::Result<()> {
        self.post(Completion::NOTIFY, 0)
    }

    /// Waits at most `timeout` (forever if `None`) for completions and
    /// replaces the contents of `completions` with them (at most
    /// [`CompletionPort::maximum_completions`]).
    pub fn wait(&self, completions: &mut Vec<Completion>, timeout: Option<Duration>) -> io::Result<usize> {
        completions.clear();
        let mut entries = Vec::new();
        entries.try_reserve_exact(self.maximum_completions).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        entries.resize(self.maximum_completions, OverlappedEntry::default());
        // The constructor checked that the count fits in a `u32`.
        let capacity = u32::try_from(entries.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let milliseconds = timeout.map_or(Windows::INFINITE, |timeout| {
            u32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(Windows::INFINITE - 1)
        });
        let mut removed = 0u32;
        // SAFETY: the entries are writable for the count given; the result is checked.
        let result = unsafe {
            sys::GetQueuedCompletionStatusEx(self.raw(), entries.as_mut_ptr(), capacity, &mut removed, milliseconds, 0)
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(Windows::WAIT_TIMEOUT) { Ok(0) } else { Err(error) };
        }
        for entry in &entries[..removed as usize] {
            completions.push(Completion { key: entry.key, overlapped: entry.overlapped as usize, bytes: entry.bytes });
        }
        Ok(removed as usize)
    }
}
