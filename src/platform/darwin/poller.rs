use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use std::vec::Vec;

use super::sys::{self, Darwin, KEvent, TimeSpec};
use crate::platform::unix::sys::{self as unix, POSIX};
use crate::platform::unix::{Interest, PollEvent, PollMode, Socket};

/// A readiness poller on `kqueue`, with a user event that
/// [`Poller::notify`] triggers to end a wait from another thread. It may be
/// shared by threads. Readiness for reading and for writing are separate
/// events of one token.
#[derive(Debug)]
pub struct Poller {
    queue: OwnedFd,
}

impl Poller {
    /// The most events one wait returns.
    pub const MAXIMUM_EVENTS: usize = 256;
    /// The identifier of the user event of notifications.
    pub const NOTIFY_IDENTIFIER: usize = 0;

    pub fn new() -> io::Result<Poller> {
        // SAFETY: no arguments; the result is checked.
        let queue = Socket::check(unsafe { sys::kqueue() })?;
        // SAFETY: the descriptor was just created and is owned by nothing else.
        let poller = Poller { queue: unsafe { OwnedFd::from_raw_fd(queue) } };
        // SAFETY: a valid descriptor; the result is checked.
        Socket::check(unsafe { unix::fcntl(poller.queue.as_raw_fd(), POSIX::F_SETFD, POSIX::FD_CLOEXEC) })?;
        let notify = Poller::change(
            Poller::NOTIFY_IDENTIFIER,
            Darwin::EVFILT_USER,
            Darwin::EV_ADD | Darwin::EV_CLEAR,
            0,
            PollEvent::NOTIFY,
        );
        poller.apply(&[notify], false)?;
        Ok(poller)
    }

    /// A change of the event (`identifier`, `filter`).
    pub fn change(identifier: usize, filter: i16, flags: u16, fflags: u32, token: usize) -> KEvent {
        KEvent { ident: identifier, filter, flags, fflags, data: 0, udata: token as *mut core::ffi::c_void }
    }

    /// The most changes [`Poller::apply`] takes at once.
    pub const MAXIMUM_CHANGES: usize = 2;

    /// Applies `changes` (at most [`Poller::MAXIMUM_CHANGES`]), reporting
    /// the first error (`ENOENT` ignored if `deleting`).
    pub fn apply(&self, changes: &[KEvent], deleting: bool) -> io::Result<()> {
        let count = changes.len().min(Poller::MAXIMUM_CHANGES);
        let mut receipts = [KEvent::default(); Poller::MAXIMUM_CHANGES];
        receipts[..count].copy_from_slice(&changes[..count]);
        receipts[..count].iter_mut().for_each(|change| change.flags |= Darwin::EV_RECEIPT);
        // With EV_RECEIPT every change gives back one event, its result; the array serves as both.
        let pointer = receipts.as_mut_ptr();
        // SAFETY: the array is valid for `count` changes and results; the result is checked.
        let returned = Socket::check(unsafe {
            sys::kevent(self.queue.as_raw_fd(), pointer, count as i32, pointer, count as i32, core::ptr::null())
        })?;
        for result in &receipts[..returned as usize] {
            let code = result.data as i32;
            if result.flags & Darwin::EV_ERROR != 0 && code != 0 && !(deleting && code == Darwin::ENOENT) {
                return Err(io::Error::from_raw_os_error(code));
            }
        }
        Ok(())
    }

    /// The changes that make `descriptor` watched for `interest` in `mode`.
    pub fn changes(descriptor: RawFd, token: usize, interest: Interest, mode: PollMode) -> [KEvent; 2] {
        let mode = match mode {
            PollMode::Level => 0,
            PollMode::Edge => Darwin::EV_CLEAR,
            PollMode::Oneshot => Darwin::EV_ONESHOT,
        };
        let flags = |wanted: bool| if wanted { Darwin::EV_ADD | Darwin::EV_ENABLE | mode } else { Darwin::EV_DELETE };
        [
            Poller::change(descriptor as usize, Darwin::EVFILT_READ, flags(interest.readable), 0, token),
            Poller::change(descriptor as usize, Darwin::EVFILT_WRITE, flags(interest.writable), 0, token),
        ]
    }

    /// Watches `descriptor` for `interest`, reported with `token` (not [`PollEvent::NOTIFY`]).
    pub fn add(&self, descriptor: RawFd, token: usize, interest: Interest, mode: PollMode) -> io::Result<()> {
        self.modify(descriptor, token, interest, mode)
    }

    /// Changes what `descriptor` is watched for (and re-arms a oneshot one).
    pub fn modify(&self, descriptor: RawFd, token: usize, interest: Interest, mode: PollMode) -> io::Result<()> {
        if token == PollEvent::NOTIFY {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        self.apply(&Poller::changes(descriptor, token, interest, mode), true)
    }

    /// Stops watching `descriptor`.
    pub fn delete(&self, descriptor: RawFd) -> io::Result<()> {
        self.apply(&Poller::changes(descriptor, 0, Interest::default(), PollMode::Level), true)
    }

    /// Waits at most `timeout` (forever if `None`) for events, and replaces
    /// the contents of `events` with them (at most [`Poller::MAXIMUM_EVENTS`]);
    /// a notification is one event of token [`PollEvent::NOTIFY`]. An
    /// interrupted wait returns no events.
    pub fn wait(&self, events: &mut Vec<PollEvent>, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();
        let mut raw = [KEvent::default(); Poller::MAXIMUM_EVENTS];
        let timespec = timeout.map(|timeout| TimeSpec {
            seconds: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
            nanoseconds: timeout.subsec_nanos() as i64,
        });
        let timeout_pointer = timespec.as_ref().map_or(core::ptr::null(), |timespec| timespec as *const TimeSpec);
        // SAFETY: the array is writable for the count given; the result is checked.
        let result = unsafe {
            sys::kevent(
                self.queue.as_raw_fd(),
                core::ptr::null(),
                0,
                raw.as_mut_ptr(),
                raw.len() as i32,
                timeout_pointer,
            )
        };
        let count = match Socket::check(result) {
            Ok(count) => count as usize,
            Err(error) if error.raw_os_error() == Some(Darwin::EINTR) => 0,
            Err(error) => return Err(error),
        };
        for event in &raw[..count] {
            if event.filter == Darwin::EVFILT_USER {
                events.push(PollEvent { token: PollEvent::NOTIFY, readable: true, ..PollEvent::default() });
                continue;
            }
            let token = event.udata as usize;
            let hangup = event.flags & Darwin::EV_EOF != 0;
            let error = event.flags & Darwin::EV_ERROR != 0 || (hangup && event.fflags != 0);
            events.push(PollEvent {
                token,
                readable: event.filter == Darwin::EVFILT_READ || error,
                writable: event.filter == Darwin::EVFILT_WRITE || error,
                hangup,
                error,
            });
        }
        Ok(count)
    }

    /// Ends the current wait, or the next one, from any thread.
    pub fn notify(&self) -> io::Result<()> {
        let trigger =
            Poller::change(Poller::NOTIFY_IDENTIFIER, Darwin::EVFILT_USER, 0, Darwin::NOTE_TRIGGER, PollEvent::NOTIFY);
        self.apply(&[trigger], false)
    }
}
