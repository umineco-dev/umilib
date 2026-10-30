use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use std::vec::Vec;

use super::EventFD;
use super::sys::{self, EpollEvent, Linux};
use crate::platform::unix::{Interest, PollEvent, PollMode, Socket};

/// A readiness poller on `epoll`, with an `eventfd` that
/// [`Poller::notify`] signals to end a wait from another thread. It may be
/// shared by threads.
#[derive(Debug)]
pub struct Poller {
    epoll: OwnedFd,
    notifier: EventFD,
}

impl Poller {
    /// The most events one wait returns.
    pub const MAXIMUM_EVENTS: usize = 256;

    pub fn new() -> io::Result<Poller> {
        // SAFETY: a plain flag; the result is checked.
        let epoll = Socket::check(unsafe { sys::epoll_create1(Linux::EPOLL_CLOEXEC) })?;
        // SAFETY: the descriptor was just created and is owned by nothing else.
        let epoll = unsafe { OwnedFd::from_raw_fd(epoll) };
        let poller = Poller { epoll, notifier: EventFD::new()? };
        poller.control(Linux::EPOLL_CTL_ADD, poller.notifier.as_raw_fd(), PollEvent::NOTIFY, Linux::EPOLLIN)?;
        Ok(poller)
    }

    /// The `epoll` flags of `interest` and `mode`.
    pub fn flags(interest: Interest, mode: PollMode) -> u32 {
        let mut flags = Linux::EPOLLRDHUP;
        if interest.readable {
            flags |= Linux::EPOLLIN;
        }
        if interest.writable {
            flags |= Linux::EPOLLOUT;
        }
        flags
            | match mode {
                PollMode::Level => 0,
                PollMode::Edge => Linux::EPOLLET,
                PollMode::Oneshot => Linux::EPOLLONESHOT,
            }
    }

    pub fn control(&self, operation: i32, descriptor: RawFd, token: usize, flags: u32) -> io::Result<()> {
        let mut event = EpollEvent { events: flags, data: token as u64 };
        // SAFETY: the event lives during the call; the result is checked.
        Socket::check(unsafe { sys::epoll_ctl(self.epoll.as_raw_fd(), operation, descriptor, &mut event) }).map(|_| ())
    }

    /// Watches `descriptor` for `interest`, reported with `token` (not [`PollEvent::NOTIFY`]).
    pub fn add(&self, descriptor: RawFd, token: usize, interest: Interest, mode: PollMode) -> io::Result<()> {
        Poller::check_token(token)?;
        self.control(Linux::EPOLL_CTL_ADD, descriptor, token, Poller::flags(interest, mode))
    }

    /// Changes what `descriptor` is watched for (and re-arms a oneshot one).
    pub fn modify(&self, descriptor: RawFd, token: usize, interest: Interest, mode: PollMode) -> io::Result<()> {
        Poller::check_token(token)?;
        self.control(Linux::EPOLL_CTL_MOD, descriptor, token, Poller::flags(interest, mode))
    }

    /// Stops watching `descriptor`.
    pub fn delete(&self, descriptor: RawFd) -> io::Result<()> {
        self.control(Linux::EPOLL_CTL_DEL, descriptor, 0, 0)
    }

    pub fn check_token(token: usize) -> io::Result<()> {
        if token == PollEvent::NOTIFY { Err(io::Error::from(io::ErrorKind::InvalidInput)) } else { Ok(()) }
    }

    /// The milliseconds of `timeout` for `epoll_wait`, rounded up (-1 for none).
    pub fn milliseconds(timeout: Option<Duration>) -> i32 {
        timeout.map_or(-1, |timeout| {
            let milliseconds = timeout.as_nanos().div_ceil(1_000_000);
            i32::try_from(milliseconds).unwrap_or(i32::MAX)
        })
    }

    /// Waits at most `timeout` (forever if `None`) for events, and replaces
    /// the contents of `events` with them (at most [`Poller::MAXIMUM_EVENTS`]);
    /// a notification is one event of token [`PollEvent::NOTIFY`]. An
    /// interrupted wait returns no events.
    pub fn wait(&self, events: &mut Vec<PollEvent>, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();
        let mut raw = [EpollEvent::default(); Poller::MAXIMUM_EVENTS];
        // SAFETY: the array is writable for the count given; the result is checked.
        let result = unsafe {
            sys::epoll_wait(self.epoll.as_raw_fd(), raw.as_mut_ptr(), raw.len() as i32, Poller::milliseconds(timeout))
        };
        let count = match Socket::check(result) {
            Ok(count) => count as usize,
            Err(error) if error.raw_os_error() == Some(Linux::EINTR) => 0,
            Err(error) => return Err(error),
        };
        for event in &raw[..count] {
            let (flags, token) = (event.events, event.data as usize);
            if token == PollEvent::NOTIFY {
                self.notifier.drain()?;
                events.push(PollEvent { token, readable: true, ..PollEvent::default() });
                continue;
            }
            let hangup = flags & (Linux::EPOLLHUP | Linux::EPOLLRDHUP) != 0;
            let error = flags & Linux::EPOLLERR != 0;
            events.push(PollEvent {
                token,
                readable: flags & Linux::EPOLLIN != 0 || hangup || error,
                writable: flags & Linux::EPOLLOUT != 0 || error,
                hangup,
                error,
            });
        }
        Ok(count)
    }

    /// Ends the current wait, or the next one, from any thread.
    pub fn notify(&self) -> io::Result<()> {
        self.notifier.notify()
    }
}
