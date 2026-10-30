use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use super::{PoolShared, Reactor};
use crate::platform::native::{Interest, PollEvent, PollMode};

/// The two directions of a source's readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Read = 0,
    Write = 1,
}

/// The readiness of a source in one direction: a count of the events that
/// reported it (so that an event between a failed attempt and the
/// registration of its waker is not lost) and the wakers of the tasks
/// waiting (several tasks may wait on one socket, as on a shared listener).
#[derive(Debug, Default)]
pub struct Readiness {
    ticks: AtomicUsize,
    wakers: Mutex<Vec<Waker>>,
}

impl Readiness {
    /// Adds `waker` to the wakers waiting, unless it is there.
    pub fn register(&self, waker: &Waker) {
        let mut wakers = PoolShared::lock(&self.wakers);
        if !wakers.iter().any(|waiting| waiting.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    /// Counts an event and wakes every task waiting (after releasing the list:
    /// a woken task may run at once).
    pub fn wake(&self) {
        self.ticks.fetch_add(1, Ordering::AcqRel);
        let wakers = core::mem::take(&mut *PoolShared::lock(&self.wakers));
        wakers.into_iter().for_each(Waker::wake);
    }
}

/// A descriptor registered with a reactor's poller (edge-triggered, for
/// reading and writing).
#[derive(Debug)]
pub struct IOSource {
    token: usize,
    descriptor: RawFd,
    readiness: [Readiness; 2],
}

impl IOSource {
    pub fn token(&self) -> usize {
        self.token
    }

    /// Records the readiness of `event` and wakes the tasks waiting for it.
    pub fn dispatch(&self, event: &PollEvent) {
        for (direction, ready) in [(Direction::Read, event.readable), (Direction::Write, event.writable)] {
            if ready {
                self.readiness[direction as usize].wake();
            }
        }
    }

    /// Runs `operation` until it does not block: `Pending` (the task woken
    /// when the source is ready in `direction`) if it would.
    pub fn poll_io<T>(
        &self,
        direction: Direction,
        context: &mut Context<'_>,
        mut operation: impl FnMut() -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let readiness = &self.readiness[direction as usize];
        loop {
            let ticks = readiness.ticks.load(Ordering::Acquire);
            match operation() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    readiness.register(context.waker());
                    // An event since the attempt: it may be ready again.
                    if readiness.ticks.load(Ordering::Acquire) != ticks {
                        continue;
                    }
                    return Poll::Pending;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return Poll::Ready(result),
            }
        }
    }
}

/// The sources of a reactor by token.
#[derive(Debug, Default)]
pub struct SourceTable {
    sources: Vec<Option<Arc<IOSource>>>,
    free: Vec<usize>,
}

impl SourceTable {
    pub fn new() -> SourceTable {
        SourceTable::default()
    }

    pub fn get(&self, token: usize) -> Option<Arc<IOSource>> {
        self.sources.get(token).cloned().flatten()
    }

    /// Adds a source of `descriptor`: its token is a free slot.
    pub fn insert(&mut self, descriptor: RawFd) -> Arc<IOSource> {
        let token = self.free.pop().unwrap_or(self.sources.len());
        let source = Arc::new(IOSource { token, descriptor, readiness: Default::default() });
        if token == self.sources.len() {
            self.sources.push(Some(source.clone()));
        } else {
            self.sources[token] = Some(source.clone());
        }
        source
    }

    pub fn remove(&mut self, token: usize) {
        if let Some(slot) = self.sources.get_mut(token)
            && slot.take().is_some()
        {
            self.free.push(token);
        }
    }

    pub fn len(&self) -> usize {
        self.sources.len() - self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The registration of a descriptor with a reactor: it is removed from the
/// poller when dropped (before the descriptor is closed).
#[derive(Debug)]
pub struct Registration {
    reactor: Reactor,
    source: Arc<IOSource>,
}

impl Registration {
    /// Registers the nonblocking `descriptor` with `reactor`.
    pub fn new(reactor: &Reactor, descriptor: &impl AsRawFd) -> io::Result<Registration> {
        let raw = descriptor.as_raw_fd();
        let shared = reactor.shared();
        let source = PoolShared::lock(&shared.sources).insert(raw);
        if let Err(error) = shared.driver.add(raw, source.token, Interest::BOTH, PollMode::Edge) {
            PoolShared::lock(&shared.sources).remove(source.token);
            return Err(error);
        }
        Ok(Registration { reactor: reactor.clone(), source })
    }

    pub fn source(&self) -> &IOSource {
        &self.source
    }

    pub fn reactor(&self) -> &Reactor {
        &self.reactor
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let shared = self.reactor.shared();
        let _ = shared.driver.delete(self.source.descriptor);
        PoolShared::lock(&shared.sources).remove(self.source.token);
    }
}
