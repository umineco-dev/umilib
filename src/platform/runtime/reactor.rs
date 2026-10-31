use std::io;
use std::string::String;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::vec::Vec;

use super::{MonotonicClock, PoolShared};
use crate::runtime::{Park, Timer};

/// The parameters of a [`Reactor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactorConfig {
    /// The name of the reactor's thread.
    pub name: String,
    /// The stack size of the thread, if not std's default.
    pub stack_size: Option<usize>,
    /// The most events (Unix) or completions (Windows) one wait of the
    /// thread takes from the system; more wait for the next round.
    pub maximum_events: usize,
    /// The pause before the thread waits again after a wait failed (out of
    /// resources), so that it does not spin.
    pub retry_delay: Duration,
}

impl Default for ReactorConfig {
    fn default() -> ReactorConfig {
        ReactorConfig {
            name: String::from("umilib-reactor"),
            stack_size: None,
            maximum_events: 256,
            retry_delay: Duration::from_millis(10),
        }
    }
}

/// The waiting of the system a reactor drives: a readiness poller on Unix,
/// a completion port on Windows.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub type ReactorDriver = crate::platform::native::Poller;
#[cfg(windows)]
pub type ReactorDriver = crate::platform::native::CompletionPort;

/// What a reactor's thread and handles share: the system's driver, the
/// sources registered with it, the timer, and whether to stop.
pub struct ReactorShared {
    pub driver: ReactorDriver,
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    pub sources: Mutex<super::SourceTable>,
    pub timer: Timer,
    retry_delay: Duration,
    stopping: AtomicBool,
}

impl ReactorShared {
    /// One round of the reactor's loop: waits for the system's events (at
    /// most until the next timer) and dispatches them, then fires the timers.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    pub fn turn(&self, events: &mut Vec<crate::platform::native::PollEvent>) -> io::Result<()> {
        let timeout = self.timer.fire().map(|deadline| deadline - self.timer.now());
        self.driver.wait(events, timeout)?;
        for event in events.iter() {
            if event.token == crate::platform::native::PollEvent::NOTIFY {
                continue;
            }
            let source = PoolShared::lock(&self.sources).get(event.token);
            if let Some(source) = source {
                source.dispatch(event);
            }
        }
        self.timer.fire();
        Ok(())
    }

    /// One round of the reactor's loop on Windows: completions instead of readiness.
    #[cfg(windows)]
    pub fn turn(&self, completions: &mut Vec<crate::platform::native::Completion>) -> io::Result<()> {
        let timeout = self.timer.fire().map(|deadline| deadline - self.timer.now());
        self.driver.wait(completions, timeout)?;
        for completion in completions.iter() {
            if completion.overlapped != 0 {
                // SAFETY: every OVERLAPPED given to the system is the head of an
                // `Operation` whose ownership was passed with `Operation::start`.
                unsafe { super::Operation::complete(completion.overlapped) };
            }
        }
        self.timer.fire();
        Ok(())
    }

    /// The loop of the reactor's thread, until the reactor stops.
    pub fn run(self: Arc<ReactorShared>) {
        let mut events = Vec::new();
        while !self.stopping.load(Ordering::Acquire) {
            if self.turn(&mut events).is_err() {
                // A failing wait (out of resources) is retried after a pause rather than spinning.
                std::thread::sleep(self.retry_delay);
            }
        }
    }

    pub fn notify(&self) {
        let _ = self.driver.notify();
    }
}

/// The [`Park`] of the timers a [`Reactor`] gives ([`Reactor::timer`]): a
/// new timer ends the reactor's wait, so that it waits no longer than the
/// new deadline. It holds the reactor, so that the reactor's thread runs
/// while timers (and the sleeps made of them) exist.
pub struct ReactorWaker {
    owner: Arc<ReactorOwner>,
}

impl Park for ReactorWaker {
    fn park(&self, _timeout: Option<Duration>) {}

    fn unpark(&self) {
        self.owner.shared.notify();
    }
}

/// The owner of a reactor's thread: dropping the last [`Reactor`] (and the
/// last timer, socket and operation, which hold one) stops it.
pub struct ReactorOwner {
    shared: Arc<ReactorShared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for ReactorOwner {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.notify();
        if let Some(thread) = PoolShared::lock(&self.thread).take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// The reactor: a thread that waits on the system's poller (Unix) or
/// completion port (Windows) and on the timers of its [`Timer`] (on the
/// [`MonotonicClock`]), wakes the tasks waiting on sockets and timers, and
/// sleeps otherwise. Its handles may be cloned and shared; the thread stops
/// when the last one (and the last timer, socket and operation of the
/// reactor, which hold one) is dropped.
#[derive(Clone)]
pub struct Reactor {
    owner: Arc<ReactorOwner>,
}

impl Reactor {
    /// A reactor of the parameters `config`, its thread started.
    pub fn new(config: &ReactorConfig) -> io::Result<Reactor> {
        let driver = Reactor::driver(config)?;
        let shared = Arc::new(ReactorShared {
            driver,
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
            sources: Mutex::new(super::SourceTable::new()),
            timer: Timer::new(Arc::new(MonotonicClock::new())),
            retry_delay: config.retry_delay,
            stopping: AtomicBool::new(false),
        });
        let mut builder = std::thread::Builder::new().name(config.name.clone());
        if let Some(size) = config.stack_size {
            builder = builder.stack_size(size);
        }
        let runner = shared.clone();
        let thread = builder.spawn(move || runner.run())?;
        Ok(Reactor { owner: Arc::new(ReactorOwner { shared, thread: Mutex::new(Some(thread)) }) })
    }

    /// A new driver of the system for `config`: a poller.
    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
    pub fn driver(config: &ReactorConfig) -> io::Result<ReactorDriver> {
        ReactorDriver::with_maximum_events(config.maximum_events)
    }

    /// A new driver of the system for `config`: a completion port (as many
    /// concurrent threads as processors).
    #[cfg(windows)]
    pub fn driver(config: &ReactorConfig) -> io::Result<ReactorDriver> {
        ReactorDriver::with_maximum_completions(0, config.maximum_events)
    }

    pub fn shared(&self) -> &Arc<ReactorShared> {
        &self.owner.shared
    }

    /// Registers `socket` with the reactor: its overlapped operations
    /// ([`super::Operation`]) complete on the reactor's thread, by the route
    /// returned. A socket made from another process's socket
    /// ([`crate::platform::native::Socket::is_duplicate`]) is never associated
    /// with the completion port, which its underlying socket may already be
    /// (in that process); its operations signal events instead
    /// ([`super::CompletionRoute::Event`]).
    #[cfg(windows)]
    pub fn register(&self, socket: &crate::platform::native::Socket) -> io::Result<super::CompletionRoute> {
        if socket.is_duplicate() {
            return Ok(super::CompletionRoute::Event);
        }
        self.owner.shared.driver.associate(socket.raw() as std::os::windows::io::RawHandle, 0)?;
        Ok(super::CompletionRoute::Port)
    }

    /// The timer of the reactor ([`Timer::sleep`], [`Timer::timeout`]): its
    /// clones and sleeps keep the reactor's thread running.
    pub fn timer(&self) -> Timer {
        self.owner.shared.timer.driven_by(Arc::new(ReactorWaker { owner: self.owner.clone() }))
    }
}

impl core::fmt::Debug for Reactor {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Reactor")
    }
}
