//! The runtime of the platform: a work-stealing [`ThreadPool`] that runs
//! the tasks of `umilib::runtime`, the [`Reactor`] that drives the system's
//! poller (or completion port) and the timers on a thread of its own, the
//! asynchronous sockets of the reactor ([`TCPListener`], [`TCPStream`],
//! [`UDPSocket`]), the system's [`MonotonicClock`], the [`Runtime`] that
//! bundles them, and the [`Supervisor`] of worker processes.

mod clock;
mod conversion;
mod listener_config;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod net_unix;
#[cfg(windows)]
mod net_windows;
#[cfg(windows)]
mod operation;
mod park;
mod pool;
mod reactor;
#[allow(clippy::module_inception)]
mod runtime;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod source;
mod supervisor;
mod worker;

pub use clock::MonotonicClock;
pub use conversion::Conversion;
pub use listener_config::ListenerConfig;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub use net_unix::{TCPListener, TCPStream, UDPSocket};
#[cfg(windows)]
pub use net_windows::{TCPListener, TCPStream, UDPSocket};
#[cfg(windows)]
pub use operation::{Operation, PendingOperation};
pub use park::ThreadPark;
pub use pool::{ParkWaker, PoolShared, PoolSpawner, PoolTask, ThreadPool, ThreadPoolConfig};
pub use reactor::{Reactor, ReactorConfig, ReactorDriver, ReactorOwner, ReactorShared, ReactorWaker};
pub use runtime::{Runtime, RuntimeConfig};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
pub use source::{Direction, IOSource, Readiness, Registration, SourceTable};
pub use supervisor::{RestartPolicy, Supervisor, SupervisorConfig, WorkerProcess};
pub use worker::{Worker, WorkerHandshake};
