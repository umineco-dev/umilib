//! The asynchronous runtime, without `std`: tasks and executors
//! ([`Executor`], [`LocalExecutor`], [`JoinHandle`]), waiting when idle
//! ([`Park`]), channels ([`Channel`]), timers ([`Timer`], [`TimerQueue`],
//! [`Clock`]), I/O traits on owned buffers ([`AsyncRead`], [`AsyncWrite`],
//! [`AsyncDatagram`], [`DuplexStream`]), future combinators and the spin
//! lock the rest is built on. The platform runtime (`platform-runtime`)
//! adds threads, the operating system's reactor and clocks.

mod channel;
mod executor;
mod future;
mod io;
mod park;
mod registry;
mod sync;
mod task;
mod time;

pub use channel::{
    Channel, ChannelError, ChannelState, OneshotReceiver, OneshotSender, OneshotState, ReceiveFuture, Receiver,
    SendError, SendFuture, Sender,
};
pub use executor::{BlockOnWaker, BoxFuture, Executor, LocalExecutor, LocalQueue, LocalTask};
pub use future::{Either, Join, JoinAll, Select, YieldNow};
pub use io::{AsyncDatagram, AsyncRead, AsyncWrite, DuplexPipe, DuplexStream, IOError, IOErrorKind, SocketAddress};
pub use park::{Park, SpinPark};
pub use registry::TaskRegistry;
pub use sync::{AtomicWaker, SpinLock, SpinLockGuard};
pub use task::{JoinHandle, TaskError, TaskFuture, TaskState};
pub use time::{Clock, Elapsed, Instant, Sleep, Timeout, Timer, TimerKey, TimerPark, TimerQueue};
