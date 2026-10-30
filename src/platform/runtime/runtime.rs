use std::io;

use super::{PoolSpawner, Reactor, ReactorConfig, ThreadPool, ThreadPoolConfig};
use crate::runtime::{BoxFuture, Executor};

/// The parameters of a [`Runtime`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub pool: ThreadPoolConfig,
    pub reactor: ReactorConfig,
}

/// A [`ThreadPool`] that runs the tasks and a [`Reactor`] that drives their
/// sockets and timers. Dropping it stops the pool first (dropping the tasks
/// left, and their sockets), then the reactor.
pub struct Runtime {
    pool: ThreadPool,
    reactor: Reactor,
}

impl Runtime {
    /// A runtime of the parameters `config`, its threads started.
    pub fn new(config: &RuntimeConfig) -> io::Result<Runtime> {
        let reactor = Reactor::new(&config.reactor)?;
        let pool = ThreadPool::new(&config.pool)?;
        Ok(Runtime { pool, reactor })
    }

    pub fn pool(&self) -> &ThreadPool {
        &self.pool
    }

    /// The reactor, for the sockets ([`super::TCPListener::bind`]) and the
    /// timer ([`Reactor::timer`]) of the tasks.
    pub fn reactor(&self) -> &Reactor {
        &self.reactor
    }

    /// A handle to spawn tasks with (tasks hold one to spawn more).
    pub fn spawner(&self) -> PoolSpawner {
        self.pool.spawner()
    }

    /// Runs `future` to completion on the calling thread, while the pool runs the tasks.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.pool.block_on(future)
    }
}

impl Executor for Runtime {
    fn spawn_boxed(&self, future: BoxFuture) {
        self.pool.spawn_boxed(future);
    }
}

impl core::fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Runtime").field("threads", &self.pool.threads()).finish_non_exhaustive()
    }
}
