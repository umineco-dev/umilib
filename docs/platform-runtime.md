# The runtime of the platform: `umilib::platform::runtime`

`platform-runtime` runs the futures of [`umilib::runtime`](runtime.md) on
an operating system, on Linux, Android, Darwin and Windows:

- `ThreadPool`, a work-stealing pool of threads;
- `Reactor`, a thread that waits on the system's I/O and timers;
- the asynchronous sockets `TCPListener`, `TCPStream` and `UDPSocket`;
- `Runtime`, a pool and a reactor together;
- `Supervisor` and `Worker`, which run a program in several processes
  that share listening sockets.

```rust
use umilib::platform::runtime::{ListenerConfig, Runtime, RuntimeConfig, TCPListener};
use umilib::runtime::{AsyncRead, AsyncWrite, Executor, SocketAddress};

let runtime = Runtime::new(&RuntimeConfig::default())?;
let address = SocketAddress::V4 { address: [127, 0, 0, 1], port: 8080 };
let listener = TCPListener::bind(runtime.reactor(), address, &ListenerConfig::default())?;
let spawner = runtime.spawner();
runtime.block_on(async move {
    while let Ok((mut stream, _peer)) = listener.accept().await {
        spawner.spawn(async move {
            let (result, buffer) = stream.read(Vec::with_capacity(4096)).await;
            if result.is_ok() {
                let _ = stream.write_all(buffer).await;     // echo what came
            }
        });
    }
});
```

## Thread pool

`ThreadPool::new(&ThreadPoolConfig { threads, name, stack_size })` starts
`threads` threads (0: as many as the system's parallelism), named `name`
followed by their index. It implements `runtime::Executor`: `spawn(future)`
gives a `JoinHandle`. A task spawned on a pool's thread goes to that
thread's queue. Other tasks go to a shared queue, and an idle thread takes
work from the shared queue or from the other threads' queues.

- `block_on(future)` runs `future` on the calling thread, which sleeps
  while the future is not ready. `ThreadPool::block_on_thread` does the
  same without a pool.
- `spawner()` gives a `PoolSpawner`, which tasks keep in order to spawn
  more. It does not keep the pool alive.
- A task that panics is dropped (its handle gives `TaskError::Cancelled`);
  the pool goes on.
- `shutdown()` (or dropping the pool) stops the threads after the polls
  they are making and drops every unfinished task. A task spawned after
  that, or woken after it, is dropped at once.

## Reactor and timers

`Reactor::new(&ReactorConfig { name, stack_size })` starts a thread that
waits on the system's I/O:

- an edge-triggered `epoll` (Linux, Android) or `kqueue` (Darwin) poller;
- an I/O completion port (Windows).

The same thread fires the timers of its `Timer` (`reactor.timer()`).
Timers count on the `MonotonicClock`, the system's monotonic clock. Use
`timer.sleep(duration)`, `timer.sleep_until(instant)` and
`timer.timeout(duration, future)`; a new timer wakes the reactor so that
it never sleeps past it. A `Reactor` is a handle: clones share the thread.
Timers (and their sleeps), sockets and pending operations each hold one,
so the thread stops once the last of them is gone.

## Sockets

The sockets implement the owned-buffer traits of `umilib::runtime`:

- `TCPStream` implements `AsyncRead` (into the spare capacity of the
  buffer given, which must have some) and `AsyncWrite`. Its `shutdown`
  ends the sending side.
- `UDPSocket` implements `AsyncDatagram`.

The futures are `Send`, so they run on a `ThreadPool`. Several tasks may
wait on one socket (for example, tasks accepting on one `Arc<TCPListener>`):
a readiness wakes them all, and those that find nothing to do wait again.

- `TCPListener::bind(&reactor, address, &config)` listens with the
  parameters of `ListenerConfig`:
  - `backlog` (1024);
  - `reuse_address` (`SO_REUSEADDR`; true on Unix; on Windows false, with
    `SO_EXCLUSIVEADDRUSE` instead);
  - `reuse_port` (Unix only);
  - `only_v6`.

  `ListenerConfig::bind(address)` makes such a socket without a reactor,
  for example to give a `Supervisor`. `accept()` gives the stream and the
  peer's address.
- `TCPStream::connect(&reactor, address)` connects; a refused connection
  fails with `IOErrorKind::ConnectionRefused`.
- `UDPSocket::bind(&reactor, address)`.
- `from_socket(&reactor, socket)` adopts a `platform::native::Socket`
  (listening, connected or datagram).

On Unix the sockets are nonblocking and registered with the poller; an
operation that would block waits for the next readiness. On Windows each
operation is an overlapped call (`AcceptEx`, `ConnectEx`, `WSARecv`,
`WSASend`, `WSARecvFrom`, `WSASendTo`) that owns its buffer until the
system completes it. A future dropped before then cancels the operation
(`CancelIoEx`); the buffer is freed when the completion arrives.

This changes what dropping a future means (for example, at the end of a
`timer.timeout`):

- On Unix, a dropped `read`, `receive_from` or `accept` has taken
  nothing; the next one gets the data or the connection.
- On Windows, the system may already have completed the operation before
  the cancellation. The bytes it read, or the connection it accepted, are
  then lost with the future.

So on Windows, do not drop a read of a stream you go on using; stop
reading with `shutdown` or by closing the stream instead.

UDP behaves the same on both. An ICMP "port unreachable" for an earlier
datagram does not fail a receive (`SIO_UDP_CONNRESET` is turned off on
Windows). A datagram longer than the buffer is cut to the buffer's room.

## Worker processes

A `Supervisor` runs the workers of a program and shares listening sockets
with them:

```rust
use umilib::platform::runtime::{ListenerConfig, Supervisor, SupervisorConfig, Worker};
use umilib::runtime::SocketAddress;

if let Some(mut worker) = Worker::current()? {
    // A worker: serve on the shared listeners until the supervisor asks to stop.
    let mut listeners = worker.take_listeners();
    Worker::watch(|| { /* stop accepting, finish, exit */ })?;
    // ... TCPListener::from_socket(runtime.reactor(), listeners.remove(0)) ...
} else {
    // The supervisor: the same program, started again as 4 workers.
    let address = SocketAddress::V4 { address: [0, 0, 0, 0], port: 8080 };
    let listener = ListenerConfig::default().bind(address)?;
    let mut supervisor = Supervisor::new(SupervisorConfig { workers: 4, ..SupervisorConfig::default() }, vec![listener]);
    supervisor.run(|| false)?;      // until every worker is done; pass a stop condition
}
```

- `SupervisorConfig` holds:
  - `workers` (0: the system's parallelism);
  - `program` (`None`: this executable);
  - `arguments` (by default, this process's);
  - `environment` (extra variables);
  - `restart` (`RestartPolicy::Never`, `OnFailure`, the default, or `Always`);
  - `restart_delay` (1 s), `stop_timeout` (10 s) and `check_interval` (100 ms).
- `start()` starts the workers.
- `check()` records the workers that exited, starts again those the policy
  says to (once `restart_delay` has passed since the exit), and returns how
  many are running.
- `stop()` asks every worker to stop, waits up to `stop_timeout` and kills
  those still running.
- `run(stop)` does all three: it checks every `check_interval` until
  `stop()` returns true, or until no worker runs and none is to be started
  again. Dropping a supervisor stops its workers.
- `workers()` describes each `WorkerProcess`: its index, its process ID
  while it runs, its last exit status and how many times it was restarted.

A worker is started with the environment variable `UMILIB_WORKER`
(`Worker::ENVIRONMENT`) set to its index. On its standard input it
receives a `WorkerHandshake` naming the listening sockets:

- on Unix, the descriptors, which the worker inherits across `exec`;
- on Windows, sockets duplicated for its process with
  `WSADuplicateSocketW`.

On Unix a listener may not be descriptor 0, 1 or 2: the worker's
standard streams replace them. That can only happen in a supervisor
started without them, and `start` then fails with `InvalidInput`. The
workers share the listener's open file description, so it is nonblocking
in every one of them.

`Worker::current()` reads the handshake. Call it once, before anything
else reads standard input. It returns `None` in a process the supervisor
did not start.

The supervisor asks a worker to stop by closing the worker's standard
input. That also happens if the supervisor exits or crashes, so workers
never outlive it. `Worker::watch(stop)` calls `stop` on a thread of its
own when that happens. The supervisor handles no signals itself: pass
`run` a condition your signal handling sets.

Several worker processes accept from the same listening socket, and the
system gives each connection to one of them.

The handshake is binary, in little-endian:
1. the magic `UMWH`;
2. the version (u32, 1);
3. the number of listeners (u32);
4. for each listener, the length of its bytes (u32) and the bytes.

The bytes are a descriptor (i32) on Unix and a `WSAPROTOCOL_INFOW` on
Windows. A worker rejects another magic or version, more than 1024
listeners, bytes longer than 4096, and a listener given twice. On Unix it
also rejects a descriptor that is not a socket.

## C and Python

The C ABI (`include/umilib/platform/runtime.h`) and the Python package
`umilib.platform.runtime` provide:

- `ThreadPool`, which runs the callback tasks of the runtime's C ABI. A
  task's context must be usable from any of the pool's threads, one at a
  time.
- `PoolSpawner`, for tasks to spawn more.
- `block_on_thread`, which waits for a task from any thread.
- `MonotonicClock`.
- `Reactor`: `now`, `wake_at(deadline, waker)`, which wakes a task at a
  deadline and gives the key of the timer, and `remove(key)`, for a task
  that stops waiting.

The sockets and the supervisor are Rust only for now. On a system without
the platform runtime, the C functions fail with `Unsupported`.

In Python, each call on a handle locks it, which leads to three rules:

- A task spawns more through `pool.spawner()`, never through the pool.
  `shutdown` holds the pool while it waits for the pool's threads, so a
  task using the pool itself could wait forever.
- A task waited for with `block_on(handle)` cannot meanwhile be aborted
  through the same handle from another thread.
- The waker a poll function is given belongs to the pool: closing it
  only gives it up. `waker.clone()` makes one to keep.

`ThreadPool.block_on(handle)` raises the first exception a poll or drop
function of the pool raised. Pools still alive when the interpreter exits
are stopped first.
