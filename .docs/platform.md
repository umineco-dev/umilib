# Operating system layers

How the modules of `umilib::platform` that call the operating system are
built and tested. The user-facing description is in
[docs/platform.md](../docs/platform.md).

## Declarations

Each system has a `sys` module: `extern` declarations of the C functions
used (from the C library std links: glibc, musl or bionic, libSystem,
`ws2_32` and `kernel32`; `ProcessPrng` with `raw-dylib`, as std does) and a
struct of constants. The constants and structure layouts were taken from:

- Linux: the kernel and glibc headers of Debian bookworm
  (`asm-generic/socket.h`, `linux/in6.h`, `linux/eventpoll.h`,
  `bits/eventfd.h`, `bits/socket_type.h`, `linux/if_packet.h`).
  `struct epoll_event` is packed on x86-64 only.
- Darwin: the macOS SDK (`sys/socket.h`, `netinet/in.h`, `netinet6/in6.h`,
  `sys/event.h`, `sys/random.h`); `sockaddr` structures start with a length byte.
- Windows: the mingw-w64 headers (as Zig ships them): `winsock2.h`,
  `ws2def.h`, `ws2ipdef.h`, `minwinbase.h`. `FIONBIO` is
  `_IOW('f', 126, u_long)` = 0x8004667E; `WSAPROTOCOL_INFOW` is 628 bytes.

On Linux the constants are those of the kernel's generic headers
(`asm-generic/socket.h`, `asm-generic/fcntl.h`, `asm-generic/errno.h`, and
`SOCK_STREAM` 1, `SOCK_DGRAM` 2 of `linux/net.h`). Most architectures use
them: x86, x86-64, ARM, AArch64, RISC-V, LoongArch64 and s390x have no
header of their own for them, and PowerPC's `asm/socket.h` and
`asm/fcntl.h` change only options umilib does not use (`SO_RCVLOWAT` to
`SO_PEERCRED`, `O_DIRECTORY` to `O_DIRECT`) before including the generic
ones (checked against the kernel's sources). MIPS has its own
(`SOCK_DGRAM` 1, `SOCK_STREAM` 2, `SOL_SOCKET` 0xFFFF, BSD-style `SO_*`
numbers, `O_NONBLOCK` 0x80, `ENOSYS` 89), and so do SPARC (`SOL_SOCKET`
0xFFFF, `O_NONBLOCK` 0x4000, `O_CLOEXEC` 0x400000), Alpha and PA-RISC.
`unix::sys` and `linux::sys` refuse to compile (`compile_error!`) on any
architecture outside the verified list. Per-architecture values for MIPS
and SPARC were rejected for now: no such target can be run here or in CI
(Rust's MIPS targets are tier 3, without std builds), and values never run
are the kind of mistake that corrupts system calls silently. Adding one
means taking every constant of both modules from its headers and running
the platform tests on it. `TUNSETIFF` still names the MIPS and SPARC
number for that day.

Darwin's `struct timespec` is `{ long tv_sec; long tv_nsec; }`
(`__darwin_time_t` is `long`), so `TimeSpec` uses `c_long`: 32 bits on
arm64_32 and armv7k (watchOS) and i686. Fixed `i64` fields made the kernel
read a different layout there.

`SocketDuplicate` (`WSAPROTOCOL_INFOW`, 628 bytes) is aligned to 4, the
alignment of the C structure (its widest fields are `DWORD` and `int`),
because Winsock reads and writes it in place through a typed pointer. As
a plain byte array it had alignment 1.

`getrandom` is called through `syscall` with the number of each
architecture (the system call ABI is stable; the C library's `getrandom`
needs glibc 2.25 or Android API 28). The test
`the_getrandom_system_call_is_known` checks the number by calling it.

## Choices

- Every socket is created close-on-exec (Linux `SOCK_CLOEXEC`, Darwin
  `FD_CLOEXEC` after creation, Windows `WSA_FLAG_NO_HANDLE_INHERIT`).
  Darwin sockets set `SO_NOSIGPIPE`; Linux sends pass `MSG_NOSIGNAL`.
- `accept(nonblocking)` sets the mode explicitly: Darwin and Windows make an
  accepted socket inherit the listener's, Linux does not.
- A poller's notification is a readable event of token
  `PollEvent::NOTIFY` on both pollers (an `eventfd` drained on Linux, an
  `EVFILT_USER` event with `EV_CLEAR` on Darwin).
- The OS modules export no C functions: the C ABI must be the same on every
  system (one set of headers), so only `native` exports functions, and they
  exist everywhere.
- Windows has no readiness poller without undocumented interfaces (AFD), so
  its layer is completion-based (IOCP); the runtime above it uses the owned
  buffers of `runtime::AsyncRead` so that both models fit.

## Testing

macOS runs the Darwin and Unix tests natively. Linux runs in Docker
(Docker Desktop's CLI is `/Applications/Docker.app/Contents/Resources/bin/docker`
on macOS), with a target directory of its own:

```
docker run --rm -v "$PWD":/work -w /work -e CARGO_TARGET_DIR=/work/target/docker-linux \
    rust:1-bookworm cargo test --features "platform crypto-random" --test platform
```

`--platform linux/amd64`, `linux/386` and `linux/arm/v7` run the same tests
under emulation (the layouts and system call numbers differ there). The
packet socket test needs `CAP_NET_RAW`, which a container's root has; without
it the test checks the refusal. The TUN test needs `--cap-add NET_ADMIN
--device /dev/net/tun`. Without them it checks the refusal
(`PermissionDenied`, or `NotFound` when the container has no
`/dev/net/tun`).

`TUNDevice` calls `ioctl(TUNSETIFF)` with a `struct ifreq`
(`InterfaceRequest`) of 40 bytes, the size on 64-bit systems. The kernel
reads `sizeof(struct ifreq)`, which is 32 bytes on 32-bit systems, so one
size serves both. `ioctl` is declared per C library: glibc takes the request
as `unsigned long`, musl and bionic as `int`. Calling one declaration
through the other's type would rely on how each ABI passes the argument.
`TUNSETIFF` is `_IOW('T', 202, int)`, which differs on PowerPC, MIPS and
SPARC. A wrapper around `ip tuntap` was rejected: it needs the `ip` tool
and gives no descriptor. Windows and Android are compile-checked
(`cargo check --target x86_64-pc-windows-msvc`, `aarch64-linux-android`);
they run in CI.

## Runtime (`platform-runtime`)

The user-facing description is in
[docs/platform-runtime.md](../docs/platform-runtime.md).

### Thread pool

- Each worker thread has a local queue; a thread-local
  (`PoolShared::worker()`, the pool's address and the thread's index)
  tells `push` whether the caller is a worker of this pool. A sleeping
  worker is recorded in `sleepers` and woken with `unpark`; `notified`
  keeps a wake that comes before the park.
- A worker is listed in `sleepers` at most once. `wake_one` may take a
  worker off the list in the moment between its listing and its check
  for work; the worker then sees the work and goes on, and its `notified`
  stays set. That stale flag used to make the next sleep skip its park
  and list the worker a second time, so two later wakes went to it,
  awake, and the workers really asleep stayed asleep with work queued
  (found by Miri, where the timing makes it common; natively it showed as
  a test seeing every task on one thread). The worker now clears
  `notified` just before listing itself: it is not listed then, so the
  flag can only be stale.
- `PoolTask::schedule` drops the future of a task whose pool is gone or
  stopping. Without the check, a task spawned after `shutdown` sat in a
  queue no thread ran, and `block_on` of its handle never returned.
  Tasks spawned while `shutdown` runs are caught by the registry drain,
  which takes every registered future.
- clippy reports `missing_const_for_thread_local` on Android even though
  the initializer is `const` (Android's thread-locals are emulated); the
  lint is allowed on `PoolShared::worker` for that reason.

### Reactor on Unix

Sources are registered once, edge-triggered for both directions. Each
direction counts the readiness events it received (`ticks`). `poll_io`
reads the count before the operation, and on `WouldBlock` registers the
waker. If the count changed meanwhile, an event came between the
operation and the registration, so it retries rather than waiting for an
event that already passed. The count is an `AtomicUsize` that wraps: only
a change matters, and some targets (riscv32gc) have no 64-bit atomics.

`epoll_wait` and `kevent` are never restarted after a signal handler
(signal(7)), so a wait may return `EINTR`; the pollers then report no
events and the reactor loops. Under qemu, the `SIGCHLD` of the
supervisor tests' children interrupts waits even without a handler. A
test that waits for events must therefore wait in a loop (as
`pollers_report_readiness_and_notifications` does).

### Reactor on Windows

`Reactor::register` associates a socket with the completion port (key 0),
except a socket made from another process's socket
(`Socket::from_duplicate`, `Socket::is_duplicate`). An `Operation` is
`#[repr(C)]` with its `OVERLAPPED` first, so the address the port reports
is the operation's.

A duplicated socket shares its underlying socket with the original, and a
socket can be associated with only one completion port: once one worker
of a `Supervisor` associated its listener, every other worker's
`CreateIoCompletionPort` failed with `ERROR_INVALID_PARAMETER` (87). Such
a socket takes `CompletionRoute::Event`:

- `Operation::start` gives the operation a manual-reset event in
  `OVERLAPPED.hEvent` with the low bit set. Windows then queues the
  completion to no port. Without it, the completion would go to the port
  the underlying socket is associated with, which may be another
  process's, and that process would take this process's `OVERLAPPED`
  address for one of its own operations.
- After the call is issued, `RegisterWaitForSingleObject`
  (`WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE`) waits for the event. Its
  callback posts the operation's address to the reactor's port, so the
  completion is taken back by `Operation::complete` on the reactor's
  thread, as on `CompletionRoute::Port`. If the post fails, the callback
  completes the operation itself, so the task still wakes.
- The wait is unregistered in `Operation`'s `Drop`, without blocking
  (`UnregisterWaitEx` with a null event), so it may even run in the
  callback. `Drop` comes after `start` stored the wait handle and after
  the completion, so the handle is never read before it is written.
- If the wait cannot be registered, `start` cancels the operation, waits
  for the event, and takes the reference back itself.
- The route is decided from `is_duplicate`, which is known, not from the
  error 87, which could have other causes. Even a worker that could have
  associated its listener first uses events, so every worker behaves the
  same, also after a restart.

Rejected: the supervisor accepting the connections and passing each to
a worker (the default of Node.js's cluster on Windows). Every accepted
socket is distinct, so the limit does not apply, but every connection
then passes through the supervisor, and the supervisor and the workers
would behave differently on Windows and Unix. Events keep the model of
Unix, where the workers share the listener and the system spreads the
connections, at the cost of one event and one thread-pool wait per
operation on a shared listener (an accept); the accepted sockets are
ordinary and use the port.

- `Operation::start` gives the system one reference (`Arc::into_raw`),
  which the reactor takes back (`Operation::complete`, `Arc::from_raw`)
  when the completion arrives. A call that fails without
  `WSA_IO_PENDING` gets no completion, so `start` takes the reference
  back itself.
- Sockets are not set to `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, so a
  call that succeeds at once still queues a completion. That keeps one
  path for every operation.
- A `PendingOperation` dropped early calls `CancelIoEx`; the operation
  stays alive until its (aborted) completion arrives.
- An `Operation` holds a `Reactor` clone, so the reactor's thread runs
  until the system has given back every operation.
- What the system writes while an operation runs lives in the
  `Operation`:
  - the `OVERLAPPED`, the address and the flags: cells exposed as raw
    pointers;
  - the buffer and the accepted socket: behind mutexes, taken back only
    once the operation is done (`take_buffer`, `take_accepted` return
    `None` before).
- The pointers given to Winsock are made inside the closure passed to
  `start`, never held across an `.await`, so the futures stay `Send`. An
  `async fn` taking that closure as an argument made every socket future
  non-`Send`: the arguments of an `async fn` are part of its future.
- `ConnectEx` is looked up with `WSAIoctl` for each socket, as Microsoft
  documents the pointer per provider, and needs a bound socket. After
  `AcceptEx` and `ConnectEx`, `SO_UPDATE_ACCEPT_CONTEXT` and
  `SO_UPDATE_CONNECT_CONTEXT` make `getpeername` and `shutdown` work.
- `RawSocketAddress` is aligned to 8 bytes, as `SOCKADDR_STORAGE` is, since
  the system writes it in place.

### Supervisor

- On Unix the listeners are close-on-exec. `Supervisor::inherit` clears
  the flag in the child, between `fork` and `exec` (`pre_exec`). It only
  calls `fcntl`, which is async-signal-safe, and allocates nothing.
- The worker:
  - checks that each descriptor is a socket before owning it, so a wrong
    number never closes a descriptor the worker does not own;
  - rejects a descriptor given twice, so none is closed twice;
  - makes the descriptors close-on-exec again.
- On Windows the supervisor duplicates each listener for the child's
  process ID after starting it, then writes the handshake.
- Stopping is the end of standard input: it needs no signal, works the
  same on every system, and also happens when the supervisor dies.
- The tests run the test binary itself as the worker (the test
  `runtime::supervisor::worker_entry`, which does nothing unless
  `UMILIB_WORKER` is set).

### C and Python

The C ABI is the same on every system: where there is no platform
runtime, `ThreadPool`, `PoolSpawner` and `Reactor` are uninhabited enums
and the functions fail with `Unsupported`.

`block_on_thread` takes no pool and `PoolSpawner` is a handle of its
own, because the Python `Handle` locks its object for the length of each
call. Had `block_on` (or a spawn from a task) gone through the pool,
`shutdown` or `free`, which wait for the pool's threads, would have
deadlocked with a task waiting for the pool's lock.

### Findings of the independent review

The review of this module found these problems; each has a test:

- **Timers woke their tasks while holding the queue's lock.** A wake that
  drops a task's future at once (its pool is stopping) dropped a `Sleep`
  of the same queue, which took the lock again and spun forever, and so
  did dropping the `Runtime`. `Timer::fire` now removes the expired
  timers under the lock (`TimerQueue::expire`) and wakes them after
  releasing it.
- **One waker per direction of a socket.** A second task waiting on the
  same socket replaced the first one's waker, so the first was never
  woken. `Readiness` now keeps a list.
- **Timers held the reactor weakly.** A sleep never finished once the
  last `Reactor` was dropped. `Reactor::timer` now gives a `Timer` whose
  driver (`ReactorWaker`) holds the reactor. There is no cycle: the
  reactor's own `Timer` has no driver.
- **A task that stopped its own pool was never dropped:** `shutdown`
  could not take the future being polled. `PoolShared::run` drops it
  after the poll if the pool is stopping.
- **Registry slots of tasks dropped while waiting were never freed.**
  `PoolTask` and `LocalTask` now leave the registry when dropped.
  `TaskRegistry::remove` checks the slot's identity, since a drained
  task can be dropped after its key was reused.
- **Python borrowed wakers.** A poll function's waker is a
  `BorrowedWaker`; closing it (or the garbage collector) only detaches
  it. A plain `Waker` would have released a pointer Rust never boxed.
- **Supervisor.** Every listener is adopted even if one fails, so no
  descriptor is left open unowned. `stop` kills every worker even if one
  kill fails. Listeners on descriptors 0 to 2 are refused.
- **Windows UDP.** `SIO_UDP_CONNRESET` is turned off, and `WSAEMSGSIZE`
  (a truncated datagram) gives the bytes that fit, as on Unix.
- **Limits fixed in the code.** The pollers' 256 events per wait, the
  completion port's 256 completions, the reactor's 10 ms pause after a
  failed wait and the fuzzer's sampling (1024 inputs, one in 64) were
  constants. They are now `ReactorConfig::maximum_events` and
  `retry_delay` (passed to `Poller::with_maximum_events` and
  `CompletionPort::with_maximum_completions`) and
  `FuzzConfig::maximum_corpus_inputs` and `sample_interval`, with the old
  values as defaults. The waits allocate their buffer of system events per
  call (`try_reserve_exact`, so a failure is an error), because a poller
  is shared by threads and may be waited on by several at once: a buffer
  kept in the poller would need a lock that serialized those waits.
- **Sizes and times from the caller.** `ThreadPool::new` built its
  per-thread vectors with `collect`, so a huge `threads` (reachable through
  `umilib_platform_runtime_thread_pool_new`) aborted the process; it now
  reserves with `try_reserve_exact` and fails with `OutOfMemory`.
  `Supervisor::stop` added `stop_timeout` to `Instant::now()`, which panics
  on overflow (also from `Drop`); a deadline the clock cannot hold is now
  no deadline.
- **Cancellation of completed reads on Windows.** A dropped operation's
  data is lost, which is inherent to owned buffers on completion ports;
  it is documented rather than fixed.
