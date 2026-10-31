//! The platform runtime: the thread pool, the reactor's timers and sockets.

use std::sync::Arc;
use std::time::{Duration, Instant};

use umilib::platform::runtime::{Reactor, ReactorConfig, ThreadPool, ThreadPoolConfig};
use umilib::runtime::{Channel, Executor, JoinAll, TaskError, YieldNow};

fn pool(threads: usize) -> ThreadPool {
    ThreadPool::new(&ThreadPoolConfig { threads, ..ThreadPoolConfig::default() }).unwrap()
}

#[test]
fn pools_run_many_tasks_on_their_threads() {
    let pool = pool(4);
    assert_eq!(pool.threads(), 4);
    let threads = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    // Miri runs the tasks thousands of times slower, and slower still as they add up.
    let count: u64 = if cfg!(miri) { 100 } else { 10_000 };
    let handles: Vec<_> = (0..count)
        .map(|index| {
            let threads = threads.clone();
            pool.spawn(async move {
                YieldNow::new().await;
                threads.lock().unwrap().insert(std::thread::current().name().unwrap().to_string());
                index * index
            })
        })
        .collect();
    let results = pool.block_on(JoinAll::new(handles));
    assert_eq!(results.iter().map(|result| result.unwrap()).sum::<u64>(), (0..count).map(|i| i * i).sum());
    let names = threads.lock().unwrap().clone();
    assert!(names.iter().all(|name| name.starts_with("umilib-worker-")));
    // Four tasks that each wait until all four run at once: only workers that
    // take work from each other can run them (however quick the others are).
    let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gathered: Vec<_> = (0..4)
        .map(|_| {
            let running = running.clone();
            pool.spawn(async move {
                running.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(120);
                while running.load(std::sync::atomic::Ordering::SeqCst) < 4 && Instant::now() < deadline {
                    std::thread::yield_now();
                }
                running.load(std::sync::atomic::Ordering::SeqCst) == 4
            })
        })
        .collect();
    let gathered = pool.block_on(JoinAll::new(gathered));
    assert!(gathered.into_iter().all(|result| result == Ok(true)), "the work is shared between workers");
}

#[test]
fn tasks_spawn_tasks_and_talk_through_channels() {
    let pool = pool(3);
    let spawner = pool.spawner();
    let (sender, mut receiver) = Channel::bounded::<u32>(4);
    let producers = pool.spawn(async move {
        let handles: Vec<_> = (0..8)
            .map(|producer| {
                let sender = sender.clone();
                spawner.spawn(async move {
                    for value in 0..1000 {
                        sender.send(producer * 1000 + value).await.unwrap();
                    }
                })
            })
            .collect();
        JoinAll::new(handles).await
    });
    let consumer = pool.spawn(async move {
        let mut count = 0u32;
        while receiver.receive().await.is_some() {
            count += 1;
        }
        count
    });
    assert_eq!(pool.block_on(producers).unwrap().len(), 8);
    assert_eq!(pool.block_on(consumer), Ok(8000));
}

#[test]
fn a_panicking_task_is_dropped_and_the_pool_goes_on() {
    let pool = pool(2);
    let failing = pool.spawn(async {
        if Instant::now().elapsed() < Duration::from_secs(60) {
            panic!("a task fails");
        }
        1
    });
    assert_eq!(pool.block_on(failing), Err(TaskError::Cancelled));
    assert_eq!(pool.block_on(pool.spawn(async { 2 })), Ok(2));
}

#[test]
fn dropping_a_pool_cancels_its_tasks() {
    let pool = pool(2);
    let (_sender, receiver) = Channel::oneshot::<u8>();
    let pending = pool.spawn(receiver);
    std::thread::sleep(Duration::from_millis(10));
    drop(pool);
    assert_eq!(ThreadPool::block_on_thread(pending), Err(TaskError::Cancelled));
}

#[test]
fn tasks_spawned_on_a_stopped_pool_are_cancelled() {
    let pool = pool(2);
    pool.shutdown();
    let late = pool.spawn(async { 1 });
    assert_eq!(pool.block_on(late), Err(TaskError::Cancelled));
}

#[test]
fn reactor_timers_wake_their_tasks_on_time() {
    let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
    let pool = pool(2);
    let timer = reactor.timer().clone();
    let start = Instant::now();
    let sleeps: Vec<_> = [50u64, 10, 30, 20, 40]
        .iter()
        .map(|milliseconds| {
            let timer = timer.clone();
            let milliseconds = *milliseconds;
            pool.spawn(async move {
                timer.sleep(Duration::from_millis(milliseconds)).await;
                (milliseconds, start.elapsed())
            })
        })
        .collect();
    for result in pool.block_on(JoinAll::new(sleeps)) {
        let (milliseconds, elapsed) = result.unwrap();
        assert!(elapsed >= Duration::from_millis(milliseconds), "{milliseconds} ms after {elapsed:?}");
        assert!(elapsed < Duration::from_millis(milliseconds + 500), "{milliseconds} ms after {elapsed:?}");
    }
    let (_sender, receiver) = Channel::oneshot::<u8>();
    let timed = pool.block_on(timer.timeout(Duration::from_millis(20), receiver));
    assert!(timed.is_err());
}

#[test]
fn pools_refuse_a_number_of_threads_beyond_memory() {
    let config = ThreadPoolConfig { threads: usize::MAX, ..ThreadPoolConfig::default() };
    let error = ThreadPool::new(&config).err().expect("a pool of usize::MAX threads");
    assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
}

#[test]
fn reactors_take_their_limits_from_the_config() {
    let defaults = ReactorConfig::default();
    assert_eq!((defaults.maximum_events, defaults.retry_delay), (256, Duration::from_millis(10)));
    let none = ReactorConfig { maximum_events: 0, ..ReactorConfig::default() };
    assert_eq!(Reactor::new(&none).expect_err("a reactor of no events").kind(), std::io::ErrorKind::InvalidInput);
    // A reactor taking one event per wait still serves its timers.
    let reactor = Reactor::new(&ReactorConfig { maximum_events: 1, ..ReactorConfig::default() }).unwrap();
    let pool = pool(1);
    let timer = reactor.timer();
    let sleeps: Vec<_> = (0..4u64)
        .map(|milliseconds| {
            let timer = timer.clone();
            pool.spawn(async move { timer.sleep(Duration::from_millis(milliseconds)).await })
        })
        .collect();
    assert!(pool.block_on(JoinAll::new(sleeps)).iter().all(Result::is_ok));
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
mod sockets {
    use std::time::Duration;

    use umilib::platform::runtime::{ListenerConfig, Reactor, ReactorConfig, TCPListener, TCPStream, UDPSocket};
    use umilib::runtime::{AsyncDatagram, AsyncRead, AsyncWrite, Executor, IOErrorKind, JoinAll, SocketAddress};

    use super::pool;

    const LOCALHOST: SocketAddress = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };

    #[test]
    #[cfg_attr(miri, ignore = "64 connections of 20 kB take longer than its timeout under Miri")]
    fn tcp_echoes_many_connections() {
        let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
        let pool = pool(4);
        let listener = TCPListener::bind(&reactor, LOCALHOST, &ListenerConfig::default()).unwrap();
        let address = listener.local_address().unwrap();
        let spawner = pool.spawner();
        // The server: one task per connection, echoing until the client ends its side.
        pool.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                spawner.spawn(async move {
                    let mut buffer = Vec::with_capacity(4096);
                    loop {
                        buffer.clear();
                        let (result, read) = stream.read(buffer).await;
                        buffer = read;
                        match result {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                let (result, written) = stream.write_all(buffer).await;
                                buffer = written;
                                if result.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        let clients: Vec<_> = (0..64u32)
            .map(|client| {
                let reactor = reactor.clone();
                pool.spawn(async move {
                    let mut stream = TCPStream::connect(&reactor, address).await.unwrap();
                    stream.set_nodelay(true).unwrap();
                    let data: Vec<u8> = (0..20_000u32).map(|index| (index * 7 + client) as u8).collect();
                    let (result, _) = stream.write_all(data.clone()).await;
                    result.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut received = Vec::new();
                    loop {
                        let (result, buffer) = stream.read(Vec::with_capacity(8192)).await;
                        if result.unwrap() == 0 {
                            break;
                        }
                        received.extend_from_slice(&buffer);
                    }
                    received == data
                })
            })
            .collect();
        let results = pool.block_on(reactor.timer().timeout(Duration::from_secs(30), JoinAll::new(clients)));
        assert!(results.unwrap().into_iter().all(|result| result == Ok(true)));
    }

    #[test]
    fn connecting_to_a_closed_port_is_refused() {
        let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let result =
            pool(1).block_on(TCPStream::connect(&reactor, SocketAddress::V4 { address: [127, 0, 0, 1], port }));
        assert_eq!(result.unwrap_err().kind, IOErrorKind::ConnectionRefused);
    }

    /// A worker's listener is a duplicate of the supervisor's
    /// (`WSADuplicateSocketW`): it shares the underlying socket, which another
    /// worker's completion port may already be associated with, and a socket
    /// may be associated with only one port. Here the original is associated
    /// with one reactor and a duplicate for this process accepts through
    /// another, by events.
    #[cfg(windows)]
    #[test]
    fn duplicated_listeners_accept_beside_an_associated_one() {
        use umilib::platform::native::Socket;
        use umilib::platform::runtime::CompletionRoute;

        async fn read_to_end(stream: &mut TCPStream) -> Vec<u8> {
            let mut received = Vec::new();
            loop {
                let (result, buffer) = stream.read(Vec::with_capacity(16)).await;
                if result.unwrap() == 0 {
                    return received;
                }
                received.extend_from_slice(&buffer);
            }
        }

        let (first, second) =
            (Reactor::new(&ReactorConfig::default()).unwrap(), Reactor::new(&ReactorConfig::default()).unwrap());
        let original = ListenerConfig::default().bind(LOCALHOST).unwrap();
        let duplicate = Socket::from_duplicate(&original.duplicate(std::process::id()).unwrap()).unwrap();
        assert!(duplicate.is_duplicate() && !original.is_duplicate());
        // Registering a duplicate associates nothing, so `from_socket` may register it again
        // (an associated socket cannot be associated a second time, even with the same port).
        assert_eq!(second.register(&duplicate).unwrap(), CompletionRoute::Event);
        let original = TCPListener::from_socket(&first, original).unwrap();
        let duplicate = TCPListener::from_socket(&second, duplicate).unwrap();
        let address = original.local_address().unwrap();
        let pool = pool(2);
        // An accept dropped before a connection is cancelled; its completion still comes and frees it.
        let waited = pool.block_on(second.timer().timeout(Duration::from_millis(50), duplicate.accept()));
        assert!(waited.is_err());
        // Each listener accepts a connection and echoes it, the duplicate's by events.
        for listener in [duplicate, original] {
            let client = {
                let reactor = second.clone();
                pool.spawn(async move {
                    let mut stream = TCPStream::connect(&reactor, address).await.unwrap();
                    let (result, _) = stream.write_all(b"shared".to_vec()).await;
                    result.unwrap();
                    stream.shutdown().await.unwrap();
                    read_to_end(&mut stream).await
                })
            };
            let server = pool.spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let received = read_to_end(&mut stream).await;
                let (result, _) = stream.write_all(received).await;
                result.unwrap();
                stream.shutdown().await.unwrap();
            });
            let served = pool.block_on(second.timer().timeout(Duration::from_secs(30), JoinAll::new(vec![server])));
            assert_eq!(served.unwrap(), vec![Ok(())]);
            assert_eq!(pool.block_on(client).unwrap(), b"shared");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call sendto")]
    fn udp_sockets_exchange_datagrams() {
        let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
        let pool = pool(2);
        let mut a = UDPSocket::bind(&reactor, LOCALHOST).unwrap();
        let mut b = UDPSocket::bind(&reactor, LOCALHOST).unwrap();
        let (a_address, b_address) = (a.local_address().unwrap(), b.local_address().unwrap());
        let receiver = pool.spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..10 {
                let (result, buffer) = b.receive_from(Vec::with_capacity(64)).await;
                let (count, from) = result.unwrap();
                seen.push((buffer[..count].to_vec(), from));
            }
            seen
        });
        pool.block_on(async {
            for index in 0..10u8 {
                let (result, _) = a.send_to(vec![index; 5], b_address).await;
                assert_eq!(result.unwrap(), 5);
            }
        });
        let seen = pool.block_on(receiver).unwrap();
        assert_eq!(seen.len(), 10);
        assert!(seen.iter().all(|(data, from)| data.len() == 5 && *from == a_address));
    }
}

mod runtime_bundle {
    use std::time::{Duration, Instant};

    use umilib::platform::runtime::{ListenerConfig, Runtime, RuntimeConfig, TCPListener, TCPStream, ThreadPoolConfig};
    use umilib::runtime::{AsyncRead, AsyncWrite, Executor, SocketAddress};

    #[test]
    fn runtimes_run_tasks_with_sockets_and_timers() {
        let config = RuntimeConfig {
            pool: ThreadPoolConfig { threads: 2, ..ThreadPoolConfig::default() },
            ..RuntimeConfig::default()
        };
        let runtime = Runtime::new(&config).unwrap();
        assert_eq!(runtime.pool().threads(), 2);
        let localhost = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };
        let listener = TCPListener::bind(runtime.reactor(), localhost, &ListenerConfig::default()).unwrap();
        let address = listener.local_address().unwrap();
        let timer = runtime.reactor().timer().clone();
        let server = runtime.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            timer.sleep(Duration::from_millis(20)).await;
            let (result, _) = stream.write_all(b"late".to_vec()).await;
            result.unwrap();
        });
        let reactor = runtime.reactor().clone();
        let start = Instant::now();
        let received = runtime.block_on(async move {
            let mut stream = TCPStream::connect(&reactor, address).await.unwrap();
            let (result, buffer) = stream.read(Vec::with_capacity(16)).await;
            result.unwrap();
            buffer
        });
        assert_eq!(received, b"late");
        assert!(start.elapsed() >= Duration::from_millis(20));
        assert_eq!(runtime.block_on(server), Ok(()));
    }
}

mod supervisor {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    use umilib::platform::runtime::{
        ListenerConfig, RestartPolicy, Runtime, RuntimeConfig, Supervisor, SupervisorConfig, TCPListener,
        ThreadPoolConfig, Worker, WorkerHandshake,
    };
    use umilib::runtime::{AsyncRead, AsyncWrite, Channel, Either, Executor, Select, SocketAddress};

    /// What the workers of these tests do, chosen by the supervisor's environment.
    const MODE: &str = "UMILIB_TEST_WORKER_MODE";

    /// The workers of these tests: the test binary run again with only this
    /// test, which does nothing unless a supervisor started the process.
    #[test]
    fn worker_entry() {
        let Some(mut worker) = Worker::current().unwrap() else { return };
        if std::env::var_os(MODE).is_some_and(|mode| mode == "fail") {
            std::process::exit(3);
        }
        // Answers each connection with the worker's index and then the bytes it received, until stopped.
        let config = RuntimeConfig {
            pool: ThreadPoolConfig { threads: 2, ..ThreadPoolConfig::default() },
            ..RuntimeConfig::default()
        };
        let runtime = Runtime::new(&config).unwrap();
        let listener = TCPListener::from_socket(runtime.reactor(), worker.take_listeners().remove(0)).unwrap();
        let (sender, mut stopped) = Channel::oneshot::<()>();
        Worker::watch(move || {
            let _ = sender.send(());
        })
        .unwrap();
        let index = worker.index() as u8;
        let spawner = runtime.spawner();
        runtime.block_on(async move {
            while let Either::First(Ok((mut stream, _))) = Select::new(listener.accept(), &mut stopped).await {
                spawner.spawn(async move {
                    let (result, buffer) = stream.read(Vec::with_capacity(64)).await;
                    if result.is_ok() {
                        let mut answer = vec![index];
                        answer.extend_from_slice(&buffer);
                        let _ = stream.write_all(answer).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
    }

    fn config(workers: usize) -> SupervisorConfig {
        SupervisorConfig {
            workers,
            arguments: ["runtime::supervisor::worker_entry", "--exact", "--test-threads=1", "--quiet"]
                .iter()
                .map(Into::into)
                .collect(),
            restart_delay: Duration::from_millis(10),
            stop_timeout: Duration::from_secs(20),
            check_interval: Duration::from_millis(10),
            ..SupervisorConfig::default()
        }
    }

    /// A stop timeout past what the clock can represent waits without limit instead of panicking.
    #[test]
    fn stop_timeouts_beyond_the_clock_mean_no_limit() {
        let config = SupervisorConfig { workers: 1, stop_timeout: Duration::MAX, ..SupervisorConfig::default() };
        let mut supervisor = Supervisor::new(config, Vec::new());
        supervisor.stop().unwrap();
        drop(supervisor);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri can neither make SOCK_SEQPACKET socket pairs nor start processes")]
    fn workers_share_the_listeners_and_stop_when_asked() {
        let localhost = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };
        let listener = ListenerConfig::default().bind(localhost).unwrap();
        let address = listener.local_address().unwrap();
        let mut supervisor = Supervisor::new(config(3), vec![listener]);
        supervisor.start().unwrap();
        assert_eq!(supervisor.workers().len(), 3);
        assert!(supervisor.workers().iter().all(|worker| worker.id().is_some()));
        let mut indices = std::collections::BTreeSet::new();
        for client in 0..60u8 {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            stream.write_all(&[b'#', client]).unwrap();
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).unwrap();
            assert_eq!(answer.len(), 3, "client {client}");
            assert_eq!(&answer[1..], &[b'#', client]);
            indices.insert(answer[0]);
        }
        assert!(indices.iter().all(|index| *index < 3));
        assert_eq!(supervisor.check().unwrap(), 3);
        supervisor.stop().unwrap();
        for worker in supervisor.workers() {
            assert!(!worker.is_running());
            assert!(worker.exit().unwrap().success(), "worker {} exited with {:?}", worker.index(), worker.exit());
            assert_eq!(worker.restarts(), 0);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri can neither make SOCK_SEQPACKET socket pairs nor start processes")]
    fn failed_workers_are_restarted_as_the_policy_says() {
        let localhost = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };
        let failing = |restart: RestartPolicy| {
            let listener = ListenerConfig::default().bind(localhost).unwrap();
            let mut config = config(1);
            config.environment.push((MODE.into(), "fail".into()));
            config.restart = restart;
            Supervisor::new(config, vec![listener])
        };

        let mut supervisor = failing(RestartPolicy::OnFailure);
        supervisor.start().unwrap();
        let start = Instant::now();
        while supervisor.workers()[0].restarts() < 2 && start.elapsed() < Duration::from_secs(60) {
            supervisor.check().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(supervisor.workers()[0].restarts() >= 2);
        supervisor.stop().unwrap();
        assert_eq!(supervisor.workers()[0].exit().unwrap().code(), Some(3));
        // Stopped, it starts nothing again.
        let restarts = supervisor.workers()[0].restarts();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(supervisor.check().unwrap(), 0);
        assert_eq!(supervisor.workers()[0].restarts(), restarts);

        // `run` returns once no worker runs nor is to be started again.
        let mut supervisor = failing(RestartPolicy::Never);
        supervisor.run(|| false).unwrap();
        assert_eq!(supervisor.workers()[0].exit().unwrap().code(), Some(3));
        assert_eq!(supervisor.workers()[0].restarts(), 0);

        // A worker that exits successfully is started again only by `Always`.
        #[cfg(unix)]
        let success = <std::process::ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(0);
        #[cfg(windows)]
        let success = <std::process::ExitStatus as std::os::windows::process::ExitStatusExt>::from_raw(0);
        assert!(success.success());
        assert!(!RestartPolicy::Never.restarts(success));
        assert!(!RestartPolicy::OnFailure.restarts(success));
        assert!(RestartPolicy::Always.restarts(success));
    }

    #[test]
    fn handshakes_round_trip_and_reject_what_is_not_one() {
        let handshake = WorkerHandshake { listeners: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], Vec::new()] };
        let bytes = handshake.encode();
        assert_eq!(&bytes[..12], b"UMWH\x01\x00\x00\x00\x03\x00\x00\x00");
        assert_eq!(WorkerHandshake::decode(&mut &bytes[..]).unwrap(), handshake);
        // The reader is left just after the handshake.
        let mut followed = bytes.clone();
        followed.extend_from_slice(b"rest");
        let mut reader = &followed[..];
        WorkerHandshake::decode(&mut reader).unwrap();
        assert_eq!(reader, b"rest");

        let invalid = |bytes: &[u8]| WorkerHandshake::decode(&mut &bytes[..]).unwrap_err().kind();
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert_eq!(invalid(&magic), std::io::ErrorKind::InvalidData);
        let mut version = bytes.clone();
        version[4] = 2;
        assert_eq!(invalid(&version), std::io::ErrorKind::InvalidData);
        let mut many = b"UMWH\x01\x00\x00\x00".to_vec();
        many.extend_from_slice(&(WorkerHandshake::MAXIMUM_LISTENERS as u32 + 1).to_le_bytes());
        assert_eq!(invalid(&many), std::io::ErrorKind::InvalidData);
        let mut long = b"UMWH\x01\x00\x00\x00\x01\x00\x00\x00".to_vec();
        long.extend_from_slice(&(WorkerHandshake::MAXIMUM_LENGTH as u32 + 1).to_le_bytes());
        assert_eq!(invalid(&long), std::io::ErrorKind::InvalidData);
        let twice = WorkerHandshake { listeners: vec![vec![9; 4], vec![9; 4]] }.encode();
        assert_eq!(invalid(&twice), std::io::ErrorKind::InvalidData);
        for end in 0..bytes.len() {
            assert_eq!(invalid(&bytes[..end]), std::io::ErrorKind::UnexpectedEof, "cut at {end}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn workers_adopt_only_sockets() {
        use std::os::fd::AsRawFd;
        let invalid = |bytes: &[u8]| WorkerHandshake::adopt(bytes).unwrap_err().kind();
        assert_eq!(invalid(&[1, 2, 3]), std::io::ErrorKind::InvalidData);
        assert_eq!(invalid(&(-1i32).to_le_bytes()), std::io::ErrorKind::InvalidData);
        // A descriptor that is not a socket is refused and left open.
        let mut file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(invalid(&file.as_raw_fd().to_le_bytes()), std::io::ErrorKind::InvalidData);
        let mut byte = [0u8; 1];
        assert_eq!(file.read(&mut byte).unwrap(), 1);
    }
}

mod review {
    //! The cases of the review of the platform runtime.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use umilib::platform::runtime::{
        ListenerConfig, Reactor, ReactorConfig, Runtime, RuntimeConfig, TCPListener, TCPStream, ThreadPool,
        ThreadPoolConfig,
    };
    use umilib::runtime::{Executor, JoinAll, SocketAddress, TaskError};

    /// A runtime dropped while a timer fires for a task its stopping pool
    /// drops at once does not hang (the timer woke its tasks under its lock).
    #[test]
    fn runtimes_drop_while_their_timers_fire() {
        let config = RuntimeConfig {
            pool: ThreadPoolConfig { threads: 1, ..ThreadPoolConfig::default() },
            ..RuntimeConfig::default()
        };
        let runtime = Runtime::new(&config).unwrap();
        let timer = runtime.reactor().timer();
        let sleeping = runtime.spawn(async move { timer.sleep(Duration::from_millis(50)).await });
        // Keeps the only worker busy (and so the pool's shutdown waiting) past the sleep's deadline.
        runtime.spawn(async { std::thread::sleep(Duration::from_millis(200)) });
        std::thread::sleep(Duration::from_millis(10));
        let start = Instant::now();
        drop(runtime);
        assert!(start.elapsed() < Duration::from_secs(10));
        // The sleep is normally still waiting for the busy worker and is cancelled with
        // the pool; when the worker starts late (as under Miri, which is much slower), the
        // deadline passes first and it finishes. Either way it ends, which is what is checked.
        let result = ThreadPool::block_on_thread(sleeping);
        assert!(matches!(result, Ok(()) | Err(TaskError::Cancelled)), "{result:?}");
    }

    /// Two tasks accepting on one listener are both woken.
    #[test]
    fn tasks_waiting_on_one_socket_are_all_woken() {
        let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
        let pool = ThreadPool::new(&ThreadPoolConfig { threads: 2, ..ThreadPoolConfig::default() }).unwrap();
        let localhost = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };
        let listener = Arc::new(TCPListener::bind(&reactor, localhost, &ListenerConfig::default()).unwrap());
        let address = listener.local_address().unwrap();
        let accepts: Vec<_> = (0..2)
            .map(|_| {
                let listener = listener.clone();
                pool.spawn(async move { listener.accept().await.is_ok() })
            })
            .collect();
        // Both tasks wait before the clients come.
        std::thread::sleep(Duration::from_millis(50));
        let clients: Vec<_> = (0..2)
            .map(|_| {
                let reactor = reactor.clone();
                pool.spawn(async move { TCPStream::connect(&reactor, address).await.is_ok() })
            })
            .collect();
        let timer = reactor.timer();
        let accepted = pool.block_on(timer.timeout(Duration::from_secs(10), JoinAll::new(accepts)));
        assert_eq!(accepted.expect("both accepts finish"), vec![Ok(true), Ok(true)]);
        assert!(pool.block_on(JoinAll::new(clients)).into_iter().all(|client| client == Ok(true)));
    }

    /// A sleep finishes after the last handle of its reactor is dropped: it holds the reactor.
    #[test]
    fn sleeps_keep_their_reactor_running() {
        let reactor = Reactor::new(&ReactorConfig::default()).unwrap();
        let pool = ThreadPool::new(&ThreadPoolConfig { threads: 1, ..ThreadPoolConfig::default() }).unwrap();
        let timer = reactor.timer();
        let sleeping = pool.spawn(async move { timer.sleep(Duration::from_millis(30)).await });
        drop(reactor);
        let start = Instant::now();
        assert_eq!(pool.block_on(sleeping), Ok(()));
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    /// A task that stops its own pool is dropped once its poll returns.
    #[test]
    fn a_task_stopping_its_pool_is_dropped() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let pool = Arc::new(ThreadPool::new(&ThreadPoolConfig { threads: 1, ..ThreadPoolConfig::default() }).unwrap());
        let dropped = Arc::new(AtomicBool::new(false));
        let (flag, inside) = (Flag(dropped.clone()), pool.clone());
        let (_sender, receiver) = umilib::runtime::Channel::oneshot::<()>();
        let handle = pool.spawn(async move {
            let _flag = flag;
            inside.shutdown();
            let _ = receiver.await;
        });
        assert_eq!(ThreadPool::block_on_thread(handle), Err(TaskError::Cancelled));
        let start = Instant::now();
        while !dropped.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(dropped.load(Ordering::Acquire));
    }
}
