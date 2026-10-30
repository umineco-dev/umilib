//! An echo server on the platform runtime, in one process or in several,
//! and a client that loads it and checks every byte it gets back.
//!
//! ```text
//! cargo run --release --example echo --features platform-runtime -- server 127.0.0.1:7000 [--threads N] [--workers N]
//! cargo run --release --example echo --features platform-runtime -- client 127.0.0.1:7000 [--connections N] [--messages N] [--size N]
//! ```
//!
//! With `--workers N`, the server is a supervisor of N worker processes (this
//! program again) that share its listener; each prints the connections it
//! served when the supervisor stops it (when the supervisor exits).
//! The client uses blocking std sockets on threads of its own, so that it
//! does not depend on the runtime it measures.

#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports)
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::runtime::{
    Conversion, ListenerConfig, Runtime, RuntimeConfig, Supervisor, SupervisorConfig, TCPListener, ThreadPoolConfig,
    Worker,
};
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::runtime::{AsyncRead, AsyncWrite, Channel, Either, Executor, Select};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
/// The options of the command line, with their defaults.
struct Options {
    mode: String,
    address: std::net::SocketAddr,
    threads: usize,
    workers: usize,
    connections: usize,
    messages: usize,
    size: usize,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Options {
    fn parse() -> Result<Options, String> {
        let mut arguments = std::env::args().skip(1);
        let mode = arguments.next().ok_or("a mode: server or client")?;
        let address = arguments.next().ok_or("an address")?.parse().map_err(|error| format!("the address: {error}"))?;
        let mut options = Options { mode, address, threads: 0, workers: 0, connections: 64, messages: 1000, size: 512 };
        while let Some(name) = arguments.next() {
            let value: usize =
                arguments.next().and_then(|value| value.parse().ok()).ok_or(format!("{name} needs a number"))?;
            match name.as_str() {
                "--threads" => options.threads = value,
                "--workers" => options.workers = value,
                "--connections" => options.connections = value,
                "--messages" => options.messages = value,
                "--size" => options.size = value.max(1),
                _ => return Err(format!("unknown option {name}")),
            }
        }
        Ok(options)
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
/// The server: a listener served by a runtime, in this process or in workers.
struct Server;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Server {
    fn run(options: &Options) -> std::io::Result<()> {
        if let Some(mut worker) = Worker::current()? {
            let listener = worker.take_listeners().remove(0);
            let served = Server::serve(options.threads, listener, true)?;
            eprintln!("worker {} (process {}): {served} connections", worker.index(), std::process::id());
            return Ok(());
        }
        let listener = ListenerConfig::default().bind(Conversion::address(options.address)).map_err(Server::error)?;
        eprintln!("listening on {}", options.address);
        if options.workers == 0 {
            Server::serve(options.threads, listener, false)?;
            return Ok(());
        }
        let config = SupervisorConfig { workers: options.workers, ..SupervisorConfig::default() };
        let mut supervisor = Supervisor::new(config, vec![listener]);
        supervisor.run(|| false)
    }

    /// Serves `listener` until the supervisor asks to stop (if `supervised`)
    /// or forever; the connections served.
    fn serve(threads: usize, listener: umilib::platform::native::Socket, supervised: bool) -> std::io::Result<u64> {
        let config = RuntimeConfig {
            pool: ThreadPoolConfig { threads, ..ThreadPoolConfig::default() },
            ..RuntimeConfig::default()
        };
        let runtime = Runtime::new(&config)?;
        let listener = TCPListener::from_socket(runtime.reactor(), listener).map_err(Server::error)?;
        // `stopped` ends when the supervisor asks to stop; without one, its sender is kept forever.
        let (sender, mut stopped) = Channel::oneshot::<()>();
        let _kept = if supervised {
            Worker::watch(move || {
                let _ = sender.send(());
            })?;
            None
        } else {
            Some(sender)
        };
        let served = Arc::new(AtomicU64::new(0));
        let spawner = runtime.spawner();
        let counter = served.clone();
        runtime.block_on(async move {
            while let Either::First(accepted) = Select::new(listener.accept(), &mut stopped).await {
                let Ok((mut stream, _)) = accepted else { continue };
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = stream.set_nodelay(true);
                spawner.spawn(async move {
                    let mut buffer = Vec::with_capacity(16 * 1024);
                    loop {
                        buffer.clear();
                        let (result, read) = stream.read(buffer).await;
                        buffer = read;
                        if !matches!(result, Ok(count) if count > 0) {
                            break;
                        }
                        let (result, written) = stream.write_all(buffer).await;
                        buffer = written;
                        if result.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok(served.load(Ordering::Relaxed))
    }

    fn error(error: umilib::runtime::IOError) -> std::io::Error {
        std::io::Error::other(format!("{error:?}"))
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
/// The client: connections on threads of their own, each sending messages
/// and checking that the same bytes come back.
struct Client;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Client {
    fn run(options: &Options) -> std::io::Result<()> {
        let start = Instant::now();
        let threads: Vec<_> = (0..options.connections)
            .map(|connection| {
                let (address, messages, size) = (options.address, options.messages, options.size);
                std::thread::spawn(move || Client::connection(address, connection, messages, size))
            })
            .collect();
        let mut latencies = Vec::with_capacity(options.connections * options.messages);
        let mut failures = 0;
        for thread in threads {
            match thread.join().expect("a client thread panicked") {
                Ok(times) => latencies.extend(times),
                Err(error) => {
                    failures += 1;
                    eprintln!("connection failed: {error}");
                }
            }
        }
        let elapsed = start.elapsed();
        latencies.sort_unstable();
        let percentile = |fraction: f64| {
            latencies
                .get(((latencies.len() as f64 * fraction) as usize).min(latencies.len().saturating_sub(1)))
                .copied()
        };
        let bytes = 2 * latencies.len() as u64 * options.size as u64;
        println!(
            "{} connections, {} round trips of {} bytes in {:.2?}: {:.0} round trips/s, {:.1} MiB/s; latency p50 {:?}, p99 {:?}, max {:?}; {} failed",
            options.connections,
            latencies.len(),
            options.size,
            elapsed,
            latencies.len() as f64 / elapsed.as_secs_f64(),
            bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0),
            percentile(0.5).unwrap_or_default(),
            percentile(0.99).unwrap_or_default(),
            latencies.last().copied().unwrap_or_default(),
            failures,
        );
        if failures > 0 { Err(std::io::Error::other("connections failed")) } else { Ok(()) }
    }

    /// The latencies of the round trips of one connection.
    fn connection(
        address: std::net::SocketAddr,
        connection: usize,
        messages: usize,
        size: usize,
    ) -> std::io::Result<Vec<Duration>> {
        let mut stream = TcpStream::connect(address)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut latencies = Vec::with_capacity(messages);
        let mut answer = vec![0u8; size];
        for message in 0..messages {
            let data: Vec<u8> = (0..size).map(|index| (index * 31 + message * 7 + connection) as u8).collect();
            let start = Instant::now();
            stream.write_all(&data)?;
            stream.read_exact(&mut answer)?;
            latencies.push(start.elapsed());
            if answer != data {
                return Err(std::io::Error::other(format!(
                    "connection {connection}: message {message} came back changed"
                )));
            }
        }
        Ok(latencies)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    eprintln!("echo: the platform runtime needs Linux, Android, Darwin or Windows");
    std::process::exit(2);
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let options = match Options::parse() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("echo: {error}");
            std::process::exit(2);
        }
    };
    let result = match options.mode.as_str() {
        "server" => Server::run(&options),
        "client" => Client::run(&options),
        mode => Err(std::io::Error::other(format!("unknown mode {mode}"))),
    };
    if let Err(error) = result {
        eprintln!("echo: {error}");
        std::process::exit(1);
    }
}
