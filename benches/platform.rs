//! Benchmarks of the operating system layers of `umilib::platform`.

use umilib::platform::bench::Bench;

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        #[cfg(all(
            umilib_feature = "platform-native",
            any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
        ))]
        {
            use std::hint::black_box;

            use umilib::platform::bench::Throughput;
            let random = umilib::platform::native::Random::new();
            let mut buffer = vec![0u8; 4096];
            bench.run("platform-native-random-4096", Some(Throughput::Bytes(4096)), || {
                random.fill(black_box(&mut buffer)).unwrap();
            });
        }
        #[cfg(all(
            umilib_feature = "platform-native",
            any(target_os = "linux", target_os = "android", target_vendor = "apple")
        ))]
        {
            use std::hint::black_box;
            use std::time::Duration;

            use umilib::platform::bench::Throughput;
            let poller = umilib::platform::native::Poller::new().unwrap();
            let mut events = Vec::new();
            bench.run("platform-native-poller-notify-wait", Some(Throughput::Elements(1)), || {
                poller.notify().unwrap();
                black_box(poller.wait(&mut events, Some(Duration::from_secs(1))).unwrap());
            });
        }
        #[cfg(all(
            umilib_feature = "platform-runtime",
            any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
        ))]
        Benchmarks::runtime(bench);
        let _ = bench;
    }

    /// The thread pool (spawning tasks and waiting for them) and the
    /// reactor's sockets (bytes through a loopback TCP connection).
    #[cfg(all(
        umilib_feature = "platform-runtime",
        any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
    ))]
    pub fn runtime(bench: &mut Bench) {
        use std::hint::black_box;

        use umilib::platform::bench::Throughput;
        use umilib::platform::runtime::{ListenerConfig, Runtime, RuntimeConfig, TCPListener, TCPStream};
        use umilib::runtime::{AsyncRead, AsyncWrite, Executor, Join, JoinAll, SocketAddress};

        let runtime = Runtime::new(&RuntimeConfig::default()).unwrap();
        bench.run("platform-runtime-pool-spawn-wait", Some(Throughput::Elements(1)), || {
            black_box(runtime.block_on(runtime.spawn(async { black_box(1u64) })).unwrap());
        });
        bench.run("platform-runtime-pool-spawn-1000", Some(Throughput::Elements(1000)), || {
            let handles: Vec<_> = (0..1000u64).map(|index| runtime.spawn(async move { black_box(index) })).collect();
            black_box(runtime.block_on(JoinAll::new(handles)));
        });

        let localhost = SocketAddress::V4 { address: [127, 0, 0, 1], port: 0 };
        let listener = TCPListener::bind(runtime.reactor(), localhost, &ListenerConfig::default()).unwrap();
        let address = listener.local_address().unwrap();
        let reactor = runtime.reactor().clone();
        let (client, accepted) = runtime.block_on(Join::new(TCPStream::connect(&reactor, address), listener.accept()));
        let (mut client, (mut server, _)) = (client.unwrap(), accepted.unwrap());
        const LENGTH: usize = 1 << 16;
        let mut outgoing = Some(vec![0x5au8; LENGTH]);
        let mut incoming = Some(Vec::with_capacity(LENGTH));
        bench.run("platform-runtime-tcp-loopback-65536", Some(Throughput::Bytes(LENGTH as u64)), || {
            let (sent, received) = runtime.block_on(Join::new(
                async {
                    let (result, buffer) = client.write_all(outgoing.take().unwrap()).await;
                    result.unwrap();
                    buffer
                },
                async {
                    let mut buffer = incoming.take().unwrap();
                    let mut total = 0;
                    while total < LENGTH {
                        buffer.clear();
                        let (result, read) = server.read(buffer).await;
                        buffer = read;
                        total += result.unwrap();
                    }
                    buffer
                },
            ));
            outgoing = Some(sent);
            incoming = Some(received);
        });
    }
}
