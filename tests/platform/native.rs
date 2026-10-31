//! The native layer of the system the tests run on: random bytes, sockets
//! with their options, and the poller (or completion port).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::{Duration, Instant};

use umilib::platform::native::{Random, Socket, SocketKind, System};

#[test]
fn the_system_is_named() {
    const { assert!(System::SUPPORTED) };
    let expected = if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_vendor = "apple") {
        "darwin"
    } else {
        "windows"
    };
    assert_eq!(System::NAME, expected);
}

#[test]
fn random_bytes_cover_every_value() {
    let random = Random::new();
    let mut a = vec![0u8; 1 << 20];
    random.fill(&mut a).unwrap();
    let mut counts = [0u32; 256];
    a.iter().for_each(|byte| counts[*byte as usize] += 1);
    // Each value is expected 4096 times; a uniform source stays far within these bounds.
    assert!(counts.iter().all(|count| (3500..4700).contains(count)), "{:?}", counts.iter().min());
    let mut b = vec![0u8; 1 << 20];
    random.fill(&mut b).unwrap();
    assert_ne!(a, b);
    // More than one call's worth (getentropy gives 256 bytes a call), and nothing.
    let mut odd = [0u8; 1000];
    random.fill(&mut odd).unwrap();
    assert!(odd[900..].iter().any(|byte| *byte != 0));
    random.fill(&mut []).unwrap();
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[test]
#[cfg_attr(miri, ignore = "Miri supports few socket options (not SO_KEEPALIVE)")]
fn sockets_set_and_get_their_options() {
    let socket = Socket::for_address(&localhost(0), SocketKind::Stream).unwrap();
    socket.set_reuse_address(true).unwrap();
    assert!(socket.reuse_address().unwrap());
    socket.set_nodelay(true).unwrap();
    assert!(socket.nodelay().unwrap());
    socket.set_keepalive(true).unwrap();
    assert!(socket.keepalive().unwrap());
    socket.set_receive_buffer(1 << 16).unwrap();
    assert!(socket.receive_buffer().unwrap() >= 1 << 16);
    socket.set_send_buffer(1 << 15).unwrap();
    assert!(socket.send_buffer().unwrap() >= 1 << 15);
    socket.set_ttl(17).unwrap();
    assert_eq!(socket.ttl().unwrap(), 17);
    socket.set_nonblocking(true).unwrap();
    assert!(socket.nonblocking().unwrap());
    socket.set_nonblocking(false).unwrap();
    assert!(!socket.nonblocking().unwrap());
    let udp = Socket::for_address(&localhost(0), SocketKind::Datagram).unwrap();
    udp.set_broadcast(true).unwrap();
    assert!(udp.broadcast().unwrap());
    let v6 = Socket::for_address(&SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), SocketKind::Stream).unwrap();
    v6.set_only_v6(true).unwrap();
    assert!(v6.only_v6().unwrap());
    v6.set_only_v6(false).unwrap();
    assert!(!v6.only_v6().unwrap());
}

#[test]
fn listeners_accept_connections_with_their_backlog() {
    let listener = Socket::for_address(&localhost(0), SocketKind::Stream).unwrap();
    listener.set_reuse_address(true).unwrap();
    listener.bind(&localhost(0)).unwrap();
    listener.listen(4).unwrap();
    let address = listener.local_address().unwrap();
    assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(address.port(), 0);
    let client = Socket::for_address(&address, SocketKind::Stream).unwrap();
    assert!(client.connect(&address).unwrap());
    let (server, peer) = listener.accept(false).unwrap();
    assert_eq!(peer, client.local_address().unwrap());
    assert_eq!(server.peer_address().unwrap(), peer);
    assert!(!server.nonblocking().unwrap(), "accept sets the mode asked");
    assert_eq!(client.send(b"hello").unwrap(), 5);
    let mut buffer = [0u8; 16];
    assert_eq!(server.receive(&mut buffer).unwrap(), 5);
    assert_eq!(&buffer[..5], b"hello");
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server.receive(&mut buffer).unwrap(), 0, "the end of the stream");
    // The std types take the sockets over.
    let mut stream = server.into_tcp_stream();
    stream.write_all(b"back").unwrap();
    let mut client = client.into_tcp_stream();
    let mut back = [0u8; 4];
    client.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"back");
    // A nonblocking accept with nothing waiting would block; a nonblocking connect is in progress or done.
    let listener = listener.into_tcp_listener();
    let listener = Socket::from(listener);
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept(true).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let client = Socket::for_address(&address, SocketKind::Stream).unwrap();
    client.set_nonblocking(true).unwrap();
    let _connected = client.connect(&address).unwrap();
    let start = Instant::now();
    let (accepted, _) = loop {
        match listener.accept(true) {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < Duration::from_secs(5));
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("{error}"),
        }
    };
    assert!(accepted.nonblocking().unwrap());
    assert!(client.take_error().unwrap().is_none());
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot call sendto")]
fn datagram_sockets_send_to_and_receive_from() {
    let a = Socket::for_address(&localhost(0), SocketKind::Datagram).unwrap();
    a.bind(&localhost(0)).unwrap();
    let b = Socket::for_address(&localhost(0), SocketKind::Datagram).unwrap();
    b.bind(&localhost(0)).unwrap();
    let (a_address, b_address) = (a.local_address().unwrap(), b.local_address().unwrap());
    assert_eq!(a.send_to(b"datagram", &b_address).unwrap(), 8);
    let mut buffer = [0u8; 64];
    let (count, from) = b.receive_from(&mut buffer).unwrap();
    assert_eq!((&buffer[..count], from), (&b"datagram"[..], a_address));
    // IPv6 too, scope and all.
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
    let c = Socket::for_address(&v6, SocketKind::Datagram).unwrap();
    c.bind(&v6).unwrap();
    let d = Socket::for_address(&v6, SocketKind::Datagram).unwrap();
    d.bind(&v6).unwrap();
    c.send_to(b"six", &d.local_address().unwrap()).unwrap();
    let (count, from) = d.receive_from(&mut buffer).unwrap();
    assert_eq!((&buffer[..count], from), (&b"six"[..], c.local_address().unwrap()));
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod unix {
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::Duration;

    use umilib::platform::native::{
        Interest, NetworkInterface, PollEvent, PollMode, Poller, RawSocketAddress, Socket, SocketKind,
    };

    use super::localhost;

    #[test]
    fn raw_addresses_round_trip() {
        for address in ["192.0.2.7:443", "[2001:db8::1]:8080", "[fe80::1%3]:53", "0.0.0.0:0"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(RawSocketAddress::from_std(&address).to_std(), Some(address));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call if_nametoindex")]
    fn the_loopback_interface_has_an_index() {
        let name = if cfg!(target_vendor = "apple") { "lo0" } else { "lo" };
        assert!(NetworkInterface::index(name).unwrap() > 0);
        assert!(NetworkInterface::index("no-such-interface0").is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not support SO_REUSEPORT")]
    fn sockets_share_a_port_with_reuse_port() {
        let first = Socket::for_address(&localhost(0), SocketKind::Stream).unwrap();
        first.set_reuse_port(true).unwrap();
        assert!(first.reuse_port().unwrap());
        first.bind(&localhost(0)).unwrap();
        first.listen(16).unwrap();
        let address = first.local_address().unwrap();
        let second = Socket::for_address(&address, SocketKind::Stream).unwrap();
        second.set_reuse_port(true).unwrap();
        second.bind(&address).unwrap();
        second.listen(16).unwrap();
        // Without it, the port is taken.
        let third = Socket::for_address(&address, SocketKind::Stream).unwrap();
        assert_eq!(third.bind(&address).unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's epoll still reports a listener readable after its connection is accepted")]
    fn pollers_report_readiness_and_notifications() {
        // A wait interrupted by a signal returns no events (the children of
        // other tests send SIGCHLD), so a wait for events is repeated until
        // some come, for at most `timeout`.
        let wait_for_events = |poller: &Poller, events: &mut Vec<PollEvent>, timeout: Duration| {
            let deadline = std::time::Instant::now() + timeout;
            while poller.wait(events, Some(deadline.saturating_duration_since(std::time::Instant::now()))).unwrap() == 0
                && std::time::Instant::now() < deadline
            {}
        };
        let poller = Arc::new(Poller::new().unwrap());
        let listener = Socket::for_address(&localhost(0), SocketKind::Stream).unwrap();
        listener.bind(&localhost(0)).unwrap();
        listener.listen(8).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_address().unwrap();
        poller.add(listener.as_raw_fd(), 7, Interest::READABLE, PollMode::Level).unwrap();
        let mut events = Vec::new();
        assert_eq!(poller.wait(&mut events, Some(Duration::from_millis(10))).unwrap(), 0);
        let client = Socket::for_address(&address, SocketKind::Stream).unwrap();
        client.connect(&address).unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 7 && event.readable));
        // Level-triggered: still reported until accepted.
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 7));
        let (server, _) = listener.accept(true).unwrap();
        poller.wait(&mut events, Some(Duration::from_millis(10))).unwrap();
        assert!(events.iter().all(|event| event.token != 7));
        // Edge-triggered: once per change; writable at once, then readable when data comes.
        poller.add(server.as_raw_fd(), 8, Interest::BOTH, PollMode::Edge).unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 8 && event.writable));
        assert_eq!(poller.wait(&mut events, Some(Duration::from_millis(10))).unwrap(), 0);
        client.send(b"ping").unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 8 && event.readable));
        // Oneshot: once until modified.
        poller.modify(server.as_raw_fd(), 9, Interest::READABLE, PollMode::Oneshot).unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 9 && event.readable));
        assert_eq!(poller.wait(&mut events, Some(Duration::from_millis(10))).unwrap(), 0);
        poller.modify(server.as_raw_fd(), 9, Interest::READABLE, PollMode::Oneshot).unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 9));
        // A closed peer is a hang-up, readable.
        poller.modify(server.as_raw_fd(), 10, Interest::READABLE, PollMode::Level).unwrap();
        let mut buffer = [0u8; 8];
        server.receive(&mut buffer).unwrap();
        drop(client);
        wait_for_events(&poller, &mut events, Duration::from_secs(5));
        assert!(events.iter().any(|event| event.token == 10 && event.readable && event.hangup));
        poller.delete(server.as_raw_fd()).unwrap();
        poller.delete(listener.as_raw_fd()).unwrap();
        // The notification token is reserved; a notification from another thread ends a wait.
        assert!(poller.add(server.as_raw_fd(), PollEvent::NOTIFY, Interest::READABLE, PollMode::Level).is_err());
        let other = poller.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            other.notify().unwrap();
        });
        wait_for_events(&poller, &mut events, Duration::from_secs(60));
        assert_eq!(events, [PollEvent { token: PollEvent::NOTIFY, readable: true, ..PollEvent::default() }]);
        thread.join().unwrap();
        // Notifications before a wait are not lost.
        poller.notify().unwrap();
        poller.notify().unwrap();
        wait_for_events(&poller, &mut events, Duration::from_secs(1));
        assert_eq!(events.len(), 1);
        assert_eq!(poller.wait(&mut events, Some(Duration::from_millis(10))).unwrap(), 0);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::net::{Ipv4Addr, SocketAddr};

    use umilib::platform::linux::sys::Linux;
    use umilib::platform::linux::{EventFD, LinkAddress, PacketSocket, TUNDevice, TUNKind};
    use umilib::platform::unix::{NetworkInterface, SocketKind};

    #[test]
    fn event_fds_count_notifications() {
        let event = EventFD::new().unwrap();
        assert_eq!(event.drain().unwrap(), 0);
        event.notify().unwrap();
        event.notify().unwrap();
        assert_eq!(event.drain().unwrap(), 2);
        assert_eq!(event.drain().unwrap(), 0);
    }

    /// The number of the `getrandom` system call of the architecture is
    /// right: the call itself fills the buffer (no `/dev/urandom` fallback).
    #[test]
    fn the_getrandom_system_call_is_known() {
        let number = Linux::SYS_GETRANDOM.expect("the architectures of the release are known");
        let mut buffer = [0u8; 64];
        // SAFETY: the buffer is writable for its length; the flags are `unsigned int`, as in the prototype.
        let result = unsafe {
            umilib::platform::linux::sys::syscall(number, buffer.as_mut_ptr(), buffer.len(), 0 as core::ffi::c_uint)
        };
        assert_eq!(result, 64, "{}", std::io::Error::last_os_error());
        assert!(buffer.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn link_addresses_round_trip() {
        let address = LinkAddress::new(3, 0x0800, &[0, 1, 2, 3, 4, 5]);
        assert_eq!(LinkAddress::from_raw(&address.to_raw()), Some(address));
    }

    /// Packet sockets need CAP_NET_RAW (root in a container); without it the test checks the refusal.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot call if_nametoindex")]
    fn packet_sockets_see_the_frames_of_the_loopback() {
        let interface = NetworkInterface::index("lo").unwrap();
        let socket = match PacketSocket::open(SocketKind::Datagram, 0x0800, Some(interface)) {
            Ok(socket) => socket,
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                return;
            }
        };
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target: SocketAddr = (Ipv4Addr::LOCALHOST, udp.local_addr().unwrap().port()).into();
        udp.send_to(b"through the packet socket", target).unwrap();
        let mut buffer = [0u8; 2048];
        loop {
            let (count, raw) = socket.receive_from_raw(&mut buffer).unwrap();
            let from = LinkAddress::from_raw(&raw).unwrap();
            assert_eq!((from.interface, from.protocol), (interface, 0x0800));
            // An IPv4 packet: its payload ends with the UDP payload sent.
            if buffer[..count].ends_with(b"through the packet socket") {
                assert_eq!(buffer[0] >> 4, 4);
                break;
            }
        }
    }

    /// TUN and TAP interfaces need CAP_NET_ADMIN and `/dev/net/tun` (in a
    /// container: `--cap-add NET_ADMIN --device /dev/net/tun`); without them
    /// the test checks the refusal.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot use ioctl on files (TUNSETIFF)")]
    fn tun_devices_are_interfaces_of_the_kernel() {
        // A name has at most IFNAMSIZ - 1 = 15 bytes and no NUL; it is refused before anything is opened.
        for name in ["a-name-too-long!", "a\0b"] {
            let error = TUNDevice::open(name, TUNKind::TUN).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{name:?}");
        }
        let tun = match TUNDevice::open("umitun%d", TUNKind::TUN) {
            Ok(device) => device,
            Err(error) => {
                use std::io::ErrorKind;
                assert!(matches!(error.kind(), ErrorKind::PermissionDenied | ErrorKind::NotFound), "{error}");
                return;
            }
        };
        // The kernel chose the name from the pattern, and the interface exists.
        assert!(tun.name.starts_with("umitun") && tun.name.len() > "umitun".len(), "{}", tun.name);
        assert_eq!(tun.kind, TUNKind::TUN);
        assert!(NetworkInterface::index(&tun.name).is_ok());
        let longest = TUNDevice::open("umi-fifteen-ch1", TUNKind::TUN).unwrap();
        assert_eq!(longest.name, "umi-fifteen-ch1");
        drop(longest);
        let tap = TUNDevice::open("", TUNKind::TAP).unwrap();
        assert!(tap.name.starts_with("tap"), "{}", tap.name);
        assert_ne!(NetworkInterface::index(&tap.name).unwrap(), NetworkInterface::index(&tun.name).unwrap());
        // Nothing is routed to a new interface: a nonblocking read finds no packet.
        assert!(!tun.nonblocking().unwrap());
        tun.set_nonblocking(true).unwrap();
        assert!(tun.nonblocking().unwrap());
        let mut packet = [0u8; 1500];
        assert_eq!(tun.receive(&mut packet).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        // Closing the device removes the interface it created.
        let name = tun.name.clone();
        drop(tun);
        assert_eq!(NetworkInterface::index(&name).unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
