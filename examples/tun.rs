//! A host on a TUN interface of the Linux kernel, built from the sans-I/O
//! layers of this crate: it answers pings over IPv4 and IPv6 (RFC 792,
//! RFC 4443), echoes UDP datagrams (RFC 768) and TCP connections (RFC 9293)
//! on port 7 (the Echo Protocol, RFC 862), and resets TCP segments for any
//! other port. With `--connect`, it also opens a TCP connection to the
//! kernel, sends bytes and checks that they come back.
//!
//! ```text
//! cargo build --release --example tun --features platform-linux,protocol-icmp,protocol-udp,protocol-tcp
//! sudo target/release/examples/tun umi0 10.7.0.2 fd00:7::2 [--mtu 1500] [--connect 10.7.0.1:7000 --bytes 1000000]
//! sudo ip link set umi0 up mtu 1500; sudo ip address add 10.7.0.1/24 dev umi0; sudo ip address add fd00:7::1/64 dev umi0
//! ping 10.7.0.2; ping fd00:7::2; nc -u 10.7.0.2 7; nc 10.7.0.2 7
//! ```
//!
//! `examples/tun.sh` runs these against the kernel in a Docker container.

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant as StdInstant};

use umilib::bytes::{Buffer, Writer};
use umilib::protocol::icmp::v4::ICMPv4Message;
use umilib::protocol::icmp::v6::ICMPv6Message;
use umilib::protocol::ip::v4::IPv4Header;
use umilib::protocol::ip::v6::IPv6Header;
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPEndpointPattern, IPProtocol, IPv4Address, IPv6Address};
use umilib::protocol::tcp::{TCPConfig, TCPConnection, TCPEvent, TCPISNGenerator, TCPListener, TCPSegment, TCPState};
use umilib::protocol::udp::{UDPConfig, UDPDatagram};
use umilib::runtime::Instant;

/// The options of the command line.
struct Options {
    name: String,
    v4: IPv4Address,
    v6: IPv6Address,
    mtu: u16,
    connect: Option<IPEndpoint>,
    bytes: usize,
}

impl Options {
    fn parse() -> Result<Options, String> {
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        let usage = "usage: tun NAME IPV4 IPV6 [--mtu N] [--connect ADDRESS:PORT --bytes N]";
        let [name, v4, v6, rest @ ..] = arguments.as_slice() else { return Err(usage.into()) };
        let mut options = Options {
            name: name.clone(),
            v4: v4.parse().map_err(|_| format!("bad IPv4 address {v4}"))?,
            v6: v6.parse().map_err(|_| format!("bad IPv6 address {v6}"))?,
            mtu: 1500,
            connect: None,
            bytes: 1_000_000,
        };
        let mut rest = rest.iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or(usage)?;
            match flag.as_str() {
                "--mtu" => options.mtu = value.parse().map_err(|_| format!("bad MTU {value}"))?,
                "--connect" => options.connect = Some(value.parse().map_err(|_| format!("bad endpoint {value}"))?),
                "--bytes" => options.bytes = value.parse().map_err(|_| format!("bad count {value}"))?,
                _ => return Err(usage.into()),
            }
        }
        Ok(options)
    }
}

/// The connection `--connect` opens: what it sent and what came back.
struct Client {
    remote: IPEndpoint,
    data: Vec<u8>,
    sent: usize,
    received: usize,
    started: StdInstant,
}

#[cfg(target_os = "linux")]
mod host {
    use super::*;
    use umilib::platform::linux::sys::Linux;
    use umilib::platform::linux::{Poller, Random, TUNDevice, TUNKind};
    use umilib::platform::unix::{Interest, PollMode};

    /// The host: the interface, its addresses, and the state of its protocols.
    pub struct Host {
        pub device: TUNDevice,
        pub v4: IPv4Address,
        pub v6: IPv6Address,
        pub udp: UDPConfig,
        pub tcp: TCPConfig,
        pub isn: TCPISNGenerator,
        pub listener: TCPListener,
        pub connections: HashMap<(IPEndpoint, IPEndpoint), TCPConnection>,
        pub client: Option<Client>,
        pub identification: u16,
        pub origin: StdInstant,
    }

    impl Host {
        /// The port of the echo services.
        pub const ECHO: u16 = 7;

        pub fn new(options: &Options) -> std::io::Result<Host> {
            let device = TUNDevice::open(&options.name, TUNKind::TUN)?;
            let tcp = TCPConfig { mtu: options.mtu, ..TCPConfig::default() };
            let mut keys = [[0u8; 16]; 2];
            for key in &mut keys {
                Random.fill(key)?;
            }
            Ok(Host {
                device,
                v4: options.v4,
                v6: options.v6,
                udp: UDPConfig::default(),
                tcp,
                isn: TCPISNGenerator::new(keys[0]),
                listener: TCPListener::new(
                    tcp,
                    IPEndpointPattern::port(Host::ECHO),
                    128,
                    TCPISNGenerator::new(keys[1]),
                )
                .map_err(std::io::Error::other)?,
                connections: HashMap::new(),
                client: None,
                identification: 0,
                origin: StdInstant::now(),
            })
        }

        pub fn now(&self) -> Instant {
            Instant::from_nanos(self.origin.elapsed().as_nanos() as u64)
        }

        /// Reads packets and answers them until the client, if any, is done.
        pub fn run(&mut self, connect: Option<IPEndpoint>, bytes: usize) -> std::io::Result<()> {
            self.device.set_nonblocking(true)?;
            let poller = Poller::new()?;
            poller.add(std::os::fd::AsRawFd::as_raw_fd(&self.device), 0, Interest::READABLE, PollMode::Level)?;
            println!("{}: {} and {} on {}", self.device.name, self.v4, self.v6, self.device.name);
            if let Some(remote) = connect {
                self.connect(remote, bytes)?;
            }
            let mut packet = vec![0u8; 65536];
            let mut events = Vec::new();
            loop {
                let now = self.now();
                let deadline = self
                    .connections
                    .values()
                    .filter_map(TCPConnection::poll_timeout)
                    .chain(self.listener.poll_timeout())
                    .min();
                let timeout =
                    deadline.map(|deadline| Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())));
                poller.wait(&mut events, timeout)?;
                loop {
                    match self.device.receive(&mut packet) {
                        Ok(length) => self.receive(&packet[..length])?,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
                self.transmit()?;
                // The client is done once its connection is closed or waits out TIME-WAIT.
                if self.client.as_ref().is_some_and(|client| client.received == client.data.len())
                    && !self.connections.iter().any(|((_, remote), connection)| {
                        Some(*remote) == connect && connection.state != TCPState::TimeWait
                    })
                {
                    return Ok(());
                }
            }
        }

        /// Opens the client's connection to `remote`.
        pub fn connect(&mut self, remote: IPEndpoint, bytes: usize) -> std::io::Result<()> {
            let address = match remote.address {
                IPAddress::V4(_) => IPAddress::V4(self.v4),
                IPAddress::V6(_) => IPAddress::V6(self.v6),
            };
            let local = IPEndpoint { address, port: 50000 };
            let now = self.now();
            let connection =
                TCPConnection::connect(self.tcp, local, remote, self.isn.generate(local, remote, now), now)
                    .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
            self.connections.insert((local, remote), connection);
            let data = (0..bytes).map(|index| (index * 7 % 251) as u8).collect();
            self.client = Some(Client { remote, data, sent: 0, received: 0, started: StdInstant::now() });
            self.transmit()
        }

        /// One packet from the kernel.
        pub fn receive(&mut self, packet: &[u8]) -> std::io::Result<()> {
            let now = self.now();
            match packet.first().map(|byte| byte >> 4) {
                Some(IPv4Header::VERSION) => {
                    let Ok((header, payload)) = IPv4Header::decode(packet) else { return Ok(()) };
                    // This host does not reassemble: fragments are dropped.
                    if header.destination != self.v4 || header.more_fragments || header.fragment_offset != 0 {
                        return Ok(());
                    }
                    let (source, destination) = (IPAddress::V4(header.source), IPAddress::V4(header.destination));
                    match header.protocol {
                        IPProtocol::ICMP => {
                            if let Some(reply) =
                                ICMPv4Message::decode(payload).ok().and_then(|request| request.echo_reply())
                            {
                                let mut out = Buffer::new();
                                reply.encode(&mut out).map_err(std::io::Error::other)?;
                                self.send(destination, source, IPProtocol::ICMP, out.as_slice(), false)?;
                            }
                        }
                        IPProtocol::UDP => self.receive_udp(payload, source, destination)?,
                        IPProtocol::TCP => self.receive_tcp(payload, source, destination, header.ecn == 3, now)?,
                        _ => {}
                    }
                }
                Some(IPv6Header::VERSION) => {
                    let Ok((header, payload)) = IPv6Header::decode(packet) else { return Ok(()) };
                    // Extension headers (such as the hop-by-hop options of MLD) are not followed.
                    if header.destination != self.v6 {
                        return Ok(());
                    }
                    let (source, destination) = (IPAddress::V6(header.source), IPAddress::V6(header.destination));
                    match header.next_header {
                        IPProtocol::ICMPV6 => {
                            let request = ICMPv6Message::decode(payload, header.source, header.destination);
                            if let Some(reply) = request.ok().and_then(|request| request.echo_reply()) {
                                let mut out = Buffer::new();
                                reply
                                    .encode(header.destination, header.source, &mut out)
                                    .map_err(std::io::Error::other)?;
                                self.send(destination, source, IPProtocol::ICMPV6, out.as_slice(), false)?;
                            }
                        }
                        IPProtocol::UDP => self.receive_udp(payload, source, destination)?,
                        IPProtocol::TCP => self.receive_tcp(payload, source, destination, header.ecn == 3, now)?,
                        _ => {}
                    }
                }
                _ => {}
            }
            Ok(())
        }

        /// A UDP datagram: echoed if it is for the echo port.
        pub fn receive_udp(
            &mut self,
            payload: &[u8],
            source: IPAddress,
            destination: IPAddress,
        ) -> std::io::Result<()> {
            let Ok(datagram) = UDPDatagram::decode(payload, source, destination, &self.udp) else { return Ok(()) };
            if datagram.destination_port != Host::ECHO {
                return Ok(());
            }
            let mut out = Buffer::new();
            datagram
                .reply(datagram.payload)
                .encode(destination, source, &self.udp, &mut out)
                .map_err(std::io::Error::other)?;
            self.send(destination, source, IPProtocol::UDP, out.as_slice(), false)
        }

        /// A TCP segment: to its connection, to the listener, or answered with a reset.
        pub fn receive_tcp(
            &mut self,
            payload: &[u8],
            source: IPAddress,
            destination: IPAddress,
            ce: bool,
            now: Instant,
        ) -> std::io::Result<()> {
            let Ok(segment) = TCPSegment::decode(payload, source, destination) else { return Ok(()) };
            let local = IPEndpoint { address: destination, port: segment.destination_port };
            let remote = IPEndpoint { address: source, port: segment.source_port };
            if let Some(connection) = self.connections.get_mut(&(local, remote)) {
                // RFC 6191: a new SYN may take the place of a connection in TIME-WAIT.
                if !(connection.state == TCPState::TimeWait && connection.accepts_syn(&segment)) {
                    connection.receive(&segment, ce, now);
                    return Ok(());
                }
                self.connections.remove(&(local, remote));
            }
            if self.listener.matches(local) {
                self.listener.receive(&segment, local, remote, ce, now);
                while let Some(connection) = self.listener.accept() {
                    self.connections.insert((connection.local, connection.remote), connection);
                }
            } else if let Some(reset) = segment.reset_reply() {
                // RFC 9293 §3.10.7.1: no connection and no listener.
                let mut out = Buffer::new();
                reset.encode(destination, source, &mut out).map_err(std::io::Error::other)?;
                self.send(destination, source, IPProtocol::TCP, out.as_slice(), false)?;
            }
            Ok(())
        }

        /// Sends what the listener and the connections have, and serves the events of the connections.
        pub fn transmit(&mut self) -> std::io::Result<()> {
            let now = self.now();
            let mut out = Buffer::new();
            while let Some((local, remote, sent)) =
                self.listener.transmit(now, &mut out).map_err(std::io::Error::other)?
            {
                self.send(local.address, remote.address, IPProtocol::TCP, out.as_slice(), sent.ect)?;
                out.clear();
            }
            while let Some(connection) = self.listener.accept() {
                self.connections.insert((connection.local, connection.remote), connection);
            }
            let keys: Vec<(IPEndpoint, IPEndpoint)> = self.connections.keys().copied().collect();
            for key in keys {
                self.serve(key)?;
                let Some(connection) = self.connections.get_mut(&key) else { continue };
                let mut segments = Vec::new();
                while let Some(sent) = connection.transmit(now, &mut out).map_err(std::io::Error::other)? {
                    segments.push((out.as_slice().to_vec(), sent.ect));
                    out.clear();
                }
                let closed = connection.state == TCPState::Closed;
                for (segment, ect) in segments {
                    self.send(key.0.address, key.1.address, IPProtocol::TCP, &segment, ect)?;
                }
                if closed {
                    self.connections.remove(&key);
                }
            }
            Ok(())
        }

        /// The events of a connection: an echo connection sends back what it reads and closes
        /// when its peer does; the client sends its data and checks what comes back.
        pub fn serve(&mut self, key: (IPEndpoint, IPEndpoint)) -> std::io::Result<()> {
            let Some(connection) = self.connections.get_mut(&key) else { return Ok(()) };
            let client = self.client.as_mut().filter(|client| client.remote == key.1);
            let mut buffer = [0u8; 16384];
            while let Some(event) = connection.poll_event() {
                if let TCPEvent::Closed(reason) = event {
                    println!("{} closed: {reason:?}", key.1);
                }
            }
            match client {
                None => {
                    loop {
                        let room = connection.writable().min(buffer.len());
                        let count = if room == 0 { 0 } else { connection.read(&mut buffer[..room]) };
                        if count == 0 {
                            break;
                        }
                        let _ = connection.send(&buffer[..count]);
                    }
                    // The peer closed and everything it sent was echoed: close too.
                    if connection.state == TCPState::CloseWait && connection.readable() == 0 {
                        let _ = connection.close();
                    }
                }
                Some(client) => {
                    if client.sent < client.data.len() && connection.state.can_send() {
                        client.sent += connection.send(&client.data[client.sent..]).unwrap_or(0);
                    }
                    loop {
                        let count = connection.read(&mut buffer);
                        if count == 0 {
                            break;
                        }
                        let expected = client.data.get(client.received..client.received + count);
                        if expected != Some(&buffer[..count]) {
                            return Err(std::io::Error::other(format!("byte {} differs", client.received)));
                        }
                        client.received += count;
                    }
                    if client.received == client.data.len() && connection.state == TCPState::Established {
                        let seconds = client.started.elapsed().as_secs_f64();
                        println!("{} bytes echoed by {} in {seconds:.3} s", client.received, client.remote);
                        let _ = connection.close();
                    }
                }
            }
            Ok(())
        }

        /// Sends `payload` of `protocol` from `source` to `destination` in an IP packet.
        pub fn send(
            &mut self,
            source: IPAddress,
            destination: IPAddress,
            protocol: IPProtocol,
            payload: &[u8],
            ect: bool,
        ) -> std::io::Result<()> {
            let mut packet = Buffer::new();
            match (source, destination) {
                (IPAddress::V4(source), IPAddress::V4(destination)) => {
                    let mut header =
                        IPv4Header::new(source, destination, protocol, payload.len()).map_err(std::io::Error::other)?;
                    self.identification = self.identification.wrapping_add(1);
                    header.identification = self.identification;
                    // No DF: this host passes no ICMP errors to TCP, so it does not discover the path MTU.
                    header.ecn = if ect { 2 } else { 0 };
                    header.encode(&mut packet).map_err(std::io::Error::other)?;
                }
                (IPAddress::V6(source), IPAddress::V6(destination)) => {
                    let mut header =
                        IPv6Header::new(source, destination, protocol, payload.len()).map_err(std::io::Error::other)?;
                    header.ecn = if ect { 2 } else { 0 };
                    header.encode(&mut packet).map_err(std::io::Error::other)?;
                }
                _ => return Ok(()),
            }
            packet.write(payload).map_err(std::io::Error::other)?;
            match self.device.send(packet.as_slice()) {
                // The interface is down (EIO): the packet is lost, as on a link, and TCP sends it again.
                Err(error) if error.raw_os_error() == Some(Linux::EIO) => Ok(()),
                result => result.map(|_| ()),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let options = match Options::parse() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let result = host::Host::new(&options).and_then(|mut host| host.run(options.connect, options.bytes));
    if let Err(error) = result {
        eprintln!("tun: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tun: TUN interfaces are those of the Linux kernel");
    std::process::exit(2);
}
