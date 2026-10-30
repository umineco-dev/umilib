//! A QUIC client and server over UDP, to try umilib's QUIC against other
//! implementations (`examples/quic.sh` runs it against curl and OpenSSL).
//!
//! ```text
//! quic server PORT --cert FILE --key FILE [--alpn h3,...] [--version 1|2] [--retry] [--connections N]
//!                   [--sink]
//! quic client HOST PORT [--name NAME] [--alpn ...] [--ca FILE | --insecure] [--version 1|2] [--send TEXT]
//!                   [--datagram TEXT]
//! ```
//!
//! The server echoes each stream back on the same stream, and each DATAGRAM
//! frame back as one; with `--sink` it reads and never answers. Each connection prints what was negotiated, one
//! `key: value` per line. It needs the operating system's random source:
//! Linux, Android, the Apple platforms and Windows.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports, dead_code)
)]

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant as Clock, SystemTime, UNIX_EPOCH};

use umilib::auth::cert::key::{KeyLimits, PrivateKey};
use umilib::auth::cert::path::{ServiceIdentity, TrustAnchor};
use umilib::auth::cert::x509::Certificate;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::native::Random;
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address, IPv6Address};
use umilib::protocol::quic::{
    QUICCloseReason, QUICConfig, QUICECN, QUICEndpoint, QUICEndpointConfig, QUICEvent, QUICStreamID, QUICVersion,
};
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertificateVerifier, TLSCertifiedKey, TLSClientConfig, TLSPathVerifier, TLSServerConfig,
};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 3] = ["--insecure", "--retry", "--sink"];

    pub fn parse() -> Arguments {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if !argument.starts_with("--") {
                positional.push(argument);
            } else if Arguments::FLAGS.contains(&argument.as_str()) {
                options.push((argument, None));
            } else {
                let value = arguments.next().unwrap_or_else(|| Tool::fail(&format!("{argument} needs a value")));
                options.push((argument, Some(value)));
            }
        }
        Arguments { positional, options }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(option, _)| option == name).and_then(|(_, value)| value.as_deref())
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }
}

/// A verifier that accepts any certificate, for `--insecure`.
#[derive(Debug)]
pub struct Insecure;

impl TLSCertificateVerifier for Insecure {
    fn verify(
        &self,
        _chain: &[Vec<u8>],
        _identity: Option<&ServiceIdentity>,
        _ocsp: Option<&[u8]>,
        _time: i64,
    ) -> Result<(), TLSAlertDescription> {
        Ok(())
    }
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    pub fn time() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs() as i64)
    }

    /// The connection's clock: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    pub fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")))
    }

    pub fn protocols(arguments: &Arguments) -> Vec<Vec<u8>> {
        arguments.get("--alpn").unwrap_or("echo").split(',').map(|protocol| protocol.as_bytes().to_vec()).collect()
    }

    pub fn config(arguments: &Arguments) -> QUICConfig {
        let mut config = QUICConfig { max_datagram_frame_size: 1200, ..QUICConfig::default() };
        if let Some(version) = arguments.get("--version") {
            config.versions = vec![match version {
                "1" => QUICVersion::V1,
                "2" => QUICVersion::V2,
                _ => Tool::fail("--version: 1 or 2"),
            }];
        }
        config
    }

    pub fn endpoint(address: SocketAddr) -> IPEndpoint {
        let address_bytes = match address {
            SocketAddr::V4(address) => IPAddress::V4(IPv4Address(address.ip().octets())),
            SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
                Some(mapped) => IPAddress::V4(IPv4Address(mapped.octets())),
                None => IPAddress::V6(IPv6Address(address.ip().octets())),
            },
        };
        IPEndpoint::new(address_bytes, address.port())
    }

    /// The address to send to from `socket`: an IPv4 one mapped into IPv6
    /// for a socket of IPv6 (RFC 4291 §2.5.5.2), which takes both.
    pub fn socket_address(endpoint: &IPEndpoint, socket: &UdpSocket) -> SocketAddr {
        let six = socket.local_addr().is_ok_and(|address| address.is_ipv6());
        match endpoint.address {
            IPAddress::V4(address) if six => {
                SocketAddr::from((std::net::Ipv4Addr::from(address.0).to_ipv6_mapped(), endpoint.port))
            }
            IPAddress::V4(address) => SocketAddr::from((address.0, endpoint.port)),
            IPAddress::V6(address) => SocketAddr::from((address.0, endpoint.port)),
        }
    }

    /// Moves datagrams between `endpoint` and `socket` for `budget`, or
    /// until `done` holds; `act` runs after each datagram or timer.
    pub fn pump(
        endpoint: &mut QUICEndpoint,
        socket: &UdpSocket,
        start: Clock,
        budget: Duration,
        mut act: impl FnMut(&mut QUICEndpoint, Instant) -> bool,
    ) {
        let deadline = Clock::now() + budget;
        let mut buffer = vec![0u8; 65536];
        let mut out = Vec::new();
        while Clock::now() < deadline {
            let now = Tool::now(start);
            while let Some(transmission) = endpoint.transmit(now, &mut out) {
                let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination, socket));
            }
            let wait = endpoint
                .poll_timeout()
                .map(|timeout| Duration::from_nanos(timeout.as_nanos().saturating_sub(now.as_nanos())))
                .unwrap_or(Duration::from_millis(50))
                .clamp(Duration::from_millis(1), Duration::from_millis(50));
            socket.set_read_timeout(Some(wait)).expect("a timeout");
            match socket.recv_from(&mut buffer) {
                Ok((count, from)) => {
                    let now = Tool::now(start);
                    endpoint.receive(&buffer[..count], Tool::endpoint(from), QUICECN::NotECT, now, Tool::time());
                }
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => Tool::fail(&format!("receive: {error}")),
            }
            let now = Tool::now(start);
            if endpoint.poll_timeout().is_some_and(|timeout| timeout <= now) {
                endpoint.expire(now, Tool::time());
            }
            if act(endpoint, now) {
                let now = Tool::now(start);
                while let Some(transmission) = endpoint.transmit(now, &mut out) {
                    let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination, socket));
                }
                return;
            }
        }
    }

    pub fn closed(reason: &QUICCloseReason) -> String {
        match reason {
            QUICCloseReason::Local { error, reason } => {
                format!("local transport {:#x} {}", error.0, String::from_utf8_lossy(reason))
            }
            QUICCloseReason::Peer { error, reason } => {
                format!("peer transport {:#x} {}", error.0, String::from_utf8_lossy(reason))
            }
            QUICCloseReason::LocalApplication { error, reason } => {
                format!("local application {error:#x} {}", String::from_utf8_lossy(reason))
            }
            QUICCloseReason::PeerApplication { error, reason } => {
                format!("peer application {error:#x} {}", String::from_utf8_lossy(reason))
            }
            other => format!("{other:?}"),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("server") => server(&arguments),
        Some("client") => client(&arguments),
        _ => Tool::fail("usage: quic server PORT ... | quic client HOST PORT ..."),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    Tool::fail("this platform has no random source for the example");
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn server(arguments: &Arguments) {
    let port = arguments.positional.get(1).unwrap_or_else(|| Tool::fail("the port"));
    let (certificate, key) = match (arguments.get("--cert"), arguments.get("--key")) {
        (Some(certificate), Some(key)) => (certificate, key),
        _ => Tool::fail("--cert and --key"),
    };
    let chain = Certificate::from_pem_all(&Tool::read(certificate))
        .unwrap_or_else(|error| Tool::fail(&format!("{certificate}: {error:?}")))
        .iter()
        .map(|certificate| certificate.to_der().expect("a certificate writes"))
        .collect();
    let key = PrivateKey::from_pem(&Tool::read(key)).unwrap_or_else(|error| Tool::fail(&format!("{key}: {error:?}")));
    let mut tls = TLSServerConfig::new(vec![Arc::new(TLSCertifiedKey { chain, key, ocsp: None })]);
    tls.config.protocols = Tool::protocols(arguments);
    let mut config = QUICEndpointConfig::new(Arc::new(Tool::config(arguments)), Some(Arc::new(tls)));
    let mut token_key = [0u8; 32];
    umilib::crypto::random::Random::fill(&mut Random, &mut token_key).expect("random bytes");
    config.token_key = Some(token_key);
    config.retry = arguments.has("--retry");
    let mut endpoint = QUICEndpoint::new(config, Box::new(Random)).expect("an endpoint");
    let socket = UdpSocket::bind(("::", port.parse::<u16>().unwrap_or_else(|_| Tool::fail("a port"))))
        .or_else(|_| UdpSocket::bind(("0.0.0.0", port.parse::<u16>().unwrap_or(0))))
        .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
    println!("listening: {}", socket.local_addr().expect("an address"));
    let wanted: usize = arguments.get("--connections").map_or(1, |count| count.parse().unwrap_or(1));
    let start = Clock::now();
    let mut connections = Vec::new();
    let mut finished = 0;
    let mut echoed: BTreeMap<(u64, u64), bool> = BTreeMap::new();
    let sink = arguments.has("--sink");
    Tool::pump(&mut endpoint, &socket, start, Duration::from_secs(3600), |endpoint, now| {
        while let Some(handle) = endpoint.accept() {
            connections.push(handle);
        }
        for handle in connections.clone() {
            let Some(connection) = endpoint.connection(handle) else { continue };
            while let Some(event) = connection.poll_event() {
                match event {
                    QUICEvent::Connected => {
                        println!("connected: {handle}");
                        println!("version: {:#x}", connection.version.0);
                        let protocol = connection.tls.session.protocol.clone().unwrap_or_default();
                        println!("alpn: {}", String::from_utf8_lossy(&protocol));
                        println!("retry: {}", connection.retry_source.is_some());
                    }
                    QUICEvent::StreamReadable { stream } => {
                        let mut buffer = vec![0u8; 65536];
                        while let Ok((count, fin)) = connection.stream_read(stream, &mut buffer) {
                            if count > 0 {
                                println!("stream {}: {} bytes", stream.0, count);
                            }
                            // Echo on the stream itself when it is bidirectional.
                            if stream.is_bidirectional() && !sink {
                                let _ = connection.stream_send(stream, &buffer[..count], fin);
                            }
                            if fin {
                                echoed.insert((handle, stream.0), true);
                            }
                            if count == 0 || fin {
                                break;
                            }
                        }
                    }
                    QUICEvent::Datagram => {
                        while let Some(datagram) = connection.read_datagram() {
                            println!("datagram: {}", String::from_utf8_lossy(&datagram));
                            let _ = connection.send_datagram(&datagram);
                        }
                    }
                    QUICEvent::Closed { reason } => {
                        println!("closed: {handle} {}", Tool::closed(&reason));
                        finished += 1;
                    }
                    _ => {}
                }
            }
            let _ = now;
        }
        finished >= wanted
    });
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn client(arguments: &Arguments) {
    let host = arguments.positional.get(1).unwrap_or_else(|| Tool::fail("the host"));
    let port = arguments.positional.get(2).unwrap_or_else(|| Tool::fail("the port"));
    let address = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .unwrap_or_else(|| Tool::fail("an address"));
    let verifier: Arc<dyn TLSCertificateVerifier> = match (arguments.get("--ca"), arguments.has("--insecure")) {
        (Some(path), _) => {
            let anchors = Certificate::from_pem_all(&Tool::read(path))
                .unwrap_or_else(|error| Tool::fail(&format!("{path}: {error:?}")))
                .into_iter()
                .map(|certificate| {
                    TrustAnchor::from_certificate(certificate, &KeyLimits::default()).expect("an anchor")
                })
                .collect();
            Arc::new(TLSPathVerifier::servers(anchors))
        }
        (None, true) => Arc::new(Insecure),
        (None, false) => Tool::fail("--ca FILE or --insecure"),
    };
    let mut tls = TLSClientConfig::new(verifier);
    tls.config.protocols = Tool::protocols(arguments);
    let name = arguments.get("--name").unwrap_or(host);
    let socket = UdpSocket::bind(if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
    let config = QUICEndpointConfig::new(Arc::new(Tool::config(arguments)), None);
    let mut endpoint = QUICEndpoint::new(config, Box::new(Random)).expect("an endpoint");
    let start = Clock::now();
    let handle = endpoint
        .connect(
            Arc::new(tls),
            Some(name),
            Tool::endpoint(address),
            None,
            Box::new(Random),
            Tool::now(start),
            Tool::time(),
        )
        .unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
    let send = arguments.get("--send").unwrap_or("hello").as_bytes().to_vec();
    let datagram = arguments.get("--datagram").map(|text| text.as_bytes().to_vec());
    let mut stream: Option<QUICStreamID> = None;
    let mut received = Vec::new();
    let mut datagram_back = datagram.is_none();
    let mut done = false;
    Tool::pump(&mut endpoint, &socket, start, Duration::from_secs(10), |endpoint, now| {
        let Some(connection) = endpoint.connection(handle) else { return true };
        while let Some(event) = connection.poll_event() {
            match event {
                QUICEvent::Connected => {
                    println!("connected: yes");
                    println!("version: {:#x}", connection.version.0);
                    let protocol = connection.tls.session.protocol.clone().unwrap_or_default();
                    println!("alpn: {}", String::from_utf8_lossy(&protocol));
                    let opened = connection.open_stream(true).expect("a stream");
                    connection.stream_send(opened, &send, true).expect("data goes out");
                    stream = Some(opened);
                    if let Some(datagram) = &datagram {
                        let _ = connection.send_datagram(datagram);
                    }
                }
                QUICEvent::StreamReadable { stream: readable } if Some(readable) == stream => {
                    let mut buffer = vec![0u8; 65536];
                    while let Ok((count, fin)) = connection.stream_read(readable, &mut buffer) {
                        received.extend_from_slice(&buffer[..count]);
                        if fin {
                            println!("echo: {}", String::from_utf8_lossy(&received));
                            done = true;
                        }
                        if count == 0 || fin {
                            break;
                        }
                    }
                }
                QUICEvent::Datagram => {
                    while let Some(back) = connection.read_datagram() {
                        println!("datagram: {}", String::from_utf8_lossy(&back));
                        datagram_back = true;
                    }
                }
                QUICEvent::Closed { reason } => {
                    println!("closed: {}", Tool::closed(&reason));
                    return true;
                }
                _ => {}
            }
        }
        if done && datagram_back {
            let _ = connection.close(0, b"done", now);
            done = false;
        }
        false
    });
}
