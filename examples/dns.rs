//! A DNS server, resolver and key generator, to try umilib's DNS against
//! other implementations (`examples/dns.sh` runs it against dig, delv,
//! kdig and Unbound).
//!
//! ```text
//! dns server PORT ZONE ORIGIN [--sign KEY[:FLAGS]]... [--cert FILE --key FILE] [--transfers] [--address ADDRESS]
//! dns keygen ALGORITHM ORIGIN FILE [--flags FLAGS]
//! dns resolve HOST PORT NAME TYPE [--transport udp|tcp|tls|https|quic] [--post] [--name NAME]
//!             [--ca FILE | --insecure] [--dnssec] [--anchor FILE]
//! ```
//!
//! The server answers for the zone of the zone file `ZONE` at `ORIGIN` over
//! UDP and TCP on `PORT` of `ADDRESS` (127.0.0.1 if not given), signed with
//! each `--sign` private key (flags 257 if not given, an NSEC chain, valid
//! for a week); with a certificate, over TLS (ALPN `dot`, TCP), HTTPS (ALPN
//! `h2` on the same port, `/dns-query`) and QUIC (ALPN `doq`, UDP) on
//! `PORT + 1`. Its server cookies are of a secret of the run (RFC 9018).
//! `--transfers` lets every client transfer the zone. Each query prints a
//! line `query: TRANSPORT NAME TYPE`.
//!
//! `keygen` writes a new private key of `ALGORITHM` (its number) to `FILE`,
//! and prints its DNSKEY and its DS of SHA-256.
//!
//! `resolve` asks the server (over HTTPS with GET, or POST with `--post`) and prints `rcode: CODE`, the answers one a
//! line, and with `--dnssec` `status: secure` or `status: insecure`; a
//! failure prints `error: …` (a bogus answer `error: bogus CODE …`). Its
//! trust anchor is the root's, or with `--anchor` the DS records of the
//! zone file `FILE`. It needs the operating system's random source: Linux,
//! Android, the Apple platforms and Windows.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports, dead_code)
)]

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant as Clock, SystemTime, UNIX_EPOCH};

use umilib::auth::cert::key::{KeyLimits, PrivateKey};
use umilib::auth::cert::path::{ServiceIdentity, TrustAnchor};
use umilib::auth::cert::x509::Certificate;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::native::Random;
use umilib::protocol::dns::dnssec::{
    DNSSECAlgorithm, DNSSECConfig, DNSSECDigest, DNSSECKeyDigest, DNSSECPrivateKey, DNSSECResolver,
    DNSSECResolverEvent, DNSSECSigner, DNSSECStatus, DNSSECTrustAnchor,
};
use umilib::protocol::dns::https::DNSHTTPS;
use umilib::protocol::dns::quic::{DNSQUICConnection, DNSQUICEvent};
use umilib::protocol::dns::tcp::{DNSTCPFramer, DNSTCPServer, DNSTCPServerConfig};
use umilib::protocol::dns::tls::DNSTLS;
use umilib::protocol::dns::{
    DNSAuthority, DNSAuthorityConfig, DNSData, DNSError, DNSMessage, DNSName, DNSPeer, DNSQuestion, DNSResolver,
    DNSResolverConfig, DNSResolverEvent, DNSTransmission, DNSTransport, DNSType, DNSUpstream, DNSZone, DNSZoneFile,
};
use umilib::protocol::http::v2::{H2Config, H2Connection};
use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPResponse, HTTPStatus, HTTPStreamID};
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPEndpointPattern, IPv4Address, IPv6Address};
use umilib::protocol::quic::{QUICConfig, QUICECN, QUICEndpoint, QUICEndpointConfig, QUICRole, QUICStreamID};
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertificateVerifier, TLSCertifiedKey, TLSClientConfig, TLSConnection, TLSPathVerifier,
    TLSServerConfig,
};
use umilib::runtime::Instant;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 4] = ["--insecure", "--dnssec", "--transfers", "--post"];

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

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.options.iter().filter(|(option, _)| option == name).filter_map(|(_, value)| value.as_deref()).collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
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
    /// How long a resolution may take.
    pub const BUDGET: Duration = Duration::from_secs(20);

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    pub fn time() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs() as i64)
    }

    /// The clock of the state machines: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    pub fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")))
    }

    pub fn name(text: &str) -> DNSName {
        let text = if text.ends_with('.') { text.to_string() } else { format!("{text}.") };
        DNSName::parse(&text, None).unwrap_or_else(|error| Tool::fail(&format!("{text}: {error}")))
    }

    pub fn kind(text: &str) -> DNSType {
        DNSType::parse(&text.to_ascii_uppercase()).unwrap_or_else(|error| Tool::fail(&format!("{text}: {error}")))
    }

    /// The records of the zone file `path`, relative names of `origin`.
    pub fn records(path: &str, origin: &DNSName) -> Vec<umilib::protocol::dns::DNSRecord> {
        DNSZoneFile::new(Some(origin.clone()))
            .parse(&Tool::read(path))
            .unwrap_or_else(|error| Tool::fail(&format!("{path}: line {}: {}", error.line, error.error)))
    }

    pub fn certified(arguments: &Arguments) -> Option<TLSCertifiedKey> {
        let (certificate, key) = (arguments.get("--cert")?, arguments.get("--key")?);
        let chain = Certificate::from_pem_all(&Tool::read(certificate))
            .unwrap_or_else(|error| Tool::fail(&format!("{certificate}: {error:?}")))
            .iter()
            .map(|certificate| certificate.to_der().expect("a certificate writes"))
            .collect();
        let key =
            PrivateKey::from_pem(&Tool::read(key)).unwrap_or_else(|error| Tool::fail(&format!("{key}: {error:?}")));
        Some(TLSCertifiedKey { chain, key, ocsp: None })
    }

    pub fn verifier(arguments: &Arguments) -> Arc<dyn TLSCertificateVerifier> {
        match (arguments.get("--ca"), arguments.has("--insecure")) {
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
        }
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

    pub fn socket_address(endpoint: &IPEndpoint) -> SocketAddr {
        match endpoint.address {
            IPAddress::V4(address) => SocketAddr::from((address.0, endpoint.port)),
            IPAddress::V6(address) => SocketAddr::from((address.0, endpoint.port)),
        }
    }

    pub fn transport_name(transport: DNSTransport) -> &'static str {
        match transport {
            DNSTransport::UDP => "udp",
            DNSTransport::TCP => "tcp",
            DNSTransport::TLS => "tls",
            DNSTransport::HTTPS => "https",
            DNSTransport::QUIC => "quic",
        }
    }

    /// Prints the question of a query received.
    pub fn log(transport: DNSTransport, query: &[u8]) {
        if let Some(question) = DNSMessage::decode(query).ok().and_then(|message| message.question().cloned()) {
            println!("query: {} {} {}", Tool::transport_name(transport), question.name, question.kind);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("server") => Server::run(&arguments),
        Some("keygen") => keygen(&arguments),
        Some("resolve") => Client::run(&arguments),
        _ => {
            Tool::fail("usage: dns server PORT ZONE ORIGIN ... | dns keygen ... | dns resolve HOST PORT NAME TYPE ...")
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    Tool::fail("this platform has no random source for the example");
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn keygen(arguments: &Arguments) {
    let algorithm = DNSSECAlgorithm(arguments.position(1, "the algorithm").parse().unwrap_or(0));
    let origin = Tool::name(arguments.position(2, "the origin"));
    let path = arguments.position(3, "the file");
    let flags = arguments.get("--flags").map_or(257, |flags| flags.parse().unwrap_or(257));
    let bits = if algorithm.is_rsa() { 2048 } else { 0 };
    let key = DNSSECPrivateKey::generate(algorithm, bits, &mut Random)
        .unwrap_or_else(|error| Tool::fail(&format!("generate: {error}")));
    std::fs::write(path, key.format()).unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")));
    let signer = DNSSECSigner::new(origin, flags, key);
    println!("{}", signer.dnskey(3600));
    if let Some(ds) = signer.delegation(DNSSECDigest::SHA256, 3600) {
        println!("{ds}");
    }
}

/// The server: UDP and TCP, and with a certificate TLS and QUIC.
pub struct Server;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Server {
    pub fn run(arguments: &Arguments) {
        let port: u16 = arguments.position(1, "the port").parse().unwrap_or_else(|_| Tool::fail("a port"));
        let origin = Tool::name(arguments.position(3, "the origin"));
        let records = Tool::records(arguments.position(2, "the zone file"), &origin);
        let mut zone =
            DNSZone::new(origin.clone(), records).unwrap_or_else(|error| Tool::fail(&format!("zone: {error}")));
        let signers: Vec<DNSSECSigner> = arguments
            .all("--sign")
            .iter()
            .map(|argument| {
                let (path, flags) = argument.split_once(':').unwrap_or((argument, "257"));
                let key = DNSSECPrivateKey::parse(&Tool::read(path))
                    .unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")));
                DNSSECSigner::new(origin.clone(), flags.parse().unwrap_or(257), key)
            })
            .collect();
        if !signers.is_empty() {
            let time = Tool::time() as u32;
            zone = zone
                .sign(&signers, time - 3600, time + 7 * 86_400, &mut Random)
                .unwrap_or_else(|error| Tool::fail(&format!("sign: {error}")));
        }
        let mut config = DNSAuthorityConfig::default();
        // Server cookies (RFC 7873, RFC 9018) of a secret of this run.
        let mut secret = [0u8; 16];
        umilib::crypto::random::Random::fill(&mut Random, &mut secret).expect("random bytes");
        config.cookie_secrets = vec![secret];
        if arguments.has("--transfers") {
            config.transfers = vec![IPEndpointPattern::ANY];
        }
        let authority = Arc::new(DNSAuthority::new(vec![zone], config));
        let address = arguments.get("--address").unwrap_or("127.0.0.1");
        let udp = UdpSocket::bind((address, port)).unwrap_or_else(|error| Tool::fail(&format!("bind UDP: {error}")));
        let tcp = TcpListener::bind((address, port)).unwrap_or_else(|error| Tool::fail(&format!("bind TCP: {error}")));
        if let Some(key) = Tool::certified(arguments) {
            let key = Arc::new(key);
            let tls = TcpListener::bind((address, port + 1))
                .unwrap_or_else(|error| Tool::fail(&format!("bind TLS: {error}")));
            let quic =
                UdpSocket::bind((address, port + 1)).unwrap_or_else(|error| Tool::fail(&format!("bind QUIC: {error}")));
            let (tls_authority, tls_key) = (authority.clone(), key.clone());
            std::thread::spawn(move || Server::streams(tls, tls_authority, Some(tls_key)));
            let quic_authority = authority.clone();
            std::thread::spawn(move || Server::quic(quic, quic_authority, key));
            println!("listening: tls and quic {address}:{}", port + 1);
        }
        let tcp_authority = authority.clone();
        std::thread::spawn(move || Server::streams(tcp, tcp_authority, None));
        println!("listening: udp and tcp {address}:{port}");
        Server::udp(udp, &authority);
    }

    pub fn udp(socket: UdpSocket, authority: &DNSAuthority) {
        let mut buffer = vec![0u8; 65536];
        loop {
            let Ok((count, from)) = socket.recv_from(&mut buffer) else { continue };
            Tool::log(DNSTransport::UDP, &buffer[..count]);
            let peer = DNSPeer { endpoint: Tool::endpoint(from), transport: DNSTransport::UDP };
            for response in authority.respond(&buffer[..count], &peer, Tool::time() as u32) {
                let _ = socket.send_to(&response, from);
            }
        }
    }

    /// Serves the connections of `listener`, over TLS with `key`, a thread each.
    pub fn streams(listener: TcpListener, authority: Arc<DNSAuthority>, key: Option<Arc<TLSCertifiedKey>>) {
        let config = key.map(|key| {
            let mut config = TLSServerConfig::new(vec![key]);
            config.config.protocols = vec![b"dot".to_vec(), b"h2".to_vec()];
            Arc::new(config)
        });
        for stream in listener.incoming().flatten() {
            let (authority, config) = (authority.clone(), config.clone());
            std::thread::spawn(move || Server::connection(stream, &authority, config));
        }
    }

    /// Answers the queries of a connection, over TLS with `config`: the
    /// framing of [`DNSTCPServer`], over the plaintext of TLS if any.
    pub fn connection(mut stream: TcpStream, authority: &DNSAuthority, config: Option<Arc<TLSServerConfig>>) {
        let start = Clock::now();
        let Ok(from) = stream.peer_addr() else { return };
        let transport = if config.is_some() { DNSTransport::TLS } else { DNSTransport::TCP };
        let peer = DNSPeer { endpoint: Tool::endpoint(from), transport };
        let mut tls =
            config.map(|config| TLSConnection::server(config, Box::new(Random), Tool::time()).expect("a TLS server"));
        let mut dns = DNSTCPServer::new(DNSTCPServerConfig::default(), peer, Tool::now(start));
        // HTTP/2 once TLS negotiates `h2` (RFC 8484 §5.2).
        let mut http: Option<HTTPSServer> = None;
        let mut buffer = vec![0u8; 65536];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        while !dns.is_idle(Tool::now(start)) {
            let count = match stream.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => count,
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
                Err(_) => return,
            };
            let plaintext = match &mut tls {
                Some(tls) => {
                    // The ALPN chooses DNS over TLS (`dot`, or none) or over HTTPS (`h2`).
                    let received = tls.receive(&buffer[..count]).is_ok();
                    while tls.poll_event().is_some() {}
                    let mut plaintext = Vec::new();
                    DNSTLS::read_all(tls, &mut plaintext);
                    if !received {
                        let mut out = Vec::new();
                        let _ = tls.transmit(&mut out);
                        let _ = stream.write_all(&out);
                        return;
                    }
                    plaintext
                }
                None => buffer[..count].to_vec(),
            };
            let negotiated =
                tls.as_ref().filter(|tls| !tls.is_handshaking()).and_then(|tls| tls.session.protocol.clone());
            if http.is_none() && negotiated.as_deref() == Some(b"h2") {
                let connection = H2Connection::server(H2Config::default(), Tool::now(start));
                http = Some(HTTPSServer { connection, requests: BTreeMap::new() });
            }
            let mut out = match &mut http {
                Some(https) => {
                    https.connection.receive(&plaintext, Tool::now(start));
                    https.answer(authority, from);
                    let mut out = Vec::new();
                    https.connection.transmit(&mut out);
                    out
                }
                None => {
                    let mut framer = DNSTCPFramer::new();
                    framer.receive(&dns.framer.buffer);
                    framer.receive(&plaintext);
                    while let Some(Ok(query)) = framer.next_message() {
                        Tool::log(transport, &query);
                    }
                    if dns.receive(&plaintext, authority, Tool::now(start), Tool::time() as u32).is_err() {
                        return;
                    }
                    dns.transmit()
                }
            };
            if let Some(tls) = &mut tls {
                if !out.is_empty() && tls.send(&out).is_err() {
                    return;
                }
                out.clear();
                let _ = tls.transmit(&mut out);
            }
            if !out.is_empty() && stream.write_all(&out).is_err() {
                return;
            }
        }
    }

    /// Serves DNS over QUIC on `socket`.
    pub fn quic(socket: UdpSocket, authority: Arc<DNSAuthority>, key: Arc<TLSCertifiedKey>) {
        let mut tls = TLSServerConfig::new(vec![key]);
        tls.config.protocols = vec![DNSQUICConnection::ALPN.to_vec()];
        let config = QUICEndpointConfig::new(Arc::new(QUICConfig::default()), Some(Arc::new(tls)));
        let mut endpoint = QUICEndpoint::new(config, Box::new(Random)).expect("an endpoint");
        let start = Clock::now();
        let mut connections: BTreeMap<u64, DNSQUICConnection> = BTreeMap::new();
        let mut buffer = vec![0u8; 65536];
        let mut out = Vec::new();
        loop {
            let now = Tool::now(start);
            while let Some(transmission) = endpoint.transmit(now, &mut out) {
                let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination));
            }
            let wait = endpoint
                .poll_timeout()
                .map(|timeout| Duration::from_nanos(timeout.as_nanos().saturating_sub(now.as_nanos())))
                .unwrap_or(Duration::from_millis(50))
                .clamp(Duration::from_millis(1), Duration::from_millis(50));
            socket.set_read_timeout(Some(wait)).expect("a timeout");
            if let Ok((count, from)) = socket.recv_from(&mut buffer) {
                let now = Tool::now(start);
                endpoint.receive(&buffer[..count], Tool::endpoint(from), QUICECN::NotECT, now, Tool::time());
            }
            let now = Tool::now(start);
            if endpoint.poll_timeout().is_some_and(|timeout| timeout <= now) {
                endpoint.expire(now, Tool::time());
            }
            while let Some(handle) = endpoint.accept() {
                connections.insert(handle, DNSQUICConnection::new(QUICRole::Server));
            }
            connections.retain(|handle, dns| {
                let Some(quic) = endpoint.connection(*handle) else { return false };
                let peer = DNSPeer { endpoint: quic.remote, transport: DNSTransport::QUIC };
                if dns.process(quic, now).is_err() {
                    return true;
                }
                while let Some(event) = dns.poll_event() {
                    if let DNSQUICEvent::Query { stream, message } = event {
                        Tool::log(DNSTransport::QUIC, &message);
                        let responses = authority.respond(&message, &peer, Tool::time() as u32);
                        let _ = dns.send_response(quic, stream, &responses);
                    }
                }
                true
            });
        }
    }
}

/// A server's HTTP/2 connection of DNS queries, and the requests of its streams so far.
pub struct HTTPSServer {
    pub connection: H2Connection,
    pub requests: BTreeMap<HTTPStreamID, HTTPSRequest>,
}

/// A request received and its content so far.
pub struct HTTPSRequest {
    pub request: umilib::protocol::http::HTTPRequest,
    pub content: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl HTTPSServer {
    /// Answers the DNS queries of an HTTP/2 connection (RFC 8484 §4.1, §4.2):
    /// GET and POST to any path, the status of what is not a query.
    pub fn answer(&mut self, authority: &DNSAuthority, from: SocketAddr) {
        let HTTPSServer { connection, requests } = self;
        let mut buffer = vec![0u8; 65536];
        while let Some(event) = connection.poll_event() {
            let stream = match event {
                HTTPEvent::Request { stream, request, end } => {
                    requests.insert(stream, HTTPSRequest { request, content: Vec::new() });
                    if !end {
                        continue;
                    }
                    stream
                }
                HTTPEvent::Data { stream } => {
                    while let Ok(count) = connection.read_data(stream, &mut buffer) {
                        if count == 0 {
                            break;
                        }
                        if let Some(exchange) = requests.get_mut(&stream) {
                            exchange.content.extend_from_slice(&buffer[..count]);
                        }
                    }
                    continue;
                }
                HTTPEvent::End { stream } => stream,
                _ => continue,
            };
            let Some(HTTPSRequest { request, content }) = requests.remove(&stream) else { continue };
            let peer = DNSPeer { endpoint: Tool::endpoint(from), transport: DNSTransport::HTTPS };
            let query = DNSHTTPS::query(&request, &content);
            let response = query.as_ref().ok().and_then(|query| {
                Tool::log(DNSTransport::HTTPS, query);
                authority.respond(query, &peer, Tool::time() as u32).into_iter().next()
            });
            match (query, response) {
                (Ok(_), Some(message)) => {
                    let head = DNSHTTPS::response(&message).unwrap_or_else(|_| HTTPResponse::new(HTTPStatus(500)));
                    let _ = connection.send_response(stream, &head, false);
                    let _ = connection.send_data(stream, &message, true);
                }
                (Ok(_), None) => {
                    let _ = connection.send_response(stream, &HTTPResponse::new(HTTPStatus::BAD_REQUEST), true);
                }
                (Err(status), _) => {
                    let _ = connection.send_response(stream, &HTTPResponse::new(status), true);
                }
            }
        }
    }
}

/// A client's connection over TCP, or TLS if `tls`: the queries it awaits, by ID.
pub struct StreamConnection {
    pub stream: TcpStream,
    pub tls: Option<TLSConnection>,
    pub framer: DNSTCPFramer,
    pub queries: BTreeMap<u16, u64>,
}

/// A client's HTTP/2 connection over TLS: the queries it awaits, by stream.
pub struct HTTPSConnection {
    pub stream: TcpStream,
    pub tls: TLSConnection,
    pub http: H2Connection,
    pub exchanges: BTreeMap<HTTPStreamID, HTTPSExchange>,
}

/// A query sent over HTTPS: the response's head and content so far.
pub struct HTTPSExchange {
    pub query: u64,
    pub head: Option<HTTPResponse>,
    pub content: Vec<u8>,
}

/// A client's QUIC connection: the queries it awaits, by stream.
pub struct QUICClientConnection {
    pub endpoint: QUICEndpoint,
    pub socket: UdpSocket,
    pub handle: u64,
    pub dns: DNSQUICConnection,
    pub streams: BTreeMap<QUICStreamID, u64>,
}

/// The connections of a resolution, one of each transport at most, and a
/// socket of a random port for each query over UDP (RFC 5452 §9.3).
pub struct Client {
    pub server: SocketAddr,
    pub name: String,
    pub verifier: Option<Arc<dyn TLSCertificateVerifier>>,
    pub start: Clock,
    pub datagrams: Vec<(u64, UdpSocket)>,
    pub tcp: Option<StreamConnection>,
    pub tls: Option<StreamConnection>,
    pub https: Option<HTTPSConnection>,
    pub post: bool,
    pub quic: Option<QUICClientConnection>,
    /// What arrived: the query, its transport and the response.
    pub arrived: Vec<(u64, DNSTransport, Vec<u8>)>,
}

/// The resolver of a resolution: validating or not.
pub enum Resolver {
    Stub(Box<DNSResolver>),
    Validating(Box<DNSSECResolver>),
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Resolver {
    pub fn transmit(&mut self) -> Option<DNSTransmission> {
        match self {
            Resolver::Stub(resolver) => resolver.transmit(),
            Resolver::Validating(resolver) => resolver.transmit(),
        }
    }

    pub fn receive(&mut self, query: u64, transport: DNSTransport, bytes: &[u8], now: Instant) {
        match self {
            Resolver::Stub(resolver) => resolver.receive(query, 0, transport, bytes, now, &mut Random),
            Resolver::Validating(resolver) => {
                resolver.receive(query, 0, transport, bytes, now, Tool::time() as u64, &mut Random)
            }
        }
    }

    pub fn expire(&mut self, now: Instant) {
        match self {
            Resolver::Stub(resolver) if resolver.poll_timeout().is_some_and(|timeout| timeout <= now) => {
                resolver.expire(now, &mut Random)
            }
            Resolver::Validating(resolver) if resolver.poll_timeout().is_some_and(|timeout| timeout <= now) => {
                resolver.expire(now, Tool::time() as u64, &mut Random)
            }
            _ => {}
        }
    }

    /// The result, once there is one: the response and, for a validating
    /// resolver, whether it is secure.
    pub fn result(&mut self) -> Option<Result<(DNSMessage, Option<DNSSECStatus>), DNSError>> {
        match self {
            Resolver::Stub(resolver) => match resolver.poll_event()? {
                DNSResolverEvent::Resolved { result, .. } => Some(result.map(|response| (response, None))),
            },
            Resolver::Validating(resolver) => match resolver.poll_event()? {
                DNSSECResolverEvent::Resolved { result, .. } => {
                    Some(result.map(|(response, status)| (response, Some(status))))
                }
            },
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Client {
    pub fn run(arguments: &Arguments) {
        let host = arguments.position(1, "the host");
        let port = arguments.position(2, "the port");
        let server = format!("{host}:{port}")
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .unwrap_or_else(|| Tool::fail("an address"));
        let question = DNSQuestion::new(
            Tool::name(arguments.position(3, "the name")),
            Tool::kind(arguments.position(4, "the type")),
        );
        let transport = match arguments.get("--transport").unwrap_or("udp") {
            "udp" => DNSTransport::UDP,
            "tcp" => DNSTransport::TCP,
            "tls" => DNSTransport::TLS,
            "https" => DNSTransport::HTTPS,
            "quic" => DNSTransport::QUIC,
            other => Tool::fail(&format!("a transport: {other}")),
        };
        let encrypted = transport.is_encrypted();
        let upstream = DNSUpstream { endpoint: Tool::endpoint(server), transport, name: None };
        let config = DNSResolverConfig { upstreams: vec![upstream], ..DNSResolverConfig::default() };
        let start = Clock::now();
        let now = Tool::now(start);
        let mut resolver = match arguments.has("--dnssec") {
            false => Resolver::Stub(Box::new(
                DNSResolver::new(config, &mut Random).unwrap_or_else(|error| Tool::fail(&format!("{error}"))),
            )),
            true => {
                let anchor = arguments.get("--anchor").map_or_else(DNSSECTrustAnchor::root, Client::anchor);
                let resolver = DNSSECResolver::new(config, DNSSECConfig::default(), anchor, &mut Random)
                    .unwrap_or_else(|error| Tool::fail(&format!("{error}")));
                Resolver::Validating(Box::new(resolver))
            }
        };
        match &mut resolver {
            Resolver::Stub(stub) => stub.resolve(question, now, &mut Random),
            Resolver::Validating(validating) => validating.resolve(question, now, Tool::time() as u64, &mut Random),
        }
        .unwrap_or_else(|error| Tool::fail(&format!("resolve: {error}")));
        let mut client = Client {
            server,
            name: arguments.get("--name").unwrap_or(host).to_string(),
            verifier: encrypted.then(|| Tool::verifier(arguments)),
            start,
            datagrams: Vec::new(),
            tcp: None,
            tls: None,
            https: None,
            post: arguments.has("--post"),
            quic: None,
            arrived: Vec::new(),
        };
        let deadline = Clock::now() + Tool::BUDGET;
        while Clock::now() < deadline {
            while let Some(transmission) = resolver.transmit() {
                client.send(transmission);
            }
            client.poll();
            let now = Tool::now(start);
            for (query, transport, bytes) in std::mem::take(&mut client.arrived) {
                resolver.receive(query, transport, &bytes, now);
            }
            resolver.expire(now);
            if let Some(result) = resolver.result() {
                Client::print(result);
                return;
            }
        }
        Tool::fail("no answer in time");
    }

    /// The trust anchor of the DS records of the zone file `path`.
    pub fn anchor(path: &str) -> DNSSECTrustAnchor {
        let records = DNSZoneFile::new(Some(DNSName::root()))
            .parse(&Tool::read(path))
            .unwrap_or_else(|error| Tool::fail(&format!("{path}: {}", error.error)));
        let zone = records.first().map(|record| record.name.clone()).unwrap_or_else(|| Tool::fail("no DS record"));
        let digests = records
            .iter()
            .filter_map(|record| match &record.data {
                DNSData::DS { key_tag, algorithm, digest_type, digest } => Some(DNSSECKeyDigest {
                    id: String::from("local"),
                    valid_from: 0,
                    valid_until: None,
                    key_tag: *key_tag,
                    algorithm: *algorithm,
                    digest_type: *digest_type,
                    digest: digest.clone(),
                    public_key: None,
                }),
                _ => None,
            })
            .collect();
        DNSSECTrustAnchor { zone, digests }
    }

    pub fn print(result: Result<(DNSMessage, Option<DNSSECStatus>), DNSError>) {
        match result {
            Ok((response, status)) => {
                println!("rcode: {}", response.rcode().0);
                for record in &response.answers {
                    println!("{record}");
                }
                match status {
                    Some(DNSSECStatus::Secure) => println!("status: secure"),
                    Some(DNSSECStatus::Insecure(_)) => println!("status: insecure"),
                    None => {}
                }
            }
            Err(DNSError::Bogus { code, reason }) => println!("error: bogus {code} {reason}"),
            Err(error) => println!("error: {error}"),
        }
    }

    pub fn send(&mut self, transmission: DNSTransmission) {
        let DNSTransmission { query, transport, message, .. } = transmission;
        let id = u16::from_be_bytes([message[0], message[1]]);
        match transport {
            DNSTransport::UDP => {
                let socket = UdpSocket::bind(if self.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
                    .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
                let _ = socket.set_nonblocking(true);
                let _ = socket.send_to(&message, self.server);
                self.datagrams.push((query, socket));
            }
            DNSTransport::TCP => {
                let server = self.server;
                let StreamConnection { stream, queries, .. } = self.tcp.get_or_insert_with(|| {
                    let stream =
                        TcpStream::connect(server).unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
                    let _ = stream.set_nonblocking(true);
                    StreamConnection { stream, tls: None, framer: DNSTCPFramer::new(), queries: BTreeMap::new() }
                });
                queries.insert(id, query);
                let _ = stream.write_all(&DNSTCPFramer::frame(&message).expect("a message frames"));
            }
            DNSTransport::TLS => {
                if self.tls.is_none() {
                    let (stream, tls) = self.handshake(b"dot");
                    let tls = Some(tls);
                    self.tls =
                        Some(StreamConnection { stream, tls, framer: DNSTCPFramer::new(), queries: BTreeMap::new() });
                }
                let Some(StreamConnection { stream, tls: Some(tls), queries, .. }) = &mut self.tls else { return };
                queries.insert(id, query);
                let _ = tls.send(&DNSTCPFramer::frame(&message).expect("a message frames"));
                let mut out = Vec::new();
                let _ = tls.transmit(&mut out);
                let _ = stream.write_all(&out);
            }
            DNSTransport::QUIC => {
                if self.quic.is_none() {
                    self.quic = Some(self.connect_quic());
                }
                let Some(QUICClientConnection { endpoint, handle, dns, streams, .. }) = &mut self.quic else { return };
                let decoded = DNSMessage::decode(&message).expect("a query decodes");
                // A stream opened during the handshake is sent once it completes.
                if let Some(connection) = endpoint.connection(*handle)
                    && let Ok(stream) = dns.send_query(connection, &decoded)
                {
                    streams.insert(stream, query);
                }
            }
            DNSTransport::HTTPS => {
                if self.https.is_none() {
                    let (stream, tls) = self.handshake(b"h2");
                    let http = H2Connection::client(H2Config::default(), Tool::now(self.start));
                    self.https = Some(HTTPSConnection { stream, tls, http, exchanges: BTreeMap::new() });
                }
                let authority = format!("{}:{}", self.name, self.server.port());
                let Some(HTTPSConnection { stream, tls, http, exchanges }) = &mut self.https else { return };
                let decoded = DNSMessage::decode(&message).expect("a query decodes");
                let (request, content) = match self.post {
                    true => DNSHTTPS::post(&decoded, authority.as_bytes(), DNSHTTPS::PATH).expect("a request"),
                    false => {
                        (DNSHTTPS::get(&decoded, authority.as_bytes(), DNSHTTPS::PATH).expect("a request"), Vec::new())
                    }
                };
                let Ok(id) = http.send_request(&request, content.is_empty()) else { return };
                if !content.is_empty() {
                    let _ = http.send_data(id, &content, true);
                }
                exchanges.insert(id, HTTPSExchange { query, head: None, content: Vec::new() });
                Client::flush(stream, tls, http);
            }
        }
    }

    /// A TLS connection to the server, its handshake done, of ALPN `protocol`.
    pub fn handshake(&self, protocol: &[u8]) -> (TcpStream, TLSConnection) {
        let mut stream =
            TcpStream::connect(self.server).unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
        let mut config = TLSClientConfig::new(self.verifier.clone().expect("a verifier"));
        config.config.protocols = vec![protocol.to_vec()];
        let mut tls = TLSConnection::client(Arc::new(config), Some(&self.name), Box::new(Random), Tool::time())
            .expect("a TLS client");
        let deadline = Clock::now() + Duration::from_secs(5);
        let mut buffer = vec![0u8; 65536];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        while tls.is_handshaking() {
            let mut out = Vec::new();
            let _ = tls.transmit(&mut out);
            if !out.is_empty() {
                let _ = stream.write_all(&out);
            }
            if Clock::now() > deadline {
                Tool::fail("the TLS handshake did not complete");
            }
            match stream.read(&mut buffer) {
                Ok(0) => Tool::fail("the server closed the connection"),
                Ok(count) => {
                    if let Err(error) = tls.receive(&buffer[..count]) {
                        Tool::fail(&format!("TLS: {error:?}"));
                    }
                }
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => Tool::fail(&format!("read: {error}")),
            }
        }
        let mut out = Vec::new();
        let _ = tls.transmit(&mut out);
        let _ = stream.write_all(&out);
        if tls.session.protocol.as_deref().is_some_and(|negotiated| negotiated != protocol) {
            Tool::fail("the server negotiated another ALPN");
        }
        let _ = stream.set_nonblocking(true);
        (stream, tls)
    }

    /// Sends what HTTP/2 has to send over TLS.
    pub fn flush(stream: &mut TcpStream, tls: &mut TLSConnection, http: &mut H2Connection) {
        let mut out = Vec::new();
        http.transmit(&mut out);
        if !out.is_empty() {
            let _ = tls.send(&out);
        }
        out.clear();
        let _ = tls.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    pub fn connect_quic(&self) -> QUICClientConnection {
        let mut tls = TLSClientConfig::new(self.verifier.clone().expect("a verifier"));
        tls.config.protocols = vec![DNSQUICConnection::ALPN.to_vec()];
        let socket = UdpSocket::bind(if self.server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        let _ = socket.set_nonblocking(true);
        let config = QUICEndpointConfig::new(Arc::new(QUICConfig::default()), None);
        let mut endpoint = QUICEndpoint::new(config, Box::new(Random)).expect("an endpoint");
        let now = Tool::now(self.start);
        let handle = endpoint
            .connect(
                Arc::new(tls),
                Some(&self.name),
                Tool::endpoint(self.server),
                None,
                Box::new(Random),
                now,
                Tool::time(),
            )
            .unwrap_or_else(|error| Tool::fail(&format!("connect: {error:?}")));
        let dns = DNSQUICConnection::new(QUICRole::Client);
        QUICClientConnection { endpoint, socket, handle, dns, streams: BTreeMap::new() }
    }

    /// Waits a little for what the connections receive, and takes it.
    pub fn poll(&mut self) {
        std::thread::sleep(Duration::from_millis(2));
        let mut buffer = vec![0u8; 65536];
        let server = self.server;
        self.datagrams.retain(|(query, socket)| match socket.recv_from(&mut buffer) {
            // RFC 5452 §9.1: a response from the server's address and port only.
            Ok((count, from)) if from == server => {
                self.arrived.push((*query, DNSTransport::UDP, buffer[..count].to_vec()));
                false
            }
            _ => true,
        });
        if let Some(StreamConnection { stream, framer, queries, .. }) = &mut self.tcp {
            if let Ok(count) = stream.read(&mut buffer) {
                framer.receive(&buffer[..count]);
            }
            while let Some(Ok(message)) = framer.next_message() {
                let id = u16::from_be_bytes([message[0], message[1]]);
                if let Some(query) = queries.remove(&id) {
                    self.arrived.push((query, DNSTransport::TCP, message));
                }
            }
        }
        if let Some(HTTPSConnection { stream, tls, http, exchanges }) = &mut self.https {
            if let Ok(count) = stream.read(&mut buffer)
                && count > 0
                && tls.receive(&buffer[..count]).is_ok()
            {
                let mut plain = Vec::new();
                DNSTLS::read_all(tls, &mut plain);
                http.receive(&plain, Tool::now(self.start));
            }
            while let Some(event) = http.poll_event() {
                match event {
                    HTTPEvent::Response { stream, response, .. } => {
                        if let Some(exchange) = exchanges.get_mut(&stream) {
                            exchange.head = Some(response);
                        }
                    }
                    HTTPEvent::Data { stream } => {
                        let mut data = vec![0u8; 65536];
                        while let Ok(count) = http.read_data(stream, &mut data) {
                            if count == 0 {
                                break;
                            }
                            if let Some(exchange) = exchanges.get_mut(&stream) {
                                exchange.content.extend_from_slice(&data[..count]);
                            }
                        }
                    }
                    HTTPEvent::End { stream } => {
                        let Some(HTTPSExchange { query, head: Some(head), content }) = exchanges.remove(&stream) else {
                            continue;
                        };
                        match DNSHTTPS::decode_response(&head, &content) {
                            Ok(message) => {
                                let bytes = message.encode(DNSMessage::MAXIMUM_SIZE).expect("a message encodes");
                                self.arrived.push((query, DNSTransport::HTTPS, bytes));
                            }
                            Err(error) => println!("https: {} {error}", head.status.0),
                        }
                    }
                    _ => {}
                }
            }
            http.expire(Tool::now(self.start));
            Client::flush(stream, tls, http);
        }
        if let Some(StreamConnection { stream, tls: Some(tls), framer, queries }) = &mut self.tls {
            if let Ok(count) = stream.read(&mut buffer)
                && count > 0
                && tls.receive(&buffer[..count]).is_ok()
            {
                let mut plain = Vec::new();
                DNSTLS::read_all(tls, &mut plain);
                framer.receive(&plain);
                let mut out = Vec::new();
                let _ = tls.transmit(&mut out);
                let _ = stream.write_all(&out);
            }
            while let Some(Ok(message)) = framer.next_message() {
                let id = u16::from_be_bytes([message[0], message[1]]);
                if let Some(query) = queries.remove(&id) {
                    self.arrived.push((query, DNSTransport::TLS, message));
                }
            }
        }
        if let Some(QUICClientConnection { endpoint, socket, handle, dns, streams }) = &mut self.quic {
            let start = self.start;
            let mut out = Vec::new();
            while let Ok((count, from)) = socket.recv_from(&mut buffer) {
                endpoint.receive(
                    &buffer[..count],
                    Tool::endpoint(from),
                    QUICECN::NotECT,
                    Tool::now(start),
                    Tool::time(),
                );
            }
            let now = Tool::now(start);
            if endpoint.poll_timeout().is_some_and(|timeout| timeout <= now) {
                endpoint.expire(now, Tool::time());
            }
            if let Some(connection) = endpoint.connection(*handle) {
                if let Err(error) = dns.process(connection, now) {
                    Tool::fail(&format!("DNS over QUIC: {error}"));
                }
                while let Some(event) = dns.poll_event() {
                    if let DNSQUICEvent::Response { stream, message } = event
                        && let Some(query) = streams.remove(&stream)
                        && let Ok(bytes) = message.encode(DNSMessage::MAXIMUM_SIZE)
                    {
                        self.arrived.push((query, DNSTransport::QUIC, bytes));
                    }
                }
            }
            while let Some(transmission) = endpoint.transmit(now, &mut out) {
                let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination));
            }
        }
    }
}
