//! An HTTP server and client over TCP, TLS and QUIC, to try umilib's HTTP
//! against other implementations (`examples/http.sh` runs it against curl,
//! Python's standard library and itself).
//!
//! ```text
//! http server PORT [--cert FILE --key FILE] [--quic] [--connections N]
//! http client URL [--version 1.1|2|3] [--name NAME] [--ca FILE | --insecure] [--method METHOD] [--data TEXT]
//!                 [--header NAME:VALUE] [--websocket TEXT]
//! ```
//!
//! Without a certificate the server speaks HTTP/1.1 and, to a client that
//! starts with its preface, HTTP/2 (prior knowledge) over TCP; with one it
//! speaks TLS with ALPN `h2` and `http/1.1`, and with `--quic` HTTP/3 on the
//! same port over UDP. Its site, the same for every version, is routed with
//! `HTTPRule`:
//!
//! - `GET /`: a line of text naming the version;
//! - `POST /echo`: the request's content back;
//! - `GET /bytes?N`: N bytes;
//! - `GET /gzip`: a text, gzip-coded if the request accepts it;
//! - `GET /ws.html`: a page whose script talks to `/chat`;
//! - `/chat`: a WebSocket that echoes each message (an Upgrade over HTTP/1.1,
//!   an extended CONNECT over HTTP/2 and HTTP/3).
//!
//! Each request prints a line `request: VERSION METHOD PATH STATUS`. The
//! client prints `status: CODE`, then the content, or `echo: TEXT` for
//! `--websocket`. It needs the operating system's random source: Linux,
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
use umilib::protocol::http::v1::{H1Config, H1Connection};
use umilib::protocol::http::v2::{H2Config, H2Connection};
use umilib::protocol::http::v3::{H3Config, H3Connection, H3Session};
use umilib::protocol::http::websocket::WebSocketHandshake;
use umilib::protocol::http::{
    HTTPAcceptEncoding, HTTPConnection, HTTPContentCoding, HTTPContentEncoder, HTTPEvent, HTTPMethod, HTTPRequest,
    HTTPResponse, HTTPRule, HTTPStatus, HTTPStreamID, HTTPVersion,
};
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address, IPv6Address};
use umilib::protocol::quic::{QUICConfig, QUICECN, QUICEndpoint, QUICEndpointConfig};
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertificateVerifier, TLSCertifiedKey, TLSClientConfig, TLSConnection, TLSPathVerifier,
    TLSServerConfig,
};
use umilib::protocol::websocket::{WebSocketConfig, WebSocketConnection, WebSocketEvent, WebSocketRole};
use umilib::runtime::Instant;
use umilib::service::{Pattern, Rule};

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 2] = ["--insecure", "--quic"];

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

    /// The connections' clock: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    pub fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")))
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

    pub fn version_name(version: HTTPVersion) -> &'static str {
        match (version.major, version.minor) {
            (1, 0) => "HTTP/1.0",
            (1, _) => "HTTP/1.1",
            (2, _) => "HTTP/2",
            (3, _) => "HTTP/3",
            _ => "HTTP/?",
        }
    }
}

/// HTTP/1.1 or HTTP/2 over a byte stream.
pub enum ByteConnection {
    H1(Box<H1Connection>),
    H2(Box<H2Connection>),
}

impl ByteConnection {
    pub fn http(&mut self) -> &mut dyn HTTPConnection {
        match self {
            ByteConnection::H1(connection) => connection.as_mut(),
            ByteConnection::H2(connection) => connection.as_mut(),
        }
    }

    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        match self {
            ByteConnection::H1(connection) => connection.receive(bytes, now),
            ByteConnection::H2(connection) => connection.receive(bytes, now),
        }
    }

    pub fn receive_close(&mut self, now: Instant) {
        match self {
            ByteConnection::H1(connection) => connection.receive_close(now),
            ByteConnection::H2(connection) => connection.receive_close(),
        }
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        match self {
            ByteConnection::H1(connection) => connection.transmit(out),
            ByteConnection::H2(connection) => connection.transmit(out),
        }
    }

    pub fn wants_close(&self) -> bool {
        match self {
            ByteConnection::H1(connection) => connection.wants_close(),
            ByteConnection::H2(connection) => connection.wants_close(),
        }
    }

    pub fn expire(&mut self, now: Instant) {
        match self {
            ByteConnection::H1(connection) => connection.expire(now),
            ByteConnection::H2(connection) => connection.expire(now),
        }
    }
}

/// A TCP stream, with TLS or without.
pub struct Transport {
    pub stream: TcpStream,
    pub tls: Option<TLSConnection>,
    pub closed: bool,
}

impl Transport {
    /// Sends `bytes` (of HTTP) and what TLS has to send.
    pub fn send(&mut self, bytes: &[u8]) {
        let mut out = Vec::new();
        match &mut self.tls {
            Some(tls) => {
                let mut rest = bytes;
                while !rest.is_empty() {
                    match tls.send(rest) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => rest = &rest[count..],
                    }
                }
                let _ = tls.transmit(&mut out);
            }
            None => out.extend_from_slice(bytes),
        }
        if !out.is_empty() && self.stream.write_all(&out).is_err() {
            self.closed = true;
        }
    }

    /// What arrived within `wait` (of HTTP), or `None` once the stream ended.
    pub fn receive(&mut self, wait: Duration) -> Option<Vec<u8>> {
        let _ = self.stream.set_read_timeout(Some(wait));
        let mut buffer = vec![0u8; 1 << 16];
        let count = match self.stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(count) => count,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Some(Vec::new());
            }
            Err(_) => return None,
        };
        let Some(tls) = &mut self.tls else { return Some(buffer[..count].to_vec()) };
        if tls.receive(&buffer[..count]).is_err() {
            return None;
        }
        let mut out = Vec::new();
        let _ = tls.transmit(&mut out);
        let _ = self.stream.write_all(&out);
        let mut plain = Vec::new();
        loop {
            let read = tls.read(&mut buffer);
            if read == 0 {
                break;
            }
            plain.extend_from_slice(&buffer[..read]);
        }
        Some(plain)
    }

    /// Runs the TLS handshake; the protocol it negotiated.
    pub fn handshake(&mut self) -> Option<Vec<u8>> {
        let deadline = Clock::now() + Duration::from_secs(5);
        loop {
            let mut out = Vec::new();
            let tls = self.tls.as_mut()?;
            let _ = tls.transmit(&mut out);
            if !out.is_empty() && self.stream.write_all(&out).is_err() {
                return None;
            }
            if !tls.is_handshaking() {
                return Some(tls.session.protocol.clone().unwrap_or_default());
            }
            if Clock::now() > deadline || self.receive(Duration::from_millis(50)).is_none() {
                return None;
            }
        }
    }
}

/// What a route of the site does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Home,
    Echo,
    Bytes,
    Gzip,
    Script,
    Chat,
}

/// A stream the site answers: content to send and the request's content so far.
#[derive(Default)]
pub struct Exchange {
    pub page: Option<Page>,
    pub received: Vec<u8>,
    /// Content not yet taken by the connection, and whether it ends the stream.
    pub pending: Vec<u8>,
    pub end: bool,
    pub websocket: Option<WebSocketConnection>,
}

/// The site: the same for every version.
pub struct Site {
    pub routes: Vec<(HTTPRule, Page)>,
    pub exchanges: BTreeMap<u64, Exchange>,
    pub version: HTTPVersion,
    pub finished: bool,
}

impl Site {
    pub const SCRIPT: &'static str = "<!doctype html><title>umilib WebSocket</title><pre id=log></pre><script>\n\
        const log = (line) => document.getElementById('log').textContent += line + '\\n';\n\
        const socket = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/chat');\n\
        socket.onopen = () => { log('open'); socket.send('hello from the browser'); };\n\
        socket.onmessage = (event) => { log('echo: ' + event.data); socket.close(1000, 'done'); };\n\
        socket.onclose = (event) => log('closed: ' + event.code);\n\
        </script>\n";

    pub fn new(version: HTTPVersion) -> Site {
        let any = || Pattern::any();
        let routes = vec![
            (HTTPRule::new(any(), Pattern::exact(b"/")).with_method(HTTPMethod::GET), Page::Home),
            (HTTPRule::new(any(), Pattern::exact(b"/echo")).with_method(HTTPMethod::POST), Page::Echo),
            (HTTPRule::new(any(), Pattern::prefix(b"/bytes?")).with_method(HTTPMethod::GET), Page::Bytes),
            (HTTPRule::new(any(), Pattern::exact(b"/gzip")).with_method(HTTPMethod::GET), Page::Gzip),
            (HTTPRule::new(any(), Pattern::exact(b"/ws.html")).with_method(HTTPMethod::GET), Page::Script),
            (HTTPRule::new(any(), Pattern::exact(b"/chat")), Page::Chat),
        ];
        Site { routes, exchanges: BTreeMap::new(), version, finished: false }
    }

    pub fn respond(
        connection: &mut dyn HTTPConnection,
        stream: HTTPStreamID,
        status: HTTPStatus,
        fields: &[(&[u8], &[u8])],
    ) {
        let mut response = HTTPResponse::new(status);
        for (name, value) in fields {
            response.fields.append(name, value).expect("a valid field");
        }
        let _ = connection.send_response(stream, &response, false);
    }

    /// Takes the connection's events and answers them.
    pub fn serve(&mut self, connection: &mut dyn HTTPConnection) {
        while let Some(event) = connection.poll_event() {
            match event {
                HTTPEvent::Request { stream, request, end } => self.request(connection, stream, &request, end),
                HTTPEvent::Data { stream } => self.data(connection, stream),
                HTTPEvent::End { stream } => {
                    self.data(connection, stream);
                    let exchange = self.exchanges.entry(stream.0).or_default();
                    if exchange.page == Some(Page::Echo) {
                        let content = std::mem::take(&mut exchange.received);
                        let length = content.len().to_string();
                        Site::respond(connection, stream, HTTPStatus::OK, &[(b"content-length", length.as_bytes())]);
                        exchange.pending = content;
                        exchange.end = true;
                    }
                }
                HTTPEvent::Reset { stream, .. } => {
                    self.exchanges.remove(&stream.0);
                }
                HTTPEvent::Closed { error } => {
                    if let Some(error) = error {
                        println!("closed: {error}");
                    }
                    self.finished = true;
                }
                _ => {}
            }
        }
        self.flush(connection);
    }

    pub fn request(
        &mut self,
        connection: &mut dyn HTTPConnection,
        stream: HTTPStreamID,
        request: &HTTPRequest,
        end: bool,
    ) {
        let page = self.routes.iter().find(|(rule, _)| rule.matches(request)).map(|(_, page)| *page);
        let mut exchange = Exchange { page, ..Exchange::default() };
        let status = match page {
            None => {
                Site::respond(connection, stream, HTTPStatus::NOT_FOUND, &[(b"content-length", b"10")]);
                exchange.pending = b"not found\n".to_vec();
                exchange.end = true;
                HTTPStatus::NOT_FOUND
            }
            Some(Page::Home) => {
                let text = format!("hello from umilib over {}\n", Tool::version_name(self.version));
                let length = text.len().to_string();
                let fields: [(&[u8], &[u8]); 2] =
                    [(b"content-type", b"text/plain"), (b"content-length", length.as_bytes())];
                Site::respond(connection, stream, HTTPStatus::OK, &fields);
                exchange.pending = text.into_bytes();
                exchange.end = true;
                HTTPStatus::OK
            }
            Some(Page::Echo) => {
                if end {
                    Site::respond(connection, stream, HTTPStatus::OK, &[(b"content-length", b"0")]);
                    exchange.end = true;
                }
                HTTPStatus::OK
            }
            Some(Page::Bytes) => {
                let count: usize =
                    std::str::from_utf8(&request.path[7..]).ok().and_then(|n| n.parse().ok()).unwrap_or(0);
                let length = count.to_string();
                Site::respond(connection, stream, HTTPStatus::OK, &[(b"content-length", length.as_bytes())]);
                exchange.pending = vec![b'x'; count];
                exchange.end = true;
                HTTPStatus::OK
            }
            Some(Page::Gzip) => {
                let text = "a text that compresses, a text that compresses, a text that compresses\n".repeat(64);
                let accepted =
                    HTTPAcceptEncoding::parse(&request.fields.combined(b"accept-encoding").unwrap_or_default());
                let content = match accepted.choose(&[HTTPContentCoding::Gzip]) {
                    Some(coding) => {
                        let mut encoder = HTTPContentEncoder::new(coding).expect("gzip");
                        let mut out = Vec::new();
                        encoder.encode(text.as_bytes(), false, &mut out).expect("it encodes");
                        encoder.finish(&mut out).expect("it ends");
                        let length = out.len().to_string();
                        Site::respond(
                            connection,
                            stream,
                            HTTPStatus::OK,
                            &[
                                (b"content-encoding", b"gzip"),
                                (b"content-length", length.as_bytes()),
                                (b"vary", b"accept-encoding"),
                            ],
                        );
                        out
                    }
                    None => {
                        let length = text.len().to_string();
                        Site::respond(
                            connection,
                            stream,
                            HTTPStatus::OK,
                            &[(b"content-length", length.as_bytes()), (b"vary", b"accept-encoding")],
                        );
                        text.into_bytes()
                    }
                };
                exchange.pending = content;
                exchange.end = true;
                HTTPStatus::OK
            }
            Some(Page::Script) => {
                let length = Site::SCRIPT.len().to_string();
                let fields: [(&[u8], &[u8]); 2] =
                    [(b"content-type", b"text/html; charset=utf-8"), (b"content-length", length.as_bytes())];
                Site::respond(connection, stream, HTTPStatus::OK, &fields);
                exchange.pending = Site::SCRIPT.as_bytes().to_vec();
                exchange.end = true;
                HTTPStatus::OK
            }
            Some(Page::Chat) => match WebSocketHandshake::check_request(request, self.version) {
                Ok(offer) => {
                    let agreement = WebSocketHandshake::agree(&offer, &[], true);
                    let response = WebSocketHandshake::response(&offer, &agreement).expect("a response");
                    let status = response.status;
                    let _ = connection.send_response(stream, &response, false);
                    let websocket = WebSocketConnection::new(
                        WebSocketRole::Server,
                        WebSocketConfig::default(),
                        agreement.deflate,
                        Box::new(Random),
                    );
                    exchange.websocket = Some(websocket.expect("a WebSocket"));
                    status
                }
                Err(refusal) => {
                    let status = refusal.status;
                    let _ = connection.send_response(stream, &refusal, true);
                    status
                }
            },
        };
        println!(
            "request: {} {} {} {}",
            Tool::version_name(self.version),
            String::from_utf8_lossy(request.method.as_bytes()),
            String::from_utf8_lossy(&request.path),
            status.0
        );
        let _ = std::io::stdout().flush();
        self.exchanges.insert(stream.0, exchange);
    }

    /// Reads what arrived on `stream`: a request's content, or a WebSocket's frames.
    pub fn data(&mut self, connection: &mut dyn HTTPConnection, stream: HTTPStreamID) {
        let mut buffer = vec![0u8; 1 << 16];
        let exchange = self.exchanges.entry(stream.0).or_default();
        loop {
            let count = connection.read_data(stream, &mut buffer).unwrap_or(0);
            if count == 0 {
                break;
            }
            match &mut exchange.websocket {
                Some(websocket) => websocket.receive(&buffer[..count]),
                None => exchange.received.extend_from_slice(&buffer[..count]),
            }
        }
        let Some(websocket) = &mut exchange.websocket else { return };
        while let Some(event) = websocket.poll_event() {
            match event {
                WebSocketEvent::Text(text) => {
                    println!("websocket: {text}");
                    let _ = websocket.send_text(&text);
                }
                WebSocketEvent::Binary(data) => {
                    let _ = websocket.send_binary(&data);
                }
                WebSocketEvent::Closed { code, .. } => println!("websocket closed: {}", code.0),
                _ => {}
            }
        }
        websocket.transmit(&mut exchange.pending);
        if websocket.wants_close() {
            exchange.end = true;
        }
    }

    /// Writes what each stream has pending, as far as flow control lets it.
    pub fn flush(&mut self, connection: &mut dyn HTTPConnection) {
        let mut done = Vec::new();
        for (&stream, exchange) in &mut self.exchanges {
            if exchange.pending.is_empty() && !exchange.end {
                continue;
            }
            match connection.send_data(HTTPStreamID(stream), &exchange.pending, exchange.end) {
                Ok(count) => {
                    exchange.pending.drain(..count);
                    if exchange.pending.is_empty() && exchange.end {
                        done.push(stream);
                    }
                }
                Err(_) => done.push(stream),
            }
        }
        for stream in done {
            self.exchanges.remove(&stream);
        }
    }
}

/// The server.
pub struct Server;

impl Server {
    pub fn run(arguments: &Arguments) {
        let port: u16 =
            arguments.positional.get(1).and_then(|port| port.parse().ok()).unwrap_or_else(|| Tool::fail("server PORT"));
        let certified = Tool::certified(arguments).map(Arc::new);
        let tls = certified.clone().map(|key| {
            let mut config = TLSServerConfig::new(vec![key]);
            config.config.protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        });
        let listener =
            TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        if arguments.has("--quic") {
            let key = certified.unwrap_or_else(|| Tool::fail("--quic needs --cert and --key"));
            std::thread::spawn(move || Server::quic(port, key));
        }
        println!("listening: {port}");
        let _ = std::io::stdout().flush();
        let connections: usize = arguments.get("--connections").map_or(usize::MAX, |count| count.parse().unwrap_or(1));
        let mut threads = Vec::new();
        for _ in 0..connections {
            let Ok((stream, _)) = listener.accept() else { break };
            let tls = tls.clone();
            threads.push(std::thread::spawn(move || Server::tcp(stream, tls)));
        }
        for thread in threads {
            let _ = thread.join();
        }
    }

    /// One connection over TCP: TLS and ALPN, or HTTP/1.1 and HTTP/2 by prior knowledge.
    pub fn tcp(stream: TcpStream, tls: Option<Arc<TLSServerConfig>>) {
        let start = Clock::now();
        let mut transport = Transport { stream, tls: None, closed: false };
        let mut first = Vec::new();
        let h2 = match tls {
            Some(config) => {
                transport.tls =
                    Some(TLSConnection::server(config, Box::new(Random), Tool::time()).expect("a TLS server"));
                match transport.handshake() {
                    Some(protocol) => protocol == b"h2",
                    None => return,
                }
            }
            None => {
                // The client's preface says HTTP/2 (RFC 9113 §3.3).
                while first.len() < 24 {
                    match transport.receive(Duration::from_secs(5)) {
                        Some(bytes) if !bytes.is_empty() => first.extend_from_slice(&bytes),
                        Some(_) if first.starts_with(b"GET") || first.contains(&b'\n') => break,
                        _ => break,
                    }
                    if !b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".starts_with(&first[..first.len().min(24)]) {
                        break;
                    }
                }
                first.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            }
        };
        let now = Tool::now(start);
        let (mut connection, version) = if h2 {
            let config = H2Config { enable_connect_protocol: true, ..H2Config::default() };
            (ByteConnection::H2(Box::new(H2Connection::server(config, now))), HTTPVersion::HTTP2)
        } else {
            let scheme = if transport.tls.is_some() { b"https".to_vec() } else { b"http".to_vec() };
            (
                ByteConnection::H1(Box::new(H1Connection::server(H1Config { scheme, ..H1Config::default() }, now))),
                HTTPVersion::HTTP1_1,
            )
        };
        let mut site = Site::new(version);
        connection.receive(&first, now);
        loop {
            site.serve(connection.http());
            let mut out = Vec::new();
            connection.transmit(&mut out);
            transport.send(&out);
            if connection.wants_close() || transport.closed || site.finished {
                break;
            }
            match transport.receive(Duration::from_millis(20)) {
                Some(bytes) => connection.receive(&bytes, Tool::now(start)),
                None => connection.receive_close(Tool::now(start)),
            }
            connection.expire(Tool::now(start));
        }
        if let Some(tls) = &mut transport.tls {
            let _ = tls.close();
        }
        transport.send(&[]);
    }

    /// HTTP/3 on UDP `port`.
    pub fn quic(port: u16, key: Arc<TLSCertifiedKey>) {
        let mut tls = TLSServerConfig::new(vec![key]);
        tls.config.protocols = vec![b"h3".to_vec()];
        let mut endpoint = QUICEndpoint::new(
            QUICEndpointConfig::new(Arc::new(QUICConfig::default()), Some(Arc::new(tls))),
            Box::new(Random),
        )
        .expect("an endpoint");
        let socket =
            UdpSocket::bind(("127.0.0.1", port)).unwrap_or_else(|error| Tool::fail(&format!("bind UDP: {error}")));
        let start = Clock::now();
        let mut connections: BTreeMap<u64, (H3Connection, Site)> = BTreeMap::new();
        let mut buffer = vec![0u8; 65536];
        let mut out = Vec::new();
        loop {
            let now = Tool::now(start);
            let wait = endpoint
                .poll_timeout()
                .map(|timeout| Duration::from_nanos(timeout.as_nanos().saturating_sub(now.as_nanos())))
                .unwrap_or(Duration::from_millis(50))
                .clamp(Duration::from_millis(1), Duration::from_millis(50));
            socket.set_read_timeout(Some(wait)).expect("a timeout");
            match socket.recv_from(&mut buffer) {
                Ok((count, from)) => {
                    endpoint.receive(
                        &buffer[..count],
                        Tool::endpoint(from),
                        QUICECN::NotECT,
                        Tool::now(start),
                        Tool::time(),
                    );
                }
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => Tool::fail(&format!("receive: {error}")),
            }
            let now = Tool::now(start);
            if endpoint.poll_timeout().is_some_and(|timeout| timeout <= now) {
                endpoint.expire(now, Tool::time());
            }
            while let Some(handle) = endpoint.accept() {
                connections.insert(
                    handle,
                    (
                        H3Connection::server(H3Config { enable_connect_protocol: true, ..H3Config::default() }, now),
                        Site::new(HTTPVersion::HTTP3),
                    ),
                );
            }
            connections.retain(|&handle, (state, site)| {
                let Some(quic) = endpoint.connection(handle) else { return false };
                let mut session = H3Session::new(state, quic);
                session.process(now);
                site.serve(&mut session);
                session.flush();
                !session.is_closed()
            });
            let now = Tool::now(start);
            while let Some(transmission) = endpoint.transmit(now, &mut out) {
                let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination, &socket));
            }
        }
    }
}

/// The client.
pub struct Client;

impl Client {
    pub fn run(arguments: &Arguments) {
        let url = arguments.positional.get(1).unwrap_or_else(|| Tool::fail("client URL"));
        let (scheme, rest) = url.split_once("://").unwrap_or_else(|| Tool::fail("a URL with a scheme"));
        let (authority, path) = rest.find('/').map_or((rest, "/"), |slash| (&rest[..slash], &rest[slash..]));
        let tls = scheme == "https" || scheme == "wss";
        let default_port = if tls { 443 } else { 80 };
        let address =
            if authority.contains(':') { authority.to_string() } else { format!("{authority}:{default_port}") };
        // The server name of TLS: `--name`, else the URL's host.
        let host = arguments.get("--name").unwrap_or(authority.rsplit_once(':').map_or(authority, |(host, _)| host));
        let version = arguments.get("--version").unwrap_or("1.1");
        let websocket = arguments.get("--websocket");
        let http_scheme: &[u8] = if tls { b"https" } else { b"http" };
        let mut request = match (websocket, version) {
            (Some(_), "1.1") => HTTPRequest::new(HTTPMethod::GET, http_scheme, authority.as_bytes(), path.as_bytes()),
            (Some(_), _) => {
                WebSocketHandshake::connect_request(http_scheme, authority.as_bytes(), path.as_bytes(), &[], None)
                    .expect("a CONNECT")
            }
            (None, _) => {
                let method =
                    HTTPMethod::parse(arguments.get("--method").unwrap_or("GET").as_bytes()).expect("a method");
                HTTPRequest::new(method, http_scheme, authority.as_bytes(), path.as_bytes())
            }
        };
        let mut key = None;
        if websocket.is_some() && version == "1.1" {
            let (handshake, nonce) =
                WebSocketHandshake::request(http_scheme, authority.as_bytes(), path.as_bytes(), &[], None, &mut Random)
                    .expect("a request");
            request = handshake;
            key = Some(nonce);
        }
        for header in arguments.all("--header") {
            let (name, value) = header.split_once(':').unwrap_or_else(|| Tool::fail("--header NAME:VALUE"));
            request.fields.append(name.trim().as_bytes(), value.trim().as_bytes()).expect("a field");
        }
        let data = arguments.get("--data").map(|data| data.as_bytes().to_vec());
        if let Some(data) = &data {
            request.fields.append(b"content-length", data.len().to_string().as_bytes()).expect("a length");
        }
        let mut client = ClientState { data, websocket: websocket.map(str::to_string), key, ..ClientState::default() };
        let start = Clock::now();
        if version == "3" {
            Client::quic(arguments, &address, host, &request, &mut client, start);
        } else {
            Client::tcp(arguments, &address, host, tls, version, &request, &mut client, start);
        }
        std::process::exit(if client.ok { 0 } else { 1 });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tcp(
        arguments: &Arguments,
        address: &str,
        host: &str,
        tls: bool,
        version: &str,
        request: &HTTPRequest,
        client: &mut ClientState,
        start: Clock,
    ) {
        let stream = TcpStream::connect(address).unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
        let mut transport = Transport { stream, tls: None, closed: false };
        if tls {
            let mut config = TLSClientConfig::new(Tool::verifier(arguments));
            config.config.protocols = match version {
                "2" => vec![b"h2".to_vec()],
                _ => vec![b"http/1.1".to_vec()],
            };
            let config = Arc::new(config);
            transport.tls =
                Some(TLSConnection::client(config, Some(host), Box::new(Random), Tool::time()).expect("a TLS client"));
            if transport.handshake().is_none() {
                Tool::fail("the TLS handshake failed");
            }
        }
        let now = Tool::now(start);
        let mut connection = match version {
            "2" => ByteConnection::H2(Box::new(H2Connection::client(H2Config::default(), now))),
            _ => ByteConnection::H1(Box::new(H1Connection::client(H1Config::default(), now))),
        };
        let deadline = Clock::now() + Duration::from_secs(10);
        let mut sent = false;
        while Clock::now() < deadline && !client.finished {
            client.step(connection.http(), request, &mut sent);
            let mut out = Vec::new();
            connection.transmit(&mut out);
            transport.send(&out);
            if client.finished || connection.wants_close() || transport.closed {
                break;
            }
            match transport.receive(Duration::from_millis(20)) {
                Some(bytes) => connection.receive(&bytes, Tool::now(start)),
                None => connection.receive_close(Tool::now(start)),
            }
            connection.expire(Tool::now(start));
        }
        if let Some(tls) = &mut transport.tls {
            let _ = tls.close();
        }
        transport.send(&[]);
    }

    pub fn quic(
        arguments: &Arguments,
        address: &str,
        host: &str,
        request: &HTTPRequest,
        client: &mut ClientState,
        start: Clock,
    ) {
        let address = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .unwrap_or_else(|| Tool::fail("an address"));
        let mut tls = TLSClientConfig::new(Tool::verifier(arguments));
        tls.config.protocols = vec![b"h3".to_vec()];
        let socket = UdpSocket::bind(if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        let mut endpoint =
            QUICEndpoint::new(QUICEndpointConfig::new(Arc::new(QUICConfig::default()), None), Box::new(Random))
                .expect("an endpoint");
        let handle = endpoint
            .connect(
                Arc::new(tls),
                Some(host),
                Tool::endpoint(address),
                None,
                Box::new(Random),
                Tool::now(start),
                Tool::time(),
            )
            .unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
        let mut state = H3Connection::client(H3Config::default(), Tool::now(start));
        let deadline = Clock::now() + Duration::from_secs(10);
        let mut buffer = vec![0u8; 65536];
        let mut out = Vec::new();
        let mut sent = false;
        while Clock::now() < deadline && !client.finished {
            let now = Tool::now(start);
            while let Some(transmission) = endpoint.transmit(now, &mut out) {
                let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination, &socket));
            }
            let wait = endpoint
                .poll_timeout()
                .map(|timeout| Duration::from_nanos(timeout.as_nanos().saturating_sub(now.as_nanos())))
                .unwrap_or(Duration::from_millis(50))
                .clamp(Duration::from_millis(1), Duration::from_millis(50));
            socket.set_read_timeout(Some(wait)).expect("a timeout");
            if let Ok((count, from)) = socket.recv_from(&mut buffer) {
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
            let Some(quic) = endpoint.connection(handle) else { break };
            let connected = quic.handshake_complete;
            let mut session = H3Session::new(&mut state, quic);
            session.process(now);
            if connected {
                client.step(&mut session, request, &mut sent);
            }
            session.flush();
        }
        if let Some(quic) = endpoint.connection(handle) {
            let _ = quic.close(0x100, b"", Tool::now(start));
        }
        let now = Tool::now(start);
        while let Some(transmission) = endpoint.transmit(now, &mut out) {
            let _ = socket.send_to(&out, Tool::socket_address(&transmission.destination, &socket));
        }
    }
}

/// What the client sent and received.
#[derive(Default)]
pub struct ClientState {
    pub data: Option<Vec<u8>>,
    pub websocket: Option<String>,
    pub key: Option<Vec<u8>>,
    pub stream: Option<HTTPStreamID>,
    pub connection: Option<WebSocketConnection>,
    pub content: Vec<u8>,
    pub finished: bool,
    pub ok: bool,
}

impl ClientState {
    /// Sends the request once, then takes the connection's events.
    pub fn step(&mut self, connection: &mut dyn HTTPConnection, request: &HTTPRequest, sent: &mut bool) {
        if !*sent {
            let end = self.data.is_none() && self.websocket.is_none();
            match connection.send_request(request, end) {
                Ok(stream) => {
                    self.stream = Some(stream);
                    if let Some(data) = self.data.take() {
                        let _ = connection.send_data(stream, &data, true);
                    }
                    *sent = true;
                }
                Err(_) => return,
            }
        }
        let Some(stream) = self.stream else { return };
        let mut buffer = vec![0u8; 1 << 16];
        while let Some(event) = connection.poll_event() {
            match event {
                HTTPEvent::Response { response, .. }
                    if !response.status.is_informational() || response.status == HTTPStatus::SWITCHING_PROTOCOLS =>
                {
                    println!("status: {}", response.status.0);
                    if let Some(text) = self.websocket.clone() {
                        match WebSocketHandshake::check_response(&response, self.key.as_deref(), &[], None) {
                            Ok(agreement) => {
                                let mut websocket = WebSocketConnection::new(
                                    WebSocketRole::Client,
                                    WebSocketConfig::default(),
                                    agreement.deflate,
                                    Box::new(Random),
                                )
                                .expect("a WebSocket");
                                websocket.send_text(&text).expect("a message");
                                let mut out = Vec::new();
                                websocket.transmit(&mut out);
                                let _ = connection.send_data(stream, &out, false);
                                self.connection = Some(websocket);
                            }
                            Err(reason) => {
                                println!("websocket refused: {reason}");
                                self.finished = true;
                            }
                        }
                    }
                }
                HTTPEvent::Data { stream } => {
                    while let Ok(count) = connection.read_data(stream, &mut buffer) {
                        if count == 0 {
                            break;
                        }
                        match &mut self.connection {
                            Some(websocket) => websocket.receive(&buffer[..count]),
                            None => self.content.extend_from_slice(&buffer[..count]),
                        }
                    }
                }
                HTTPEvent::End { .. } if self.websocket.is_none() => {
                    print!("{}", String::from_utf8_lossy(&self.content));
                    let _ = std::io::stdout().flush();
                    self.ok = true;
                    self.finished = true;
                }
                HTTPEvent::Reset { code, .. } => {
                    println!("reset: {code:#x}");
                    self.finished = true;
                }
                HTTPEvent::Closed { error } => {
                    if let Some(error) = error {
                        println!("closed: {error}");
                    }
                    self.finished = true;
                }
                _ => {}
            }
        }
        let Some(websocket) = &mut self.connection else { return };
        while let Some(event) = websocket.poll_event() {
            match event {
                WebSocketEvent::Text(text) => {
                    println!("echo: {text}");
                    let _ = websocket.close(umilib::protocol::websocket::WebSocketCloseCode::NORMAL, "done");
                }
                WebSocketEvent::Closed { code, .. } => {
                    println!("websocket closed: {}", code.0);
                    self.ok = code.0 == 1000;
                    self.finished = true;
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        websocket.transmit(&mut out);
        if !out.is_empty() {
            let _ = connection.send_data(stream, &out, false);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("server") => Server::run(&arguments),
        Some("client") => Client::run(&arguments),
        _ => Tool::fail("usage: http server PORT ... | http client URL ..."),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    Tool::fail("this platform has no random source for the example");
}
