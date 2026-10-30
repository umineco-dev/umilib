//! A CoAP server and client over UDP, to try umilib's CoAP against other
//! implementations (`examples/coap.sh` runs them against libcoap's
//! coap-client and coap-server).
//!
//! ```text
//! coap server PORT [--address ADDRESS]
//! coap client HOST PORT METHOD PATH [--payload TEXT] [--non] [--observe COUNT] [--block SIZE]
//! ```
//!
//! The server's resources, routed with `CoAPRule`:
//!
//! - `GET /hello`: the text `hello world`;
//! - `POST /echo`: the request's payload back, 2.04 Changed;
//! - `GET /large`: 2000 bytes of text, block by block (RFC 7959 §2.4);
//! - `GET /counter`: a number, observable, notified each second (RFC 7641);
//! - `GET /.well-known/core`: the resources in the Link Format (RFC 6690).
//!
//! Each request prints a line `request: METHOD PATH`. The client prints
//! `code: CODE`, then the payload, its blocks put together; with
//! `--observe COUNT` each of COUNT notifications as `notification: VALUE
//! PAYLOAD`, after which it forgets the observation, so that the next
//! notification is rejected (RFC 7641 §3.6). It needs the operating
//! system's random source: Linux, Android, the Apple platforms and Windows.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports, dead_code)
)]

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant as Clock};

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::native::Random;
use umilib::protocol::coap::{
    CoAPBlockwise, CoAPCode, CoAPConfig, CoAPContentFormat, CoAPEndpoint, CoAPEvent, CoAPLink, CoAPMessage,
    CoAPObservers, CoAPOptionNumber, CoAPRule, CoAPType,
};
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address, IPv6Address};
use umilib::runtime::Instant;
use umilib::service::Rule;

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 1] = ["--non"];

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

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
    }
}

/// The helpers of the tool.
pub struct Tool;

impl Tool {
    /// How long the client waits for its responses.
    pub const BUDGET: Duration = Duration::from_secs(30);

    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    /// The endpoint's clock: nanoseconds since the tool started.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
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

    /// Moves datagrams between `endpoint` and `socket` for a step: what is
    /// due goes out, then what arrives within `wait`, or the timers.
    pub fn step(endpoint: &mut CoAPEndpoint, socket: &UdpSocket, start: Clock, wait: Duration) {
        while let Some(transmission) = endpoint.transmit() {
            let _ = socket.send_to(&transmission.message, Tool::socket_address(&transmission.peer));
        }
        let now = Tool::now(start);
        let until = endpoint
            .poll_timeout()
            .map_or(wait, |timeout| Duration::from_nanos(timeout.as_nanos().saturating_sub(now.as_nanos())));
        socket.set_read_timeout(Some(until.clamp(Duration::from_millis(1), wait))).expect("a timeout");
        let mut buffer = vec![0u8; 65536];
        if let Ok((count, from)) = socket.recv_from(&mut buffer) {
            endpoint.receive(Tool::endpoint(from), &buffer[..count], Tool::now(start), &mut Random);
        }
        let now = Tool::now(start);
        if endpoint.poll_timeout().is_some_and(|timeout| timeout <= now) {
            endpoint.expire(now);
        }
        while let Some(transmission) = endpoint.transmit() {
            let _ = socket.send_to(&transmission.message, Tool::socket_address(&transmission.peer));
        }
    }

    pub fn method(text: &str) -> CoAPCode {
        match text.to_ascii_uppercase().as_str() {
            "GET" => CoAPCode::GET,
            "POST" => CoAPCode::POST,
            "PUT" => CoAPCode::PUT,
            "DELETE" => CoAPCode::DELETE,
            "FETCH" => CoAPCode::FETCH,
            _ => Tool::fail(&format!("a method: {text}")),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("server") => Server::run(&arguments),
        Some("client") => Client::run(&arguments),
        _ => Tool::fail("usage: coap server PORT ... | coap client HOST PORT METHOD PATH ..."),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    Tool::fail("this platform has no random source for the example");
}

/// What a route of the server does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Hello,
    Echo,
    Large,
    Counter,
    Core,
}

/// The server: its routes, the observers of `/counter`, and its count.
pub struct Server {
    pub routes: Vec<(CoAPRule, Resource)>,
    pub observers: CoAPObservers,
    pub counter: u32,
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Server {
    /// The size of a block of `/large`.
    pub const BLOCK: usize = 256;

    pub fn run(arguments: &Arguments) {
        let port: u16 = arguments.position(1, "the port").parse().unwrap_or_else(|_| Tool::fail("a port"));
        let address = arguments.get("--address").unwrap_or("127.0.0.1");
        let socket = UdpSocket::bind((address, port)).unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        println!("listening: {}", socket.local_addr().expect("an address"));
        let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut Random).expect("an endpoint");
        let mut server = Server {
            routes: vec![
                (CoAPRule::new("/hello").with_method(CoAPCode::GET), Resource::Hello),
                (CoAPRule::new("/echo").with_method(CoAPCode::POST), Resource::Echo),
                (CoAPRule::new("/large").with_method(CoAPCode::GET), Resource::Large),
                (CoAPRule::new("/counter").with_method(CoAPCode::GET), Resource::Counter),
                (CoAPRule::new("/.well-known/core").with_method(CoAPCode::GET), Resource::Core),
            ],
            observers: CoAPObservers::default(),
            counter: 0,
        };
        let start = Clock::now();
        let mut next_count = Clock::now() + Duration::from_secs(1);
        loop {
            Tool::step(&mut endpoint, &socket, start, Duration::from_millis(100));
            while let Some(event) = endpoint.poll_event() {
                server.observers.handle(&event);
                if let CoAPEvent::Request { exchange, peer, message } = event {
                    let response = server.answer(peer, &message, Tool::now(start));
                    let _ = endpoint.respond(exchange, response, Tool::now(start), &mut Random);
                }
            }
            if Clock::now() >= next_count {
                next_count += Duration::from_secs(1);
                server.counter += 1;
                let notification = server.counter_response();
                let path = vec!["counter".to_string()];
                let now = Tool::now(start);
                let _ = server.observers.notify(&mut endpoint, &path, &notification, false, now, &mut Random);
            }
        }
    }

    pub fn counter_response(&self) -> CoAPMessage {
        let mut response = CoAPMessage::new(CoAPType::NonConfirmable, CoAPCode::CONTENT, 0);
        response.options.set_uint(CoAPOptionNumber::CONTENT_FORMAT, CoAPContentFormat::TEXT_PLAIN.0.into());
        response.options.set_uint(CoAPOptionNumber::MAX_AGE, 1);
        response.payload = self.counter.to_string().into_bytes();
        response
    }

    /// The response to `request` of `peer` (its type and token the endpoint's to set).
    pub fn answer(&mut self, peer: IPEndpoint, request: &CoAPMessage, now: Instant) -> CoAPMessage {
        println!("request: {} /{}", request.code, request.options.path().join("/"));
        let mut response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::CONTENT, 0);
        let text = |response: &mut CoAPMessage, format: CoAPContentFormat| {
            response.options.set_uint(CoAPOptionNumber::CONTENT_FORMAT, format.0.into());
        };
        let resource = self.routes.iter().find(|(rule, _)| rule.matches(request)).map(|(_, resource)| *resource);
        match resource {
            Some(Resource::Hello) => {
                text(&mut response, CoAPContentFormat::TEXT_PLAIN);
                response.payload = b"hello world".to_vec();
            }
            Some(Resource::Echo) => {
                response.code = CoAPCode::CHANGED;
                response.payload = request.payload.clone();
            }
            Some(Resource::Large) => {
                text(&mut response, CoAPContentFormat::TEXT_PLAIN);
                let body: Vec<u8> = (0..2000).map(|index| b'a' + (index % 26) as u8).collect();
                if CoAPBlockwise::respond(request, &body, Server::BLOCK, &mut response).is_err() {
                    response = CoAPMessage::new(CoAPType::Acknowledgement, CoAPCode::BAD_OPTION, 0);
                }
            }
            Some(Resource::Counter) => {
                response = self.counter_response();
                if self.observers.register(peer, request, now) {
                    response.options.set_uint(CoAPOptionNumber::OBSERVE, self.observers.next_value());
                }
            }
            Some(Resource::Core) => {
                text(&mut response, CoAPContentFormat::LINK_FORMAT);
                let links = [
                    CoAPLink::new("/hello").with("rt", Some("example.hello")).with("ct", Some("0")),
                    CoAPLink::new("/echo").with("rt", Some("example.echo")),
                    CoAPLink::new("/large").with("sz", Some("2000")),
                    CoAPLink::new("/counter").with("obs", None).with("ct", Some("0")),
                ];
                response.payload = CoAPLink::format(&links).into_bytes();
            }
            None if self.routes.iter().any(|(rule, _)| request.options.path() == rule.path) => {
                response.code = CoAPCode::METHOD_NOT_ALLOWED;
            }
            None => response.code = CoAPCode::NOT_FOUND,
        }
        response
    }
}

/// The client.
pub struct Client;

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
        let kind = if arguments.has("--non") { CoAPType::NonConfirmable } else { CoAPType::Confirmable };
        let mut request = CoAPMessage::new(kind, Tool::method(arguments.position(3, "the method")), 0);
        request.options.set_uri(arguments.position(4, "the path"), None);
        if let Some(payload) = arguments.get("--payload") {
            request.options.set_uint(CoAPOptionNumber::CONTENT_FORMAT, CoAPContentFormat::TEXT_PLAIN.0.into());
            request.payload = payload.as_bytes().to_vec();
        }
        let observe: Option<usize> = arguments.get("--observe").map(|count| count.parse().unwrap_or(1));
        if observe.is_some() {
            request.options.set_uint(CoAPOptionNumber::OBSERVE, 0);
        }
        let size: usize = arguments.get("--block").map_or(1024, |size| size.parse().unwrap_or(1024));
        let socket = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        let mut endpoint = CoAPEndpoint::new(CoAPConfig::default(), &mut Random).expect("an endpoint");
        let start = Clock::now();
        let peer = Tool::endpoint(server);
        let mut handle = endpoint
            .request(peer, request.clone(), Tool::now(start), &mut Random)
            .unwrap_or_else(|error| Tool::fail(&format!("request: {error}")));
        let mut blocks = CoAPBlockwise::new(1 << 20);
        let mut notifications = 0;
        let deadline = Clock::now() + Tool::BUDGET;
        while Clock::now() < deadline {
            Tool::step(&mut endpoint, &socket, start, Duration::from_millis(50));
            while let Some(event) = endpoint.poll_event() {
                match event {
                    CoAPEvent::Response { request: of, message } if of == handle => {
                        if observe.is_some() && message.options.observe().is_some() && notifications > 0 {
                            println!(
                                "notification: {} {}",
                                message.options.observe().unwrap_or(0),
                                String::from_utf8_lossy(&message.payload)
                            );
                            notifications += 1;
                            if Some(notifications) > observe {
                                // Forgotten: the next notification is rejected with RST (RFC 7641 §3.6).
                                endpoint.cancel(handle, Tool::now(start));
                                println!("cancelled");
                                Client::linger(&mut endpoint, &socket, start);
                                return;
                            }
                            continue;
                        }
                        // RFC 7959 §2.4: the next block, until the last.
                        if let Some(Ok(block)) = message.options.block(CoAPOptionNumber::BLOCK2) {
                            let etag = message.options.get(CoAPOptionNumber::ETAG);
                            match blocks.receive(block, &message.payload, etag) {
                                Ok(false) => {
                                    let mut next = request.clone();
                                    next.options =
                                        blocks.next_request(&request.options, block.size().min(size)).expect("options");
                                    handle = endpoint
                                        .request(peer, next, Tool::now(start), &mut Random)
                                        .unwrap_or_else(|error| Tool::fail(&format!("request: {error}")));
                                    continue;
                                }
                                Ok(true) => {}
                                Err(error) => Tool::fail(&format!("block: {error}")),
                            }
                        } else {
                            blocks.body = message.payload.clone();
                        }
                        println!("code: {}", message.code);
                        println!("{}", String::from_utf8_lossy(&blocks.body));
                        if observe.is_some() && message.options.observe().is_some() {
                            notifications = 1;
                            continue;
                        }
                        return;
                    }
                    CoAPEvent::Timeout { .. } => Tool::fail("no response"),
                    CoAPEvent::Reset { .. } => Tool::fail("the server reset the request"),
                    _ => {}
                }
            }
        }
        Tool::fail("no response in time");
    }

    /// Waits a few seconds, rejecting what arrives.
    pub fn linger(endpoint: &mut CoAPEndpoint, socket: &UdpSocket, start: Clock) {
        let until = Clock::now() + Duration::from_secs(3);
        while Clock::now() < until {
            Tool::step(endpoint, socket, start, Duration::from_millis(50));
            while endpoint.poll_event().is_some() {}
        }
    }
}
