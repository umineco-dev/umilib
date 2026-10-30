use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::runtime::Instant;

use super::{H1Config, H1Head, H1Parser, H1StartLine, H1Writer};
use crate::protocol::http::{
    HTTPAuthority, HTTPConnection, HTTPError, HTTPEvent, HTTPFields, HTTPMethod, HTTPRequest, HTTPReset, HTTPResponse,
    HTTPRole, HTTPStatus, HTTPStreamID, HTTPSyntax, HTTPTarget, HTTPVersion,
};

/// How the content of a message is delimited (RFC 9112 §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H1Framing {
    /// No content.
    None,
    /// Content-Length: the bytes left.
    Length(u64),
    Chunked,
    /// Content to the close of the connection (responses only, RFC 9112 §6.3 rule 8).
    Close,
    /// After a 2xx to CONNECT or a 101: the connection is a tunnel (RFC 9110 §7.8, §9.3.6).
    Tunnel,
}

impl H1Framing {
    /// The field that says this framing when the connection writes it
    /// itself: Content-Length 0 for no content, Transfer-Encoding chunked.
    pub fn field(self) -> Option<(&'static [u8], &'static [u8])> {
        match self {
            H1Framing::None => Some((b"content-length", b"0")),
            H1Framing::Chunked => Some((b"transfer-encoding", b"chunked")),
            _ => None,
        }
    }
}

/// Where the reading of chunked content is (RFC 9112 §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H1Chunk {
    /// The line of a chunk's size.
    Size,
    /// A chunk's data, the bytes left.
    Data(u64),
    /// The line end after a chunk's data.
    DataEnd,
    /// The trailer section after the last chunk.
    Trailers,
}

/// How the content being read is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H1Body {
    Length(u64),
    Chunked(H1Chunk),
    Close,
}

/// What the connection reads next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H1Reading {
    /// The head of a message.
    Head,
    /// The content of the message of an exchange.
    Body { stream: HTTPStreamID, body: H1Body },
    /// The bytes of a tunnel.
    Tunnel { stream: HTTPStreamID },
    /// Nothing until the final response to a request that asks for a
    /// tunnel (CONNECT, Upgrade): the response says whether what follows
    /// is the tunnel's or HTTP/1.1, so it is held unread (RFC 9931 §4).
    Waiting { stream: HTTPStreamID },
    /// Nothing more: the input is discarded.
    Done,
}

/// The state of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H1State {
    Open,
    /// No new exchange: those under way finish, then the connection closes (RFC 9112 §9.6).
    Closing,
    Closed,
}

/// An exchange: a request and its response, in the order of the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H1Exchange {
    pub stream: HTTPStreamID,
    pub method: HTTPMethod,
    /// The version of the peer's message: the request's for a server, the response's for a client.
    pub version: HTTPVersion,
    /// Content received and not read; whether all of the peer's message arrived.
    pub received: VecDeque<u8>,
    pub received_end: bool,
    /// Whether the content received is dropped: its reader abandoned it.
    pub discard: bool,
    /// The bytes to send, framed, and how this end's message is delimited.
    pub outgoing: Vec<u8>,
    pub framing: H1Framing,
    /// Whether this end sent the head of its message (the final one, for a
    /// server), and all of the message.
    pub sent_head: bool,
    pub sent_end: bool,
    /// A client: whether the final response arrived. A server: whether the
    /// request expects 100 (Continue), and whether it got one or a final response.
    pub final_response: bool,
    pub expect_continue: bool,
    /// Whether the connection closes after this exchange (RFC 9112 §9.6).
    pub close: bool,
    /// Whether the request asked to upgrade (RFC 9110 §7.8).
    pub upgrade: bool,
    /// Whether this exchange is the connection's own (an error response), not the application's.
    pub internal: bool,
}

impl H1Exchange {
    pub fn new(stream: HTTPStreamID, method: HTTPMethod) -> H1Exchange {
        H1Exchange {
            stream,
            method,
            version: HTTPVersion::HTTP1_1,
            received: VecDeque::new(),
            received_end: false,
            discard: false,
            outgoing: Vec::new(),
            framing: H1Framing::None,
            sent_head: false,
            sent_end: false,
            final_response: false,
            expect_continue: false,
            close: false,
            upgrade: false,
            internal: false,
        }
    }

    /// Whether the request asks for a tunnel: CONNECT, or an Upgrade (RFC 9110 §7.8, §9.3.6).
    pub fn asks_tunnel(&self) -> bool {
        self.method == HTTPMethod::CONNECT || self.upgrade
    }

    /// Whether the exchange is over: both messages sent and received whole,
    /// and the content received read.
    pub fn is_done(&self) -> bool {
        self.sent_end
            && self.received_end
            && self.outgoing.is_empty()
            && self.received.is_empty()
            && self.framing != H1Framing::Tunnel
    }
}

/// An HTTP/1.1 connection without I/O (RFC 9112), of a client or a server:
/// the caller gives it what arrives ([`H1Connection::receive`],
/// [`H1Connection::receive_close`]), sends what [`H1Connection::transmit`]
/// writes, closes the transport once [`H1Connection::wants_close`] after
/// sending everything, and calls [`H1Connection::expire`] at
/// [`H1Connection::poll_timeout`]. Exchanges are in order: responses are
/// sent in the order of their requests whatever order the application
/// gives them in (RFC 9112 §9.3.2). The connection does not add a Date
/// field: a server with a clock adds it (RFC 9110 §6.6.1).
#[derive(Clone, Debug)]
pub struct H1Connection {
    pub role: HTTPRole,
    pub config: H1Config,
    pub state: H1State,
    pub reading: H1Reading,
    /// What arrived and is not processed yet.
    pub incoming: Vec<u8>,
    /// The exchanges under way, oldest first.
    pub exchanges: VecDeque<H1Exchange>,
    pub next_stream: u64,
    pub events: VecDeque<HTTPEvent>,
    /// Whether the peer closed its side of the transport.
    pub peer_closed: bool,
    /// The version of the peer's latest message (a client's guide to framing).
    pub peer_version: HTTPVersion,
    /// When the last exchange ended or the connection opened, and when the head being read started.
    pub idle_since: Instant,
    pub head_since: Option<Instant>,
    /// The error that ended the connection.
    pub error: Option<HTTPError>,
    /// Exchanges whose application waits for room to write.
    pub blocked: Vec<HTTPStreamID>,
    /// The time of the latest call that gave one, for what a call without
    /// one processes (the input held until a response, say).
    pub now: Instant,
    /// How far the head or trailer section being read was scanned for its end.
    pub scanned: usize,
}

impl H1Connection {
    pub fn client(config: H1Config, now: Instant) -> H1Connection {
        H1Connection::new(HTTPRole::Client, config, now)
    }

    pub fn server(config: H1Config, now: Instant) -> H1Connection {
        H1Connection::new(HTTPRole::Server, config, now)
    }

    pub fn new(role: HTTPRole, config: H1Config, now: Instant) -> H1Connection {
        H1Connection {
            role,
            config,
            state: H1State::Open,
            reading: H1Reading::Head,
            incoming: Vec::new(),
            exchanges: VecDeque::new(),
            next_stream: 0,
            events: VecDeque::new(),
            peer_closed: false,
            peer_version: HTTPVersion::HTTP1_1,
            idle_since: now,
            head_since: None,
            error: None,
            blocked: Vec::new(),
            now,
            scanned: 0,
        }
    }

    // ---- Receiving ----

    /// Takes bytes that arrived at `now`.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if self.state == H1State::Closed {
            return;
        }
        self.now = now;
        self.incoming.extend_from_slice(bytes);
        if let Err(error) = self.process(now) {
            self.fail(error);
        }
        if self.exchanges.is_empty() {
            self.idle_since = now;
        }
    }

    /// The peer closed its side of the transport: a message delimited by
    /// the close ends, one cut short is an error (RFC 9112 §6.3, §8).
    pub fn receive_close(&mut self, now: Instant) {
        if self.state == H1State::Closed {
            return;
        }
        self.now = now;
        self.peer_closed = true;
        let result = self.process(now).and_then(|()| match self.reading {
            H1Reading::Body { stream, body: H1Body::Close } => {
                self.end_message(stream);
                Ok(())
            }
            H1Reading::Body { .. } => Err(HTTPError::Malformed("the connection closed inside a message")),
            H1Reading::Head if !self.incoming.iter().all(|byte| *byte == b'\r' || *byte == b'\n') => {
                Err(HTTPError::Malformed("the connection closed inside a head"))
            }
            H1Reading::Tunnel { stream } => {
                if let Some(exchange) = self.exchange_mut(stream) {
                    exchange.received_end = true;
                }
                self.push_event(HTTPEvent::End { stream });
                Ok(())
            }
            _ => Ok(()),
        });
        match result {
            Err(error) => self.fail(error),
            // A client whose responses did not all come gets an error; otherwise the connection is done.
            Ok(()) if self.role == HTTPRole::Client && self.exchanges.iter().any(|exchange| !exchange.received_end) => {
                self.fail(HTTPError::Malformed("the connection closed before a response"))
            }
            Ok(()) => {
                if self.state == H1State::Open {
                    self.state = H1State::Closing;
                }
            }
        }
    }

    /// Whether the caller should read more from the transport: the content
    /// and events held for the application are within their limits.
    pub fn wants_receive(&self) -> bool {
        self.state != H1State::Closed
            && !self.peer_closed
            && self.events.len() < self.config.http.maximum_events
            && self.incoming.len()
                <= self.config.http.maximum_field_section_size + self.config.http.maximum_target_length
            && self.exchanges.iter().all(|exchange| exchange.received.len() < self.config.http.maximum_buffered_content)
    }

    /// Processes what arrived as far as it goes: until it waits for more,
    /// for the application to read or answer, or for room for events.
    pub fn process(&mut self, now: Instant) -> Result<(), HTTPError> {
        let incoming = core::mem::take(&mut self.incoming);
        let mut offset = 0;
        let result = loop {
            if offset >= incoming.len() || self.events.len() >= self.config.http.maximum_events {
                break Ok(());
            }
            let input = &incoming[offset..];
            let step = match self.reading {
                H1Reading::Head => self.read_head(input, now),
                H1Reading::Body { stream, body } => self.read_body(stream, body, input),
                H1Reading::Tunnel { stream } => Ok(self.deliver(stream, input)),
                H1Reading::Waiting { .. } => Ok(0),
                H1Reading::Done => Ok(input.len()),
            };
            match step {
                Ok(0) => break Ok(()),
                Ok(consumed) => offset += consumed,
                Err(error) => break Err(error),
            }
        };
        self.incoming = incoming;
        self.incoming.drain(..offset.min(self.incoming.len()));
        result
    }

    /// Processes what waits, once the application made room for it: read
    /// content, answered requests, took events.
    pub fn resume(&mut self) {
        if self.incoming.is_empty() || self.state == H1State::Closed {
            return;
        }
        let now = self.now;
        if let Err(error) = self.process(now) {
            self.fail(error);
        }
    }

    /// Reads a head at the start of `input`; returns the bytes it took, 0 if it is not whole.
    pub fn read_head(&mut self, input: &[u8], now: Instant) -> Result<usize, HTTPError> {
        if self.state == H1State::Closed
            || self.role == HTTPRole::Server && self.exchanges.len() >= self.config.maximum_pipelined
        {
            return Ok(0);
        }
        // §2.2: a server ignores empty lines before a request line.
        let blank = if self.role == HTTPRole::Server {
            input.iter().take_while(|byte| **byte == b'\r' || **byte == b'\n').count()
        } else {
            0
        };
        let input = &input[blank..];
        if input.is_empty() {
            return Ok(blank);
        }
        self.head_since.get_or_insert(now);
        let length = match H1Parser::head_length(input, self.scanned) {
            Ok(length) => length,
            Err(scanned) => {
                self.scanned = scanned;
                let limit = self.config.http.maximum_field_section_size + self.config.http.maximum_target_length;
                if input.len() > limit {
                    let line = H1Parser::line(input).is_none()
                        || input.iter().position(|byte| *byte == b'\n') > Some(self.config.http.maximum_target_length);
                    return Err(if line {
                        HTTPError::TooLarge("a request target too long")
                    } else {
                        HTTPError::TooLarge("a header section too large")
                    });
                }
                return Ok(blank);
            }
        };
        self.scanned = 0;
        let head = H1Parser::parse_head(&input[..length], self.role == HTTPRole::Server)?;
        self.head_since = None;
        if head.fields.size() > self.config.http.maximum_field_section_size {
            return Err(HTTPError::TooLarge("a header section too large"));
        }
        match self.role {
            HTTPRole::Server => self.receive_request(head)?,
            HTTPRole::Client => self.receive_response(head)?,
        }
        Ok(blank + length)
    }

    /// A request's head arrived (RFC 9112 §3, §6.3, RFC 9110 §7.2).
    pub fn receive_request(&mut self, head: H1Head) -> Result<(), HTTPError> {
        let H1StartLine::Request { method, target, version } = head.start else {
            return Err(HTTPError::Malformed("a status line where a request was expected"));
        };
        if version.major != 1 {
            return Err(HTTPError::Protocol { code: 505, reason: "an HTTP version other than 1.x" });
        }
        if target.len() > self.config.http.maximum_target_length {
            return Err(HTTPError::TooLarge("a request target too long"));
        }
        let fields = head.fields;
        // A minor version above 1 is read as 1.1 (RFC 9110 §2.5).
        let version = if version.minor >= 1 { HTTPVersion::HTTP1_1 } else { HTTPVersion::HTTP1_0 };
        self.peer_version = version;
        let hosts = fields.get_all(b"host").count();
        if version == HTTPVersion::HTTP1_1 && hosts != 1 || hosts > 1 {
            return Err(HTTPError::Malformed("a request without one Host field"));
        }
        let host = fields.get(b"host").filter(|host| !host.is_empty());
        if let Some(host) = host {
            HTTPAuthority::parse(host)?;
        }
        let (scheme, authority, path) = match HTTPTarget::parse(&target)? {
            HTTPTarget::Origin(path) => (Some(self.config.scheme.clone()), host.map(<[u8]>::to_vec), path),
            // §3.2.2: the absolute-form's authority, not Host.
            HTTPTarget::Absolute { scheme, authority, path } => (Some(scheme), Some(authority), path),
            HTTPTarget::Authority(authority) if method == HTTPMethod::CONNECT => (None, Some(authority), Vec::new()),
            HTTPTarget::Asterisk if method == HTTPMethod::OPTIONS => {
                (Some(self.config.scheme.clone()), host.map(<[u8]>::to_vec), b"*".to_vec())
            }
            _ => return Err(HTTPError::Malformed("a request target of the wrong form for its method")),
        };
        let framing = H1Connection::request_framing(&fields, version)?;
        let stream = HTTPStreamID(self.next_stream);
        self.next_stream += 1;
        let mut exchange = H1Exchange::new(stream, method.clone());
        exchange.version = version;
        exchange.close = H1Connection::closes(&fields, version) || self.state != H1State::Open;
        // §6.1: TE and Content-Length together close the connection afterwards.
        exchange.close |= fields.contains(b"transfer-encoding") && fields.contains(b"content-length");
        exchange.expect_continue = version == HTTPVersion::HTTP1_1
            && fields.get(b"expect").is_some_and(|expect| expect.eq_ignore_ascii_case(b"100-continue"));
        // An Upgrade of an HTTP/1.0 request is ignored (RFC 9110 §7.8).
        exchange.upgrade = version == HTTPVersion::HTTP1_1
            && fields.contains(b"upgrade")
            && fields.contains_token(b"connection", b"upgrade");
        let request = HTTPRequest { method, scheme, authority, path, protocol: None, fields };
        request.check()?;
        let end = framing == H1Framing::None;
        exchange.received_end = end;
        if exchange.close {
            self.state = H1State::Closing;
        }
        let asks_tunnel = exchange.asks_tunnel();
        self.exchanges.push_back(exchange);
        self.reading = match framing {
            H1Framing::Length(length) => H1Reading::Body { stream, body: H1Body::Length(length) },
            H1Framing::Chunked => H1Reading::Body { stream, body: H1Body::Chunked(H1Chunk::Size) },
            // No further request is read after one that closes (RFC 9112 §9.6).
            _ if self.state != H1State::Open => H1Reading::Done,
            _ if asks_tunnel => H1Reading::Waiting { stream },
            _ => H1Reading::Head,
        };
        self.push_event(HTTPEvent::Request { stream, request, end });
        Ok(())
    }

    /// The framing of a request's content (RFC 9112 §6.1, §6.3 rules 3 to 7).
    pub fn request_framing(fields: &HTTPFields, version: HTTPVersion) -> Result<H1Framing, HTTPError> {
        if let Some(codings) = fields.combined(b"transfer-encoding") {
            if version == HTTPVersion::HTTP1_0 {
                return Err(HTTPError::Malformed("Transfer-Encoding in an HTTP/1.0 request"));
            }
            if fields.contains(b"content-length") {
                return Err(HTTPError::Malformed("both Transfer-Encoding and Content-Length"));
            }
            let codings = HTTPSyntax::list(&codings);
            match codings.last() {
                Some(last) if last.eq_ignore_ascii_case(b"chunked") && codings.len() == 1 => {
                    return Ok(H1Framing::Chunked);
                }
                Some(last) if last.eq_ignore_ascii_case(b"chunked") => {
                    return Err(HTTPError::Protocol { code: 501, reason: "a transfer coding other than chunked" });
                }
                _ => return Err(HTTPError::Malformed("chunked not the final transfer coding")),
            }
        }
        Ok(match fields.content_length()? {
            Some(0) | None => H1Framing::None,
            Some(length) => H1Framing::Length(length),
        })
    }

    /// Whether a message of `version` with `fields` closes the connection
    /// after its exchange (RFC 9112 §9.3, §9.6, Appendix C.2.2).
    pub fn closes(fields: &HTTPFields, version: HTTPVersion) -> bool {
        fields.contains_token(b"connection", b"close")
            || version == HTTPVersion::HTTP1_0 && !fields.contains_token(b"connection", b"keep-alive")
    }

    /// A response's head arrived for the oldest exchange waiting for one (RFC 9112 §4, §6.3, §9.3).
    pub fn receive_response(&mut self, head: H1Head) -> Result<(), HTTPError> {
        let H1StartLine::Response { version, status } = head.start else {
            return Err(HTTPError::Malformed("a request line where a response was expected"));
        };
        if version.major != 1 {
            return Err(HTTPError::Malformed("an HTTP version other than 1.x"));
        }
        let version = if version.minor >= 1 { HTTPVersion::HTTP1_1 } else { HTTPVersion::HTTP1_0 };
        self.peer_version = version;
        let fields = head.fields;
        let exchange = self
            .exchanges
            .iter_mut()
            .find(|exchange| !exchange.final_response)
            .ok_or(HTTPError::Malformed("a response to no request"))?;
        let stream = exchange.stream;
        let response = HTTPResponse { status, fields };
        // Interim responses come before the final one; 101 switches protocols (RFC 9110 §15.2).
        if status.is_informational() && status != HTTPStatus::SWITCHING_PROTOCOLS {
            self.push_event(HTTPEvent::Response { stream, response, end: false });
            return Ok(());
        }
        exchange.final_response = true;
        exchange.version = version;
        exchange.close |= H1Connection::closes(&response.fields, version);
        let connect = exchange.method == HTTPMethod::CONNECT && status.is_successful();
        let framing = if status == HTTPStatus::SWITCHING_PROTOCOLS {
            if !exchange.upgrade {
                return Err(HTTPError::Malformed("101 without an upgrade asked for"));
            }
            H1Framing::Tunnel
        } else if connect {
            H1Framing::Tunnel
        } else if exchange.method == HTTPMethod::HEAD || status.has_no_content() {
            H1Framing::None
        } else if let Some(codings) = response.fields.combined(b"transfer-encoding") {
            let codings = HTTPSyntax::list(&codings);
            match codings.last() {
                Some(last)
                    if last.eq_ignore_ascii_case(b"chunked")
                        && codings.len() == 1
                        && version != HTTPVersion::HTTP1_0 =>
                {
                    H1Framing::Chunked
                }
                _ => return Err(HTTPError::Malformed("a transfer coding other than chunked")),
            }
        } else {
            match response.fields.content_length()? {
                Some(0) => H1Framing::None,
                Some(length) => H1Framing::Length(length),
                None => H1Framing::Close,
            }
        };
        if matches!(framing, H1Framing::Close) {
            exchange.close = true;
        }
        if exchange.close && self.state == H1State::Open {
            self.state = H1State::Closing;
        }
        let end = framing == H1Framing::None;
        exchange.received_end = end;
        if framing == H1Framing::Tunnel {
            // The stream carries the tunnel's bytes now: those of the
            // server, and the client's unless its request ended the stream.
            exchange.framing = H1Framing::Tunnel;
        } else if exchange.framing == H1Framing::Tunnel {
            // Refused: the request was its head alone.
            exchange.framing = H1Framing::None;
            exchange.sent_end = true;
        }
        self.reading = match framing {
            H1Framing::Length(length) => H1Reading::Body { stream, body: H1Body::Length(length) },
            H1Framing::Chunked => H1Reading::Body { stream, body: H1Body::Chunked(H1Chunk::Size) },
            H1Framing::Close => H1Reading::Body { stream, body: H1Body::Close },
            H1Framing::Tunnel => H1Reading::Tunnel { stream },
            H1Framing::None => H1Reading::Head,
        };
        self.push_event(HTTPEvent::Response { stream, response, end });
        self.collect();
        Ok(())
    }

    /// Reads content of `stream` delimited by `body` from `input`; returns the bytes it took.
    pub fn read_body(&mut self, stream: HTTPStreamID, body: H1Body, input: &[u8]) -> Result<usize, HTTPError> {
        match body {
            H1Body::Length(left) => {
                let take = (left.min(input.len() as u64)) as usize;
                let taken = self.deliver(stream, &input[..take]);
                let left = left - taken as u64;
                if left == 0 {
                    self.end_message(stream);
                } else {
                    self.reading = H1Reading::Body { stream, body: H1Body::Length(left) };
                }
                Ok(taken)
            }
            H1Body::Close => Ok(self.deliver(stream, input)),
            H1Body::Chunked(chunk) => self.read_chunked(stream, chunk, input),
        }
    }

    /// Reads chunked content (RFC 9112 §7.1).
    pub fn read_chunked(&mut self, stream: HTTPStreamID, chunk: H1Chunk, input: &[u8]) -> Result<usize, HTTPError> {
        let line_limit = self.config.maximum_chunk_line;
        match chunk {
            H1Chunk::Size => {
                let Some((newline, end)) = H1Parser::line(input) else {
                    if input.len() > line_limit {
                        return Err(HTTPError::TooLarge("a chunk line too long"));
                    }
                    return Ok(0);
                };
                if end > line_limit {
                    return Err(HTTPError::TooLarge("a chunk line too long"));
                }
                let size = H1Parser::chunk_size(&input[..end])?;
                let next = if size == 0 { H1Chunk::Trailers } else { H1Chunk::Data(size) };
                self.reading = H1Reading::Body { stream, body: H1Body::Chunked(next) };
                Ok(newline + 1)
            }
            H1Chunk::Data(left) => {
                let take = (left.min(input.len() as u64)) as usize;
                let taken = self.deliver(stream, &input[..take]);
                let left = left - taken as u64;
                let next = if left == 0 { H1Chunk::DataEnd } else { H1Chunk::Data(left) };
                self.reading = H1Reading::Body { stream, body: H1Body::Chunked(next) };
                Ok(taken)
            }
            H1Chunk::DataEnd => match input {
                [b'\r', b'\n', ..] => {
                    self.reading = H1Reading::Body { stream, body: H1Body::Chunked(H1Chunk::Size) };
                    Ok(2)
                }
                [b'\n', ..] => {
                    self.reading = H1Reading::Body { stream, body: H1Body::Chunked(H1Chunk::Size) };
                    Ok(1)
                }
                [b'\r'] | [] => Ok(0),
                _ => Err(HTTPError::Malformed("chunk data longer than its size")),
            },
            H1Chunk::Trailers => {
                let length = match H1Parser::head_length(input, self.scanned) {
                    Ok(length) => length,
                    Err(scanned) => {
                        self.scanned = scanned;
                        if input.len() > self.config.http.maximum_field_section_size {
                            return Err(HTTPError::TooLarge("a trailer section too large"));
                        }
                        return Ok(0);
                    }
                };
                self.scanned = 0;
                let fields = H1Parser::parse_fields(&input[..length], self.role == HTTPRole::Client)?;
                if fields.size() > self.config.http.maximum_field_section_size {
                    return Err(HTTPError::TooLarge("a trailer section too large"));
                }
                if !fields.is_empty() {
                    self.push_event(HTTPEvent::Trailers { stream, fields });
                }
                self.end_message(stream);
                Ok(length)
            }
        }
    }

    /// Holds content of `stream` for its application, within the limit;
    /// returns how much it took.
    pub fn deliver(&mut self, stream: HTTPStreamID, data: &[u8]) -> usize {
        let limit = self.config.http.maximum_buffered_content;
        let Some(exchange) = self.exchange_mut(stream) else { return data.len() };
        if exchange.discard {
            return data.len();
        }
        let room = limit.saturating_sub(exchange.received.len());
        let taken = data.len().min(room);
        let was_empty = exchange.received.is_empty();
        exchange.received.extend(&data[..taken]);
        if taken > 0 && was_empty {
            self.push_event(HTTPEvent::Data { stream });
        }
        taken
    }

    /// The message of `stream` arrived whole. A request answered with 101
    /// or a 2xx to CONNECT turns into its tunnel now (RFC 9110 §7.8).
    pub fn end_message(&mut self, stream: HTTPStreamID) {
        let closing = self.state != H1State::Open;
        let server = self.role == HTTPRole::Server;
        let (mut tunnel, mut waiting) = (false, false);
        if let Some(exchange) = self.exchange_mut(stream) {
            tunnel = exchange.framing == H1Framing::Tunnel && exchange.final_response;
            waiting = server && exchange.asks_tunnel() && !exchange.final_response;
            exchange.received_end = !tunnel;
        }
        self.reading = match () {
            _ if tunnel => H1Reading::Tunnel { stream },
            _ if waiting => H1Reading::Waiting { stream },
            _ if closing && self.role == HTTPRole::Server => H1Reading::Done,
            _ => H1Reading::Head,
        };
        self.push_event(HTTPEvent::End { stream });
        self.collect();
    }

    // ---- Sending ----

    /// Writes what is ready to send into `out` (appended): each exchange's
    /// bytes in order, those of one only once the one before sent all of
    /// its message, so that requests and responses keep their order.
    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        for exchange in &mut self.exchanges {
            out.append(&mut exchange.outgoing);
            if !exchange.sent_end {
                break;
            }
        }
        self.collect();
        // Room again for the writers that waited, and for requests.
        for stream in core::mem::take(&mut self.blocked) {
            self.push_event(HTTPEvent::Writable { stream });
        }
        self.resume();
    }

    /// Removes the exchanges at the front that are over. After one that
    /// closes the connection, nothing more goes: a client is told that its
    /// later requests were not processed (RFC 9112 §9.6).
    pub fn collect(&mut self) {
        // Once a server's response is whole, the rest of its request is
        // not delivered: read to its end and dropped (RFC 9112 §9.3).
        for exchange in &mut self.exchanges {
            if self.role == HTTPRole::Server
                && exchange.final_response
                && exchange.sent_end
                && exchange.framing != H1Framing::Tunnel
                && !exchange.discard
            {
                exchange.discard = true;
                exchange.received.clear();
            }
        }
        while self.exchanges.front().is_some_and(H1Exchange::is_done) {
            let Some(exchange) = self.exchanges.pop_front() else { break };
            if exchange.close {
                self.state = H1State::Closing;
                self.reading = H1Reading::Done;
                if self.role == HTTPRole::Client && !self.exchanges.is_empty() {
                    self.exchanges.clear();
                    self.push_event(HTTPEvent::GoAway { last: exchange.stream });
                }
                self.exchanges.clear();
            }
        }
    }

    /// Whether the caller should close the transport once it sent what
    /// [`H1Connection::transmit`] wrote: the connection closed, or closes
    /// and has nothing more to send or, for a client, to receive.
    pub fn wants_close(&self) -> bool {
        self.state == H1State::Closed
            || self.state == H1State::Closing
                && self.exchanges.iter().all(|exchange| {
                    exchange.outgoing.is_empty()
                        && exchange.sent_end
                        && (self.role == HTTPRole::Server || exchange.received_end)
                })
    }

    /// The exchange of `stream`.
    pub fn exchange_mut(&mut self, stream: HTTPStreamID) -> Option<&mut H1Exchange> {
        self.exchanges.iter_mut().find(|exchange| exchange.stream == stream)
    }

    /// Ends the connection on `error`. A server answers what it could not
    /// read with an error response (RFC 9112 §3, §5, §6.3), then closes.
    pub fn fail(&mut self, error: HTTPError) {
        self.error = Some(error);
        self.reading = H1Reading::Done;
        self.incoming.clear();
        if self.role == HTTPRole::Server {
            let status = match error {
                HTTPError::TooLarge(reason) if reason.contains("target") => HTTPStatus::URI_TOO_LONG,
                HTTPError::TooLarge(_) => HTTPStatus::REQUEST_HEADER_FIELDS_TOO_LARGE,
                HTTPError::Protocol { code, .. } => HTTPStatus::new(code as u16).unwrap_or(HTTPStatus::BAD_REQUEST),
                _ => HTTPStatus::BAD_REQUEST,
            };
            // Only when no response of the exchange in progress went out.
            let sent = self.exchanges.back().is_some_and(|exchange| exchange.sent_head);
            if !sent {
                let mut exchange = H1Exchange::new(HTTPStreamID(u64::MAX), HTTPMethod::GET);
                exchange.internal = true;
                let fields = HTTPFields::new();
                H1Writer::response_head(
                    status,
                    &fields,
                    &[(b"content-length", b"0"), (b"connection", b"close")],
                    &mut exchange.outgoing,
                );
                exchange.sent_head = true;
                exchange.sent_end = true;
                exchange.received_end = true;
                exchange.close = true;
                self.exchanges.retain(|exchange| exchange.sent_head);
                self.exchanges.push_back(exchange);
                self.state = H1State::Closing;
                self.push_event(HTTPEvent::Closed { error: Some(error) });
                return;
            }
        }
        self.state = H1State::Closed;
        self.exchanges.clear();
        self.push_event(HTTPEvent::Closed { error: Some(error) });
    }

    /// Queues `event`. None is dropped: reading stops once
    /// `maximum_events` wait ([`H1Connection::process`]), so the queue stays
    /// near that size.
    pub fn push_event(&mut self, event: HTTPEvent) {
        self.events.push_back(event);
    }

    // ---- Timers ----

    /// When [`H1Connection::expire`] is due: the end of a head that takes
    /// too long, or of an idle connection.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == H1State::Closed {
            return None;
        }
        let head = self.head_since.zip(self.config.head_timeout).map(|(since, timeout)| since + timeout);
        let idle = (self.exchanges.is_empty() && self.incoming.is_empty())
            .then_some(())
            .and(self.config.idle_timeout)
            .map(|timeout| self.idle_since + timeout);
        [head, idle].into_iter().flatten().min()
    }

    /// The timers due at `now`: a head too slow is 408 for a server (RFC
    /// 9110 §15.5.9), an idle connection closes (RFC 9112 §9.5).
    pub fn expire(&mut self, now: Instant) {
        self.now = now;
        if self.poll_timeout().is_none_or(|deadline| deadline > now) {
            return;
        }
        if self.head_since.is_some() {
            self.head_since = None;
            match self.role {
                HTTPRole::Server => self.fail(HTTPError::Protocol { code: 408, reason: "a head that came too slowly" }),
                HTTPRole::Client => self.fail(HTTPError::Malformed("a response that came too slowly")),
            }
            return;
        }
        self.state = H1State::Closed;
        self.push_event(HTTPEvent::Closed { error: None });
    }

    /// Whether ready: an exchange may start (a client) or the connection takes requests.
    pub fn is_open(&self) -> bool {
        self.state == H1State::Open
    }

    /// The framing a server gives its response to `exchange`, and whether
    /// it writes the framing's field ([`H1Framing::field`]) (RFC 9112 §6, §9.6): none for HEAD, 1xx, 204 and 304,
    /// a tunnel after 101 or a 2xx to CONNECT, the Content-Length given,
    /// else chunked to HTTP/1.1 and to the close for HTTP/1.0.
    pub fn response_framing(
        exchange: &H1Exchange,
        response: &HTTPResponse,
        end: bool,
    ) -> Result<(H1Framing, bool), HTTPError> {
        let status = response.status;
        let length = response.fields.content_length()?;
        let mut announced = false;
        let framing_given = response.fields.contains(b"transfer-encoding");
        if (status.is_informational() || status == HTTPStatus::NO_CONTENT) && (length.is_some() || framing_given) {
            return Err(HTTPError::Malformed("framing fields in a 1xx or 204 response"));
        }
        if framing_given {
            return Err(HTTPError::Malformed("a Transfer-Encoding the connection writes itself"));
        }
        let framing = if status == HTTPStatus::SWITCHING_PROTOCOLS {
            if !exchange.upgrade {
                return Err(HTTPError::Malformed("101 without an upgrade asked for"));
            }
            H1Framing::Tunnel
        } else if exchange.method == HTTPMethod::CONNECT && status.is_successful() {
            if length.is_some() {
                return Err(HTTPError::Malformed("Content-Length in a 2xx to CONNECT"));
            }
            H1Framing::Tunnel
        } else if exchange.method == HTTPMethod::HEAD || status.has_no_content() {
            H1Framing::None
        } else if let Some(length) = length {
            if length == 0 { H1Framing::None } else { H1Framing::Length(length) }
        } else if end {
            announced = true;
            H1Framing::None
        } else if exchange.version == HTTPVersion::HTTP1_1 {
            announced = true;
            H1Framing::Chunked
        } else {
            H1Framing::Close
        };
        Ok((framing, announced))
    }

    /// The bytes of a stream's outgoing buffer still free.
    pub fn room(&self, exchange: &H1Exchange) -> usize {
        self.config.http.maximum_buffered_content.saturating_sub(exchange.outgoing.len())
    }
}

impl HTTPConnection for H1Connection {
    fn version(&self) -> HTTPVersion {
        HTTPVersion::HTTP1_1
    }

    fn role(&self) -> HTTPRole {
        self.role
    }

    /// Writes a request (RFC 9112 §3): the target in origin-form, the
    /// authority-form for CONNECT, "*" for a server-wide OPTIONS; Host
    /// from the authority unless given; Content-Length 0 for an empty
    /// request whose method takes content, chunked when content follows
    /// without a Content-Length (the server is taken to be HTTP/1.1). A
    /// CONNECT or an Upgrade request is its head alone: unless `end`, its
    /// stream stays open for the tunnel, which takes data once the 2xx or
    /// 101 arrived, never before (RFC 9931 §4, §8).
    fn send_request(&mut self, request: &HTTPRequest, end: bool) -> Result<HTTPStreamID, HTTPError> {
        if self.role != HTTPRole::Client
            || self.state != H1State::Open
            || self.exchanges.len() >= self.config.maximum_pipelined
        {
            return Err(HTTPError::State);
        }
        request.check()?;
        if request.protocol.is_some() {
            return Err(HTTPError::Malformed("an extended CONNECT over HTTP/1.1"));
        }
        let target: &[u8] = if request.method == HTTPMethod::CONNECT {
            request.authority.as_deref().unwrap_or_default()
        } else if request.path.is_empty() {
            b"/"
        } else {
            &request.path
        };
        let fields = &request.fields;
        let length = fields.content_length()?;
        if fields.contains(b"transfer-encoding") {
            return Err(HTTPError::Malformed("a Transfer-Encoding the connection writes itself"));
        }
        let mut extra: Vec<(&[u8], &[u8])> = Vec::new();
        if !fields.contains(b"host") {
            extra.push((b"host", request.authority.as_deref().unwrap_or_default()));
        }
        let takes_content = !matches!(
            request.method,
            HTTPMethod::GET
                | HTTPMethod::HEAD
                | HTTPMethod::DELETE
                | HTTPMethod::OPTIONS
                | HTTPMethod::TRACE
                | HTTPMethod::CONNECT
        );
        // A request that opens a tunnel is its head alone; what follows is
        // the tunnel's, once it opens (RFC 9931 §4, §7.1, §8).
        let upgrade = fields.contains(b"upgrade") && fields.contains_token(b"connection", b"upgrade");
        let tunnel = request.method == HTTPMethod::CONNECT || upgrade;
        let framing = match length {
            Some(0) => H1Framing::None,
            Some(_) if tunnel => return Err(HTTPError::Malformed("content in a request that opens a tunnel")),
            Some(length) => H1Framing::Length(length),
            None if end || tunnel => {
                if takes_content {
                    extra.push((b"content-length", b"0"));
                }
                H1Framing::None
            }
            None => {
                extra.push((b"transfer-encoding", b"chunked"));
                H1Framing::Chunked
            }
        };
        let stream = HTTPStreamID(self.next_stream);
        self.next_stream += 1;
        let mut exchange = H1Exchange::new(stream, request.method.clone());
        H1Writer::request_head(&request.method, target, fields, &extra, &mut exchange.outgoing);
        exchange.sent_head = true;
        // Unless `end`, a tunnel's request keeps its stream open for the
        // tunnel, which takes data once its 2xx or 101 arrived.
        exchange.framing = if tunnel && !end { H1Framing::Tunnel } else { framing };
        exchange.sent_end = framing == H1Framing::None && (end || !tunnel);
        exchange.close = fields.contains_token(b"connection", b"close");
        exchange.upgrade = upgrade;
        if exchange.close {
            self.state = H1State::Closing;
        }
        self.exchanges.push_back(exchange);
        Ok(stream)
    }

    fn send_response(&mut self, stream: HTTPStreamID, response: &HTTPResponse, end: bool) -> Result<(), HTTPError> {
        if self.role != HTTPRole::Server || self.state == H1State::Closed {
            return Err(HTTPError::State);
        }
        let closing = self.state != H1State::Open;
        let exchange = self.exchange_mut(stream).ok_or(HTTPError::State)?;
        if exchange.final_response {
            return Err(HTTPError::State);
        }
        let status = response.status;
        if status.is_informational() && status != HTTPStatus::SWITCHING_PROTOCOLS {
            // Interim responses go to HTTP/1.1 clients only (RFC 9110 §15.2).
            if exchange.version == HTTPVersion::HTTP1_1 {
                H1Writer::response_head(status, &response.fields, &[], &mut exchange.outgoing);
                if status == HTTPStatus::CONTINUE {
                    exchange.expect_continue = false;
                }
            }
            return Ok(());
        }
        let (framing, announced) = H1Connection::response_framing(exchange, response, end)?;
        let mut extra: Vec<(&[u8], &[u8])> = framing.field().filter(|_| announced).into_iter().collect();
        // A refused CONNECT closes the connection, and nothing after it is
        // read as a request: it may be the client's tunnel (RFC 9931 §8).
        let refused_connect = exchange.method == HTTPMethod::CONNECT && framing != H1Framing::Tunnel;
        exchange.close |= closing || framing == H1Framing::Close || refused_connect;
        if exchange.close && !response.fields.contains_token(b"connection", b"close") {
            extra.push((b"connection", b"close"));
        } else if exchange.version == HTTPVersion::HTTP1_0 && !exchange.close {
            extra.push((b"connection", b"keep-alive"));
        }
        H1Writer::response_head(status, &response.fields, &extra, &mut exchange.outgoing);
        exchange.final_response = true;
        exchange.expect_continue = false;
        exchange.sent_head = true;
        exchange.framing = framing;
        exchange.sent_end = framing == H1Framing::None;
        let mut tunnel = false;
        if framing == H1Framing::Tunnel {
            // The tunnel's bytes start after the request (RFC 9110 §7.8).
            if exchange.received_end {
                exchange.received_end = false;
                tunnel = true;
            }
        }
        let close = exchange.close;
        let held = self.reading == H1Reading::Waiting { stream };
        if tunnel {
            self.reading = H1Reading::Tunnel { stream };
        } else if held && refused_connect {
            self.reading = H1Reading::Done;
            self.incoming.clear();
        } else if held {
            // A refused Upgrade: HTTP/1.1 goes on (RFC 9931 §5).
            self.reading = H1Reading::Head;
        }
        if close {
            self.state = H1State::Closing;
        }
        self.collect();
        if held {
            self.resume();
        }
        Ok(())
    }

    fn send_data(&mut self, stream: HTTPStreamID, data: &[u8], end: bool) -> Result<usize, HTTPError> {
        if self.state == H1State::Closed {
            return Err(HTTPError::State);
        }
        let limit = self.config.http.maximum_buffered_content;
        let exchange = self.exchange_mut(stream).ok_or(HTTPError::State)?;
        // A message whose framing ended it (no content, or all of its
        // Content-Length) takes an empty last write, as other versions do.
        if exchange.sent_end
            && data.is_empty()
            && end
            && matches!(exchange.framing, H1Framing::None | H1Framing::Length(0))
        {
            return Ok(0);
        }
        if !exchange.sent_head || exchange.sent_end {
            return Err(HTTPError::State);
        }
        let room = limit.saturating_sub(exchange.outgoing.len());
        let count = data.len().min(room);
        let finished = end && count == data.len();
        match exchange.framing {
            H1Framing::None => return Err(HTTPError::State),
            H1Framing::Length(left) => {
                if count as u64 > left || finished && count as u64 != left {
                    return Err(HTTPError::Malformed("content of another length than Content-Length"));
                }
                exchange.outgoing.extend_from_slice(&data[..count]);
                exchange.framing = H1Framing::Length(left - count as u64);
                exchange.sent_end = left == count as u64;
            }
            H1Framing::Chunked => {
                if count > 0 {
                    H1Writer::chunk(&data[..count], &mut exchange.outgoing);
                }
                if finished {
                    H1Writer::last_chunk(&HTTPFields::new(), &mut exchange.outgoing);
                    exchange.sent_end = true;
                }
            }
            // Before its 2xx or 101, a tunnel takes no data (RFC 9931 §4, §8).
            H1Framing::Tunnel if !exchange.final_response => return Err(HTTPError::State),
            H1Framing::Close | H1Framing::Tunnel => {
                exchange.outgoing.extend_from_slice(&data[..count]);
                if finished {
                    exchange.sent_end = true;
                    exchange.close = true;
                    exchange.framing = H1Framing::Close;
                }
            }
        }
        if count < data.len() && !self.blocked.contains(&stream) {
            self.blocked.push(stream);
        }
        if finished && self.state == H1State::Open && self.exchange_mut(stream).is_some_and(|exchange| exchange.close) {
            self.state = H1State::Closing;
        }
        self.collect();
        Ok(count)
    }

    fn send_trailers(&mut self, stream: HTTPStreamID, trailers: &HTTPFields) -> Result<(), HTTPError> {
        let exchange = self.exchange_mut(stream).ok_or(HTTPError::State)?;
        if exchange.framing != H1Framing::Chunked || exchange.sent_end {
            return Err(HTTPError::State);
        }
        H1Writer::last_chunk(trailers, &mut exchange.outgoing);
        exchange.sent_end = true;
        self.collect();
        Ok(())
    }

    /// Reads content; a server first sends 100 (Continue) to a request that
    /// expects it, when configured to.
    fn read_data(&mut self, stream: HTTPStreamID, out: &mut [u8]) -> Result<usize, HTTPError> {
        let automatic = self.config.continue_automatically && self.role == HTTPRole::Server;
        let started = stream.0 < self.next_stream;
        let Some(exchange) = self.exchange_mut(stream) else {
            // An exchange over and forgotten has nothing more to read.
            return if started { Ok(0) } else { Err(HTTPError::State) };
        };
        if automatic && exchange.expect_continue && !exchange.final_response {
            H1Writer::response_head(HTTPStatus::CONTINUE, &HTTPFields::new(), &[], &mut exchange.outgoing);
            exchange.expect_continue = false;
        }
        let count = out.len().min(exchange.received.len());
        for (slot, byte) in out.iter_mut().zip(exchange.received.drain(..count)) {
            *slot = byte;
        }
        self.collect();
        self.resume();
        Ok(count)
    }

    /// A server's [`HTTPReset::NoError`] after its whole response drops the
    /// rest of the request, which [`H1Connection::collect`] does anyway.
    /// Otherwise HTTP/1.1 has no reset of one exchange (RFC 9112 §9.6): a
    /// client's connection closes now; a server's once what it queued is
    /// sent, the exchange's message cut short, nothing more read.
    fn reset(&mut self, stream: HTTPStreamID, reason: HTTPReset) -> Result<(), HTTPError> {
        let server = self.role == HTTPRole::Server;
        let started = stream.0 < self.next_stream;
        let Some(exchange) = self.exchange_mut(stream) else {
            // An exchange over and forgotten needs no reset.
            return if started { Ok(()) } else { Err(HTTPError::State) };
        };
        if server && reason == HTTPReset::NoError && exchange.final_response && exchange.sent_end {
            self.collect();
            return Ok(());
        }
        if !server {
            self.state = H1State::Closed;
            self.exchanges.clear();
            self.push_event(HTTPEvent::Closed { error: None });
            return Ok(());
        }
        exchange.sent_end = true;
        exchange.received_end = true;
        exchange.received.clear();
        exchange.close = true;
        let position = self.exchanges.iter().position(|exchange| exchange.stream == stream).unwrap_or(0);
        self.exchanges.truncate(position + 1);
        self.state = H1State::Closing;
        self.reading = H1Reading::Done;
        self.incoming.clear();
        Ok(())
    }

    fn poll_event(&mut self) -> Option<HTTPEvent> {
        let event = self.events.pop_front();
        if self.events.len() < self.config.http.maximum_events {
            self.resume();
        }
        event
    }

    /// A server sends "close" in its next response and closes after it; a
    /// client sends no more requests and closes once its responses came (RFC 9112 §9.6).
    fn shutdown(&mut self) {
        if self.state == H1State::Open {
            self.state = H1State::Closing;
            if let Some(exchange) = self.exchanges.back_mut() {
                exchange.close = true;
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.state == H1State::Closed
    }
}
