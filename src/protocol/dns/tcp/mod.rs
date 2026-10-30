//! DNS: `tcp` — messages over a byte stream (RFC 1035 §4.2.2, RFC 7766):
//! the 2-byte length before each message, a client that pipelines its
//! queries and matches responses out of order by ID (RFC 7766 §6.2.1.1),
//! and a server connection that answers each query of its stream, with the
//! idle timeouts of RFC 7766 §6.2.3 and the edns-tcp-keepalive option of
//! RFC 7828. The same streams carry DNS over TLS (RFC 7858 §3.3).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::runtime::Instant;

use super::{DNSAuthority, DNSError, DNSKeepalive, DNSMessage, DNSPeer};

/// The framing of messages on a stream: each after its length in two
/// bytes, big-endian (RFC 1035 §4.2.2); a message of length 0 is not one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSTCPFramer {
    /// The bytes received that do not yet make a message.
    pub buffer: Vec<u8>,
}

impl DNSTCPFramer {
    pub fn new() -> DNSTCPFramer {
        DNSTCPFramer { buffer: Vec::new() }
    }

    /// `message` after its length; fails above 65535 bytes.
    pub fn frame(message: &[u8]) -> Result<Vec<u8>, DNSError> {
        let length =
            u16::try_from(message.len()).map_err(|_| DNSError::TooLarge("a message longer than 65535 bytes"))?;
        let mut out = Vec::with_capacity(2 + message.len());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }

    /// Takes `bytes` of the stream.
    pub fn receive(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole message received, or an error for a length of 0.
    pub fn next_message(&mut self) -> Option<Result<Vec<u8>, DNSError>> {
        let [high, low, ..] = self.buffer[..] else { return None };
        let length = usize::from(u16::from_be_bytes([high, low]));
        if length == 0 {
            return Some(Err(DNSError::Malformed("a message of length 0")));
        }
        if self.buffer.len() < 2 + length {
            return None;
        }
        let message = self.buffer[2..2 + length].to_vec();
        self.buffer.drain(..2 + length);
        Some(Ok(message))
    }

    /// Whether part of a message is received.
    pub fn is_partial(&self) -> bool {
        !self.buffer.is_empty()
    }
}

/// The limits of a client's connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSTCPClientConfig {
    /// The most queries outstanding at once (RFC 7766 §6.2.1.1 allows many).
    pub maximum_outstanding: usize,
    /// How long an idle connection is kept unless the server says less (RFC 7828 §3.2.2).
    pub idle_timeout: Duration,
    /// Queries ask for the server's keepalive timeout (RFC 7828 §3.2.1).
    pub keepalive: bool,
}

impl Default for DNSTCPClientConfig {
    fn default() -> DNSTCPClientConfig {
        DNSTCPClientConfig { maximum_outstanding: 100, idle_timeout: Duration::from_secs(10), keepalive: true }
    }
}

/// A client's connection: its queries pipelined, each of an ID no other
/// outstanding one has, and responses matched by ID in any order (RFC 7766
/// §6.2.1.1); idle once nothing is outstanding, until its timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSTCPClient {
    pub config: DNSTCPClientConfig,
    pub framer: DNSTCPFramer,
    /// The questions outstanding by ID, and the handle the caller gave each.
    pub outstanding: BTreeMap<u16, (u64, DNSMessage)>,
    /// The bytes to write to the stream.
    pub output: Vec<u8>,
    pub responses: VecDeque<(u64, DNSMessage)>,
    /// When the connection goes idle too long; None while queries are outstanding.
    pub idle_until: Option<Instant>,
    /// The server's keepalive timeout, once it tells one.
    pub server_timeout: Option<Duration>,
}

impl DNSTCPClient {
    pub fn new(config: DNSTCPClientConfig, now: Instant) -> DNSTCPClient {
        DNSTCPClient {
            idle_until: Some(now.saturating_add(config.idle_timeout)),
            config,
            framer: DNSTCPFramer::new(),
            outstanding: BTreeMap::new(),
            output: Vec::new(),
            responses: VecDeque::new(),
            server_timeout: None,
        }
    }

    /// Sends `query`, known to the caller as `handle`, under a new random
    /// ID, with edns-tcp-keepalive if configured and the query has EDNS.
    /// Fails at the limit of outstanding queries.
    pub fn send<R: Random>(&mut self, handle: u64, mut query: DNSMessage, random: &mut R) -> Result<u16, DNSError> {
        if self.outstanding.len() >= self.config.maximum_outstanding {
            return Err(DNSError::State);
        }
        let id = loop {
            let mut id = [0u8; 2];
            random.fill(&mut id).map_err(|_| DNSError::State)?;
            let id = u16::from_be_bytes(id);
            if !self.outstanding.contains_key(&id) {
                break id;
            }
        };
        query.header.id = id;
        if self.config.keepalive
            && let Some(edns) = &mut query.edns
        {
            edns.set_option(DNSKeepalive::query());
        }
        self.output.extend_from_slice(&DNSTCPFramer::frame(&query.encode(DNSMessage::MAXIMUM_SIZE)?)?);
        self.outstanding.insert(id, (handle, query));
        self.idle_until = None;
        Ok(id)
    }

    /// Takes `bytes` of the stream; a response matched to no outstanding
    /// query, or to another question, is an error that ends the connection
    /// (RFC 7766 §7).
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), DNSError> {
        self.framer.receive(bytes);
        while let Some(message) = self.framer.next_message() {
            let response = DNSMessage::decode(&message?)?;
            let Some((_, query)) = self.outstanding.get(&response.header.id) else {
                return Err(DNSError::Bogus { code: 0, reason: "a response to no outstanding query" });
            };
            if !response.header.response || (!response.questions.is_empty() && response.questions != query.questions) {
                return Err(DNSError::Bogus { code: 0, reason: "a response that is not of its query" });
            }
            if let Some(timeout) = DNSKeepalive::timeout(&response)? {
                self.server_timeout = Some(timeout);
            }
            if let Some((handle, _)) = self.outstanding.remove(&response.header.id) {
                self.responses.push_back((handle, response));
            }
        }
        if self.outstanding.is_empty() {
            let timeout =
                self.server_timeout.map_or(self.config.idle_timeout, |server| server.min(self.config.idle_timeout));
            self.idle_until = Some(now.saturating_add(timeout));
        }
        Ok(())
    }

    /// The bytes to write.
    pub fn transmit(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    pub fn poll_response(&mut self) -> Option<(u64, DNSMessage)> {
        self.responses.pop_front()
    }

    /// Whether the connection should be closed at `now`: idle past its timeout.
    pub fn is_idle(&self, now: Instant) -> bool {
        self.idle_until.is_some_and(|until| now >= until)
    }

    /// The handles of the queries outstanding, which a closed connection did not answer.
    pub fn abandon(&mut self) -> Vec<u64> {
        let handles = self.outstanding.values().map(|(handle, _)| *handle).collect();
        self.outstanding.clear();
        handles
    }
}

/// The limits of a server's connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSTCPServerConfig {
    /// How long a connection may be idle (RFC 7766 §6.2.3: some seconds),
    /// told to clients that ask (RFC 7828 §3.3.2).
    pub idle_timeout: Duration,
    /// The longest a query may stay partly received.
    pub read_timeout: Duration,
}

impl Default for DNSTCPServerConfig {
    fn default() -> DNSTCPServerConfig {
        DNSTCPServerConfig { idle_timeout: Duration::from_secs(10), read_timeout: Duration::from_secs(10) }
    }
}

/// A server's connection: each query of its stream answered by an
/// authoritative server, in order; idle without a query, until its timeout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSTCPServer {
    pub config: DNSTCPServerConfig,
    pub peer: DNSPeer,
    pub framer: DNSTCPFramer,
    pub output: Vec<u8>,
    pub deadline: Instant,
}

impl DNSTCPServer {
    pub fn new(config: DNSTCPServerConfig, peer: DNSPeer, now: Instant) -> DNSTCPServer {
        DNSTCPServer {
            deadline: now.saturating_add(config.idle_timeout),
            config,
            peer,
            framer: DNSTCPFramer::new(),
            output: Vec::new(),
        }
    }

    /// Takes `bytes` of the stream and answers each whole query with
    /// `authority` at `time` (seconds since 1970, for cookies); the
    /// authority tells its keepalive timeout to a query that asks for it
    /// ([`super::DNSAuthorityConfig::keepalive`]). A message of length 0 is
    /// an error that ends the connection.
    pub fn receive(&mut self, bytes: &[u8], authority: &DNSAuthority, now: Instant, time: u32) -> Result<(), DNSError> {
        let continued = self.framer.is_partial();
        let mut completed = false;
        self.framer.receive(bytes);
        while let Some(message) = self.framer.next_message() {
            completed = true;
            for response in authority.respond(&message?, &self.peer, time) {
                self.output.extend_from_slice(&DNSTCPFramer::frame(&response)?);
            }
        }
        // A message begun keeps the deadline of its beginning: bytes trickled in do not extend it.
        match (self.framer.is_partial(), continued && !completed) {
            (true, true) => {}
            (true, false) => self.deadline = now.saturating_add(self.config.read_timeout),
            (false, _) => self.deadline = now.saturating_add(self.config.idle_timeout),
        }
        Ok(())
    }

    pub fn transmit(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Whether the connection should be closed at `now`.
    pub fn is_idle(&self, now: Instant) -> bool {
        now >= self.deadline
    }
}
