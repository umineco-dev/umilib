use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ip::IPEndpoint;
use crate::runtime::Instant;

use super::{
    DNSCache, DNSCacheConfig, DNSCookie, DNSEDNS, DNSError, DNSHeader, DNSMessage, DNSName, DNSOpcode, DNSOption,
    DNSOptionCode, DNSQuestion, DNSResponseCode, DNSTransport,
};

/// A server a resolver asks: where, how, and, for an encrypted transport,
/// the name its certificate is checked against (RFC 8310 §8).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSUpstream {
    pub endpoint: IPEndpoint,
    pub transport: DNSTransport,
    pub name: Option<DNSName>,
}

/// How a stub resolver asks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSResolverConfig {
    /// The servers, asked in order, the next when one fails or does not answer.
    pub upstreams: Vec<DNSUpstream>,
    /// The time the first round waits for an answer; each later round
    /// waits twice as long, up to `maximum_timeout` (RFC 1536 §1).
    pub timeout: Duration,
    pub maximum_timeout: Duration,
    /// The rounds over all servers before the question fails.
    pub rounds: usize,
    /// Queries carry EDNS (RFC 6891), offering this UDP payload (RFC 9715 §3.2).
    pub edns: bool,
    pub udp_size: u16,
    /// RD, DO (RFC 3225) and CD (RFC 4035 §3.2.2) of the queries.
    pub recursion_desired: bool,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    /// Queries over UDP and TCP carry a client cookie (RFC 7873 §5.1).
    pub cookies: bool,
    /// Queries over encrypted transports are padded to a multiple of this
    /// (RFC 8467 §4.1: 128); 0 does not pad.
    pub padding: usize,
    pub cache: DNSCacheConfig,
    /// The most questions being resolved at once.
    pub maximum_queries: usize,
}

impl Default for DNSResolverConfig {
    fn default() -> DNSResolverConfig {
        DNSResolverConfig {
            upstreams: Vec::new(),
            timeout: Duration::from_secs(2),
            maximum_timeout: Duration::from_secs(8),
            rounds: 2,
            edns: true,
            udp_size: DNSEDNS::DEFAULT_UDP_SIZE,
            recursion_desired: true,
            dnssec_ok: false,
            checking_disabled: false,
            cookies: true,
            padding: 128,
            cache: DNSCacheConfig::default(),
            maximum_queries: 1024,
        }
    }
}

/// A query to send: of which question, to which server, how, and its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSTransmission {
    pub query: u64,
    pub upstream: usize,
    pub transport: DNSTransport,
    pub message: Vec<u8>,
}

/// What a resolver tells.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DNSResolverEvent {
    /// The question of the query is answered, the answer of a server or
    /// the cache, or it failed.
    Resolved { query: u64, question: DNSQuestion, result: Result<DNSMessage, DNSError> },
}

/// A query sent: to which server, how, and of which ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSAttempt {
    pub upstream: usize,
    pub transport: DNSTransport,
    pub id: u16,
}

/// A question being resolved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DNSPendingQuery {
    pub question: DNSQuestion,
    /// The queries sent, whose responses are accepted.
    pub attempts: Vec<DNSAttempt>,
    pub upstream: usize,
    pub transport: DNSTransport,
    /// Whether the queries carry EDNS (not after a FORMERR without it, RFC 6891 §7).
    pub edns: bool,
    /// The rounds over all servers done.
    pub round: usize,
    pub deadline: Instant,
    /// Whether it was sent again after BADCOOKIE (RFC 7873 §5.3).
    pub cookie_retried: bool,
    /// The last response of a server that failed (SERVFAIL, REFUSED,
    /// NOTIMP, FORMERR, BADCOOKIE or BADVERS), given if every server fails so.
    pub failure: Option<DNSMessage>,
}

/// A stub resolver (RFC 1034 §5.3.1), Sans-I/O: it makes the queries of
/// the questions it is given ([`DNSResolver::transmit`]), takes the
/// responses ([`DNSResolver::receive`]) and the time
/// ([`DNSResolver::expire`]), and tells the answers
/// ([`DNSResolver::poll_event`]). It sends a query again to the next server
/// on a timeout or a failure, over TCP when a UDP response is truncated
/// (RFC 7766 §5), without EDNS to a server that does not take it, and with
/// the server's cookie after BADCOOKIE. Each query has a random ID (RFC
/// 5452 §9.2); the I/O sends each UDP query from a new random port (§9.3).
/// Responses that do not match their query are ignored (RFC 5452 §9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSResolver {
    pub config: DNSResolverConfig,
    pub cache: DNSCache,
    pub queries: BTreeMap<u64, DNSPendingQuery>,
    pub transmissions: VecDeque<DNSTransmission>,
    pub events: VecDeque<DNSResolverEvent>,
    /// The cookie of each server: the client's, random (RFC 7873 §5.1), and the server's once learned.
    pub cookies: Vec<DNSCookie>,
    pub next: u64,
}

impl DNSResolver {
    /// A resolver of `config`; fails without servers, rounds or a timeout.
    pub fn new<R: Random>(config: DNSResolverConfig, random: &mut R) -> Result<DNSResolver, DNSError> {
        if config.upstreams.is_empty() || config.rounds == 0 || config.timeout.is_zero() {
            return Err(DNSError::Config);
        }
        let mut cookies = Vec::with_capacity(config.upstreams.len());
        for _ in &config.upstreams {
            let mut client = [0u8; 8];
            random.fill(&mut client).map_err(|_| DNSError::State)?;
            cookies.push(DNSCookie { client, server: None });
        }
        Ok(DNSResolver {
            cache: DNSCache::new(config.cache),
            config,
            queries: BTreeMap::new(),
            transmissions: VecDeque::new(),
            events: VecDeque::new(),
            cookies,
            next: 0,
        })
    }

    /// Starts resolving `question`: answered at once from the cache if it
    /// has it, else sent to the first server. Fails if as many questions as
    /// the configuration allows are being resolved.
    pub fn resolve<R: Random>(&mut self, question: DNSQuestion, now: Instant, random: &mut R) -> Result<u64, DNSError> {
        let query = self.next;
        if let Some(result) = self.cache.get(&question, now) {
            self.next += 1;
            self.events.push_back(DNSResolverEvent::Resolved { query, question, result });
            return Ok(query);
        }
        if self.queries.len() >= self.config.maximum_queries {
            return Err(DNSError::State);
        }
        self.next += 1;
        let pending = DNSPendingQuery {
            question,
            attempts: Vec::new(),
            upstream: 0,
            transport: self.config.upstreams[0].transport,
            edns: self.config.edns,
            round: 0,
            deadline: now,
            cookie_retried: false,
            failure: None,
        };
        self.queries.insert(query, pending);
        self.send(query, now, random)?;
        Ok(query)
    }

    /// The timeout of the round `round`: the first one's, doubled for each round before.
    pub fn round_timeout(&self, round: usize) -> Duration {
        let factor = 1u32.checked_shl(round.min(31) as u32).unwrap_or(u32::MAX);
        self.config.timeout.saturating_mul(factor).min(self.config.maximum_timeout.max(self.config.timeout))
    }

    /// The query of `pending` to its current server: of a new ID (0 where
    /// the transport matches by exchange), with EDNS, DO and the cookie as
    /// configured, padded over an encrypted transport (RFC 8467 §4.1).
    pub fn query<R: Random>(&self, pending: &DNSPendingQuery, random: &mut R) -> Result<DNSMessage, DNSError> {
        let mut id = [0u8; 2];
        if !pending.transport.has_zero_id() {
            random.fill(&mut id).map_err(|_| DNSError::State)?;
        }
        let mut message = DNSMessage::query(u16::from_be_bytes(id), pending.question.clone());
        message.header = DNSHeader {
            recursion_desired: self.config.recursion_desired,
            checking_disabled: self.config.checking_disabled,
            opcode: DNSOpcode::QUERY,
            ..message.header
        };
        if pending.edns {
            let mut edns =
                DNSEDNS { udp_size: self.config.udp_size, dnssec_ok: self.config.dnssec_ok, ..DNSEDNS::default() };
            if self.config.cookies && !pending.transport.is_encrypted() {
                edns.options.push(self.cookies[pending.upstream].encode());
            }
            if pending.transport.is_encrypted() && self.config.padding > 0 {
                edns.options.push(DNSOption { code: DNSOptionCode::PADDING, data: Vec::new() });
                message.edns = Some(edns.clone());
                let length = message.encode(DNSMessage::MAXIMUM_SIZE)?.len();
                let padding = (self.config.padding - length % self.config.padding) % self.config.padding;
                edns.set_option(DNSOption { code: DNSOptionCode::PADDING, data: alloc::vec![0; padding] });
            }
            message.edns = Some(edns);
        }
        Ok(message)
    }

    /// Sends the query of `query` to its current server.
    pub fn send<R: Random>(&mut self, query: u64, now: Instant, random: &mut R) -> Result<(), DNSError> {
        let pending = self.queries.get(&query).ok_or(DNSError::State)?;
        let message = self.query(pending, random)?;
        let bytes = message.encode(DNSMessage::MAXIMUM_SIZE)?;
        let timeout = self.round_timeout(pending.round);
        let pending = self.queries.get_mut(&query).ok_or(DNSError::State)?;
        pending.attempts.push(DNSAttempt {
            upstream: pending.upstream,
            transport: pending.transport,
            id: message.header.id,
        });
        pending.deadline = now.saturating_add(timeout);
        self.transmissions.push_back(DNSTransmission {
            query,
            upstream: pending.upstream,
            transport: pending.transport,
            message: bytes,
        });
        Ok(())
    }

    /// The next query to send.
    pub fn transmit(&mut self) -> Option<DNSTransmission> {
        self.transmissions.pop_front()
    }

    /// Takes `bytes`, a response of the server `upstream` over `transport`
    /// to the query `query`. It is ignored unless it is a response of a
    /// query sent, by its ID, server and transport, to its question, and
    /// with the client's cookie if it has one, or if the server gave its
    /// cookie before and the query had one (RFC 7873 §5.3).
    pub fn receive<R: Random>(
        &mut self,
        query: u64,
        upstream: usize,
        transport: DNSTransport,
        bytes: &[u8],
        now: Instant,
        random: &mut R,
    ) {
        let Some(pending) = self.queries.get(&query) else { return };
        let Ok(response) = DNSMessage::decode(bytes) else { return };
        let header = response.header;
        let sent = pending
            .attempts
            .iter()
            .any(|attempt| attempt.upstream == upstream && attempt.transport == transport && attempt.id == header.id);
        if !sent || !header.response || header.opcode != DNSOpcode::QUERY {
            return;
        }
        // A FORMERR may lack the question it could not read.
        let question_matches = match response.questions.as_slice() {
            [question] => *question == pending.question,
            [] => response.rcode() == DNSResponseCode::FORMERR,
            _ => false,
        };
        if !question_matches {
            return;
        }
        match response.edns.as_ref().and_then(|edns| edns.cookie()) {
            Some(Ok(cookie)) if cookie.client == self.cookies[upstream].client => {
                self.cookies[upstream].server = cookie.server
            }
            Some(_) => return,
            // RFC 7873 §5.3: a server that gave its cookie answers a query with a cookie with one.
            None => {
                let expected = pending.edns
                    && self.config.cookies
                    && !transport.is_encrypted()
                    && self.cookies.get(upstream).is_some_and(|cookie| cookie.server.is_some());
                if expected {
                    return;
                }
            }
        }
        let rcode = response.rcode();
        let Some(pending) = self.queries.get_mut(&query) else { return };
        let retry = match rcode {
            DNSResponseCode::BADCOOKIE if !pending.cookie_retried => {
                pending.cookie_retried = true;
                true
            }
            // RFC 7873 §5.3: after a second BADCOOKIE, over TCP.
            DNSResponseCode::BADCOOKIE if transport == DNSTransport::UDP => {
                pending.transport = DNSTransport::TCP;
                true
            }
            DNSResponseCode::FORMERR if pending.edns && response.edns.is_none() => {
                pending.edns = false;
                true
            }
            _ if header.truncated && transport == DNSTransport::UDP => {
                pending.transport = DNSTransport::TCP;
                true
            }
            _ => false,
        };
        if retry {
            let _ = self.send(query, now, random);
            return;
        }
        match rcode {
            DNSResponseCode::SERVFAIL
            | DNSResponseCode::REFUSED
            | DNSResponseCode::NOTIMP
            | DNSResponseCode::FORMERR
            | DNSResponseCode::BADCOOKIE
            // RFC 6891 §6.1.3: the server speaks no version this resolver asks in.
            | DNSResponseCode::BADVERS => {
                pending.failure = Some(response);
                self.advance(query, now, random);
            }
            _ => self.finish(query, Ok(response), now),
        }
    }

    /// Sends the query of `query` to the next server, or, after every
    /// round, ends it with the last failure or a timeout.
    pub fn advance<R: Random>(&mut self, query: u64, now: Instant, random: &mut R) {
        let count = self.config.upstreams.len();
        let Some(pending) = self.queries.get_mut(&query) else { return };
        pending.upstream += 1;
        if pending.upstream == count {
            pending.upstream = 0;
            pending.round += 1;
        }
        if pending.round >= self.config.rounds {
            let result = pending.failure.take().ok_or(DNSError::Timeout);
            self.finish(query, result, now);
            return;
        }
        pending.transport = self.config.upstreams[pending.upstream].transport;
        pending.edns = self.config.edns;
        pending.cookie_retried = false;
        if self.send(query, now, random).is_err() {
            self.finish(query, Err(DNSError::State), now);
        }
    }

    /// Ends `query` with `result`, which the cache keeps.
    pub fn finish(&mut self, query: u64, result: Result<DNSMessage, DNSError>, now: Instant) {
        let Some(pending) = self.queries.remove(&query) else { return };
        self.cache.insert(&pending.question, result.clone(), now);
        self.events.push_back(DNSResolverEvent::Resolved { query, question: pending.question, result });
    }

    /// When [`DNSResolver::expire`] is next due.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.queries.values().map(|pending| pending.deadline).min()
    }

    /// Sends again, to their next servers, the queries unanswered at `now`.
    pub fn expire<R: Random>(&mut self, now: Instant, random: &mut R) {
        let due: Vec<u64> =
            self.queries.iter().filter(|(_, pending)| pending.deadline <= now).map(|(query, _)| *query).collect();
        for query in due {
            self.advance(query, now, random);
        }
        self.cache.expire(now);
    }

    /// Stops resolving `query`; it is not told.
    pub fn cancel(&mut self, query: u64) {
        self.queries.remove(&query);
        self.transmissions.retain(|transmission| transmission.query != query);
    }

    pub fn poll_event(&mut self) -> Option<DNSResolverEvent> {
        self.events.pop_front()
    }
}
