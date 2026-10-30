use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ip::IPEndpoint;
use crate::runtime::Instant;

use super::{CoAPCode, CoAPError, CoAPMessage, CoAPOptionNumber, CoAPType};

/// The transmission parameters (RFC 7252 §4.8) and the limits of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoAPConfig {
    pub ack_timeout: Duration,
    /// ACK_RANDOM_FACTOR in thousandths: 1500 for 1.5.
    pub ack_random_factor: u32,
    pub max_retransmit: u32,
    /// The most interactions outstanding with one peer (NSTART); more wait.
    pub nstart: usize,
    /// How long a Message ID and its response are remembered (§4.8.2).
    pub exchange_lifetime: Duration,
    pub non_lifetime: Duration,
    /// How long a server waits for the application's response to a
    /// Confirmable request before it acknowledges it alone and responds
    /// separately (§5.2.2).
    pub ack_delay: Duration,
    /// The longest token taken in requests: 8 unless extended (RFC 8974 §2.2.1).
    pub maximum_token: usize,
    /// The most messages remembered to find duplicates (§4.5); when full,
    /// the one remembered for the shortest time left goes.
    pub maximum_seen: usize,
}

impl Default for CoAPConfig {
    fn default() -> CoAPConfig {
        CoAPConfig {
            ack_timeout: Duration::from_secs(2),
            ack_random_factor: 1500,
            max_retransmit: 4,
            nstart: 1,
            exchange_lifetime: Duration::from_secs(247),
            non_lifetime: Duration::from_secs(145),
            ack_delay: Duration::from_secs(1),
            maximum_token: 8,
            maximum_seen: 8192,
        }
    }
}

/// What an endpoint tells.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CoAPEvent {
    /// A request from `peer`, to answer with [`CoAPEndpoint::respond`].
    Request { exchange: u64, peer: IPEndpoint, message: CoAPMessage },
    /// A response to the request `request`, or a notification of its observation (RFC 7641 §3.2).
    Response { request: u64, message: CoAPMessage },
    /// The Confirmable message `message` (a request or a notification) was
    /// not acknowledged after its retransmissions, or the response to a
    /// request did not come within EXCHANGE_LIFETIME.
    Timeout { message: u64 },
    /// The peer rejected the message `message` (RST, §4.2).
    Reset { message: u64 },
}

/// A datagram to send to `peer`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPTransmission {
    pub peer: IPEndpoint,
    pub message: Vec<u8>,
}

/// A message of this endpoint that is sent and remembered: to `peer`, as
/// `id`, of `token`, until it is acknowledged (Confirmable) and, for a
/// request, answered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPOutgoing {
    pub peer: IPEndpoint,
    pub id: u16,
    pub token: Vec<u8>,
    pub bytes: Vec<u8>,
    pub confirmable: bool,
    pub acknowledged: bool,
    /// Whether a response is awaited (a request), and, if it observes, notifications too.
    pub request: bool,
    pub observe: bool,
    pub retransmissions: u32,
    pub timeout: Duration,
    pub deadline: Instant,
    /// The freshest notification: its Observe value and when it came (RFC 7641 §3.4).
    pub freshest: Option<(u32, Instant)>,
}

impl CoAPOutgoing {
    /// Whether it is an outstanding interaction (§4.7): a Confirmable
    /// message not yet acknowledged, or a Non-confirmable request not yet answered.
    pub fn is_outstanding(&self) -> bool {
        !self.acknowledged || (self.request && !self.confirmable && self.freshest.is_none())
    }
}

/// A message received, remembered until `until` with the reply sent to it,
/// so that a duplicate is answered the same (RFC 7252 §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPSeen {
    pub until: Instant,
    pub reply: Option<Vec<u8>>,
}

/// A request received and not yet answered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPIncoming {
    pub peer: IPEndpoint,
    pub id: u16,
    pub token: Vec<u8>,
    pub confirmable: bool,
    pub acknowledged: bool,
    pub deadline: Instant,
}

/// A CoAP endpoint over UDP (RFC 7252), client and server, Sans-I/O: the
/// message layer — Message IDs, retransmission of Confirmable messages
/// with exponential backoff (§4.2), duplicates answered as before or
/// ignored (§4.5), RST of what cannot be processed — and the matching of
/// responses to requests by token (§5.3.2), piggybacked or separate
/// (§5.2), with the notifications of observations (RFC 7641 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoAPEndpoint {
    pub config: CoAPConfig,
    pub next_id: u16,
    pub next: u64,
    pub outgoing: BTreeMap<u64, CoAPOutgoing>,
    /// Requests waiting for NSTART, by peer.
    pub waiting: VecDeque<(u64, CoAPOutgoing)>,
    pub incoming: BTreeMap<u64, CoAPIncoming>,
    /// The messages received, by peer and Message ID, until when they are
    /// remembered, and the reply sent to each (§4.5).
    pub seen: BTreeMap<(IPEndpoint, u16), CoAPSeen>,
    pub transmissions: VecDeque<CoAPTransmission>,
    pub events: VecDeque<CoAPEvent>,
}

impl CoAPEndpoint {
    pub fn new<R: Random>(config: CoAPConfig, random: &mut R) -> Result<CoAPEndpoint, CoAPError> {
        if config.ack_timeout.is_zero() || config.ack_random_factor < 1000 || config.nstart == 0 {
            return Err(CoAPError::Config);
        }
        // §4.4: the first Message ID random.
        let next_id = random.next_u32().map_err(|_| CoAPError::Random)? as u16;
        Ok(CoAPEndpoint {
            config,
            next_id,
            next: 0,
            outgoing: BTreeMap::new(),
            waiting: VecDeque::new(),
            incoming: BTreeMap::new(),
            seen: BTreeMap::new(),
            transmissions: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    pub fn message_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// The first timeout of a Confirmable message: from ACK_TIMEOUT to
    /// ACK_TIMEOUT × ACK_RANDOM_FACTOR, at random (§4.2).
    pub fn initial_timeout<R: Random>(&self, random: &mut R) -> Duration {
        let base = self.config.ack_timeout.as_nanos();
        let span = base * u128::from(self.config.ack_random_factor - 1000) / 1000;
        let extra = if span == 0 { 0 } else { u128::from(random.next_u64().unwrap_or(0)) % (span + 1) };
        u64::try_from(base + extra).map_or(Duration::MAX, Duration::from_nanos)
    }

    /// Sends the request `message` to `peer` (its type CON or NON, its
    /// token new and random of 8 bytes if empty); the handle its response
    /// and notifications come with. It waits while NSTART interactions with
    /// the peer are outstanding (§4.7).
    pub fn request<R: Random>(
        &mut self,
        peer: IPEndpoint,
        mut message: CoAPMessage,
        now: Instant,
        random: &mut R,
    ) -> Result<u64, CoAPError> {
        if !message.code.is_request() || !matches!(message.kind, CoAPType::Confirmable | CoAPType::NonConfirmable) {
            return Err(CoAPError::State);
        }
        if message.token.is_empty() {
            let mut token = [0u8; 8];
            random.fill(&mut token).map_err(|_| CoAPError::Random)?;
            message.token = token.to_vec();
        }
        let observe = message.options.observe() == Some(0);
        let handle = self.send_message(peer, message, true, observe, now, random)?;
        Ok(handle)
    }

    /// Sends `message`, a request or a separate response or notification,
    /// under a new Message ID; Confirmable ones until acknowledged.
    pub fn send_message<R: Random>(
        &mut self,
        peer: IPEndpoint,
        mut message: CoAPMessage,
        request: bool,
        observe: bool,
        now: Instant,
        random: &mut R,
    ) -> Result<u64, CoAPError> {
        message.id = self.message_id();
        let confirmable = message.kind == CoAPType::Confirmable;
        let timeout = self.initial_timeout(random);
        let outgoing = CoAPOutgoing {
            peer,
            id: message.id,
            token: message.token.clone(),
            bytes: message.encode()?,
            confirmable,
            acknowledged: !confirmable,
            request,
            observe,
            retransmissions: 0,
            timeout,
            deadline: now.saturating_add(if confirmable { timeout } else { self.config.non_lifetime }),
            freshest: None,
        };
        let handle = self.next;
        self.next += 1;
        // §4.7, RFC 7641 §4.5.1: at most NSTART interactions outstanding with a
        // peer, notifications and separate responses among them; more wait.
        if (request || confirmable) && self.outstanding(peer) >= self.config.nstart {
            self.waiting.push_back((handle, outgoing));
            return Ok(handle);
        }
        self.transmissions.push_back(CoAPTransmission { peer, message: outgoing.bytes.clone() });
        self.outgoing.insert(handle, outgoing);
        Ok(handle)
    }

    /// The interactions outstanding with `peer` (§4.7).
    pub fn outstanding(&self, peer: IPEndpoint) -> usize {
        self.outgoing.values().filter(|sent| sent.peer == peer && sent.is_outstanding()).count()
    }

    /// Sends the messages waiting for NSTART that may now go.
    pub fn release_waiting(&mut self, now: Instant) {
        let mut index = 0;
        while index < self.waiting.len() {
            let peer = self.waiting[index].1.peer;
            if self.outstanding(peer) < self.config.nstart
                && let Some((handle, mut outgoing)) = self.waiting.remove(index)
            {
                outgoing.deadline =
                    now.saturating_add(if outgoing.confirmable { outgoing.timeout } else { self.config.non_lifetime });
                self.transmissions.push_back(CoAPTransmission { peer, message: outgoing.bytes.clone() });
                self.outgoing.insert(handle, outgoing);
                continue;
            }
            index += 1;
        }
    }

    /// Sends a reply that is a message of the message layer alone.
    pub fn reply(&mut self, peer: IPEndpoint, message: &CoAPMessage) {
        if let Ok(bytes) = message.encode() {
            self.transmissions.push_back(CoAPTransmission { peer, message: bytes });
        }
    }

    /// Takes the datagram `bytes` from `peer` at `now`.
    pub fn receive<R: Random>(&mut self, peer: IPEndpoint, bytes: &[u8], now: Instant, random: &mut R) {
        let message = match CoAPMessage::decode(bytes) {
            Ok(message) => message,
            Err(_) => {
                // §4.2, §4.3: a Confirmable message that cannot be read is rejected; others are ignored.
                if let Some((CoAPType::Confirmable, id)) = CoAPMessage::header(bytes) {
                    self.reply(peer, &CoAPMessage::empty(CoAPType::Reset, id));
                }
                return;
            }
        };
        match message.kind {
            // §4.2: an ACK is empty or a response, a RST empty; others are silently ignored.
            CoAPType::Acknowledgement if !message.code.is_empty() && !message.code.is_response() => {}
            CoAPType::Reset if !message.code.is_empty() => {}
            CoAPType::Acknowledgement => self.acknowledged(peer, message, now),
            CoAPType::Reset => {
                let found = self
                    .outgoing
                    .iter()
                    .find(|(_, sent)| sent.peer == peer && sent.id == message.id)
                    .map(|(handle, _)| *handle);
                if let Some(handle) = found {
                    self.outgoing.remove(&handle);
                    self.events.push_back(CoAPEvent::Reset { message: handle });
                    self.release_waiting(now);
                }
            }
            CoAPType::Confirmable | CoAPType::NonConfirmable => {
                let confirmable = message.kind == CoAPType::Confirmable;
                // §4.5: a duplicate gets the same reply, or none.
                if let Some(CoAPSeen { reply, .. }) = self.seen.get(&(peer, message.id)) {
                    if confirmable && let Some(reply) = reply.clone() {
                        self.transmissions.push_back(CoAPTransmission { peer, message: reply });
                    }
                    return;
                }
                let lifetime = if confirmable { self.config.exchange_lifetime } else { self.config.non_lifetime };
                if self.seen.len() >= self.config.maximum_seen {
                    let first = self.seen.iter().min_by_key(|(_, seen)| seen.until).map(|(key, _)| *key);
                    if let Some(first) = first {
                        self.seen.remove(&first);
                    }
                }
                self.seen.insert((peer, message.id), CoAPSeen { until: now.saturating_add(lifetime), reply: None });
                if message.code.is_empty() {
                    // §4.3: a ping, or an empty NON: rejected.
                    self.reject(peer, &message);
                } else if message.code.is_request() {
                    self.request_received(peer, message, now, random);
                } else if message.code.is_response() {
                    self.response_received(peer, message, now);
                } else {
                    self.reject(peer, &message);
                }
            }
        }
    }

    /// A RST of `message`, remembered as its reply.
    pub fn reject(&mut self, peer: IPEndpoint, message: &CoAPMessage) {
        let reset = CoAPMessage::empty(CoAPType::Reset, message.id);
        if let Ok(bytes) = reset.encode() {
            if message.kind == CoAPType::Confirmable
                && let Some(CoAPSeen { reply, .. }) = self.seen.get_mut(&(peer, message.id))
            {
                *reply = Some(bytes.clone());
            }
            self.transmissions.push_back(CoAPTransmission { peer, message: bytes });
        }
    }

    /// An ACK: the Confirmable message it acknowledges is done; a piggybacked response answers its request (§5.2.1).
    pub fn acknowledged(&mut self, peer: IPEndpoint, message: CoAPMessage, now: Instant) {
        let found = self
            .outgoing
            .iter()
            .find(|(_, sent)| sent.peer == peer && sent.id == message.id && !sent.acknowledged)
            .map(|(handle, _)| *handle);
        let Some(handle) = found else { return };
        let Some(sent) = self.outgoing.get_mut(&handle) else { return };
        // A piggybacked response not of the request's token, or of a critical
        // option this end cannot process, is rejected: an ACK is rejected by
        // ignoring it (§4.2, §5.3.2, §5.4.1), so the request is sent again.
        if message.code.is_response() && (sent.token != message.token || message.options.check().is_err()) {
            return;
        }
        sent.acknowledged = true;
        if !sent.request {
            self.outgoing.remove(&handle);
        } else if message.code.is_response() {
            self.deliver(handle, message, now);
        } else {
            // An empty ACK: the response comes separately, within EXCHANGE_LIFETIME.
            sent.deadline = now.saturating_add(self.config.exchange_lifetime);
        }
        self.release_waiting(now);
    }

    /// A request received: of a token longer than taken, rejected (a
    /// message-format error) by an endpoint of tokens of 8 bytes, answered
    /// 4.00 by one of extended tokens (RFC 8974 §2.2.2, §2.3); of a critical
    /// option it cannot process, answered 4.02 if Confirmable, else rejected
    /// (§5.4.1); else told.
    pub fn request_received<R: Random>(
        &mut self,
        peer: IPEndpoint,
        message: CoAPMessage,
        now: Instant,
        random: &mut R,
    ) {
        let extended = self.config.maximum_token > 8;
        if message.token.len() > self.config.maximum_token && !extended {
            self.reject(peer, &message);
            return;
        }
        let confirmable = message.kind == CoAPType::Confirmable;
        if message.options.check().is_err() && !confirmable {
            self.reject(peer, &message);
            return;
        }
        let exchange = self.next;
        self.next += 1;
        self.incoming.insert(
            exchange,
            CoAPIncoming {
                peer,
                id: message.id,
                token: message.token.clone(),
                confirmable,
                acknowledged: false,
                deadline: now.saturating_add(self.config.ack_delay),
            },
        );
        let refusal = match message.token.len() > self.config.maximum_token {
            true => Some(CoAPCode::BAD_REQUEST),
            false => message.options.check().err().map(|_| CoAPCode::BAD_OPTION),
        };
        if let Some(code) = refusal {
            let response = CoAPMessage::new(CoAPType::Acknowledgement, code, 0);
            let _ = self.respond(exchange, response, now, random);
            return;
        }
        let message = CoAPMessage { options: message.options.usable(), ..message };
        self.events.push_back(CoAPEvent::Request { exchange, peer, message });
    }

    /// A separate response or a notification: matched by token, else
    /// rejected; acknowledged if Confirmable (§5.2.2, §5.3.2).
    pub fn response_received(&mut self, peer: IPEndpoint, message: CoAPMessage, now: Instant) {
        let found = self
            .outgoing
            .iter()
            .find(|(_, sent)| sent.request && sent.peer == peer && sent.token == message.token)
            .map(|(handle, _)| *handle);
        let Some(handle) = found else {
            // Of no request: rejected if Confirmable, or a notification of
            // an observation the client forgot (RFC 7641 §3.6).
            if message.kind == CoAPType::Confirmable || message.options.contains(CoAPOptionNumber::OBSERVE) {
                self.reject(peer, &message);
            }
            return;
        };
        // §5.4.1: a response of a critical option this end cannot process is rejected.
        if message.options.check().is_err() {
            self.reject(peer, &message);
            return;
        }
        if message.kind == CoAPType::Confirmable {
            let ack = CoAPMessage::empty(CoAPType::Acknowledgement, message.id);
            if let Ok(bytes) = ack.encode() {
                if let Some(CoAPSeen { reply, .. }) = self.seen.get_mut(&(peer, message.id)) {
                    *reply = Some(bytes.clone());
                }
                self.transmissions.push_back(CoAPTransmission { peer, message: bytes });
            }
        }
        if let Some(sent) = self.outgoing.get_mut(&handle) {
            sent.acknowledged = true;
        }
        self.deliver(handle, message, now);
    }

    /// Tells the response `message` to the request `handle`: an
    /// observation stays for notifications, older ones than the freshest
    /// dropped (RFC 7641 §3.4); else the request is done.
    pub fn deliver(&mut self, handle: u64, message: CoAPMessage, now: Instant) {
        let Some(sent) = self.outgoing.get_mut(&handle) else { return };
        let notification = message.options.observe();
        if sent.observe
            && message.code.class() == 2
            && let Some(value) = notification
        {
            if let Some((freshest, at)) = sent.freshest
                && !CoAPEndpoint::is_fresher(freshest, at, value, now)
            {
                return;
            }
            sent.freshest = Some((value, now));
            sent.deadline = Instant::MAX;
            self.events.push_back(CoAPEvent::Response { request: handle, message });
            return;
        }
        self.outgoing.remove(&handle);
        self.events.push_back(CoAPEvent::Response { request: handle, message });
        self.release_waiting(now);
    }

    /// Whether a notification of Observe `value` at `now` was sent after the
    /// freshest one, of `freshest` at `at` (RFC 7641 §3.4).
    pub fn is_fresher(freshest: u32, at: Instant, value: u32, now: Instant) -> bool {
        let half = 1u32 << 23;
        (freshest < value && value - freshest < half)
            || (freshest > value && freshest - value > half)
            || now.saturating_duration_since(at) > Duration::from_secs(128)
    }

    /// Answers the request `exchange` with `response` (its code, options
    /// and payload): piggybacked in the ACK if the request is Confirmable
    /// and not yet acknowledged (§5.2.1), else separately, Confirmable for
    /// a Confirmable request (§5.2.2), Non-confirmable for a Non-confirmable one.
    pub fn respond<R: Random>(
        &mut self,
        exchange: u64,
        mut response: CoAPMessage,
        now: Instant,
        random: &mut R,
    ) -> Result<(), CoAPError> {
        // The exchange stays until the response is made, so that a response
        // that cannot be written can be replaced by another.
        let incoming = self.incoming.get(&exchange).ok_or(CoAPError::State)?.clone();
        response.token = incoming.token.clone();
        if incoming.confirmable && !incoming.acknowledged {
            response.kind = CoAPType::Acknowledgement;
            response.id = incoming.id;
            let bytes = response.encode()?;
            self.incoming.remove(&exchange);
            if let Some(CoAPSeen { reply, .. }) = self.seen.get_mut(&(incoming.peer, incoming.id)) {
                *reply = Some(bytes.clone());
            }
            self.transmissions.push_back(CoAPTransmission { peer: incoming.peer, message: bytes });
            return Ok(());
        }
        response.kind = if incoming.confirmable { CoAPType::Confirmable } else { CoAPType::NonConfirmable };
        response.encode()?;
        self.incoming.remove(&exchange);
        self.send_message(incoming.peer, response, false, false, now, random).map(|_| ())
    }

    /// Sends the notification `message` of an observation to `peer` (RFC
    /// 7641 §4.2), of the observer's token, Confirmable or not; its handle,
    /// to learn of a RST or a timeout, which end the observation (§3.6, §4.5).
    pub fn notify<R: Random>(
        &mut self,
        peer: IPEndpoint,
        message: CoAPMessage,
        now: Instant,
        random: &mut R,
    ) -> Result<u64, CoAPError> {
        if !message.code.is_response() || !message.options.contains(CoAPOptionNumber::OBSERVE) {
            return Err(CoAPError::State);
        }
        self.send_message(peer, message, false, false, now, random)
    }

    /// Stops awaiting the request `handle` at `now`: its observation
    /// forgotten, so that notifications are rejected (RFC 7641 §3.6); what
    /// waited for it may go.
    pub fn cancel(&mut self, handle: u64, now: Instant) {
        self.outgoing.remove(&handle);
        self.waiting.retain(|(waiting, _)| *waiting != handle);
        self.release_waiting(now);
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        let outgoing = self.outgoing.values().filter(|sent| sent.deadline != Instant::MAX).map(|sent| sent.deadline);
        let incoming = self
            .incoming
            .values()
            .filter(|exchange| exchange.confirmable && !exchange.acknowledged)
            .map(|exchange| exchange.deadline);
        let seen = self.seen.values().map(|seen| seen.until);
        outgoing.chain(incoming).chain(seen).min()
    }

    /// What is due at `now`: retransmissions, doubling the timeout up to
    /// MAX_RETRANSMIT (§4.2); the end of what is not answered; the empty ACK
    /// of a request the application has not yet answered (§5.2.2).
    pub fn expire(&mut self, now: Instant) {
        let due: Vec<u64> =
            self.outgoing.iter().filter(|(_, sent)| sent.deadline <= now).map(|(handle, _)| *handle).collect();
        for handle in due {
            let Some(sent) = self.outgoing.get_mut(&handle) else { continue };
            if sent.confirmable && !sent.acknowledged && sent.retransmissions < self.config.max_retransmit {
                sent.retransmissions += 1;
                sent.timeout *= 2;
                sent.deadline = now.saturating_add(sent.timeout);
                let transmission = CoAPTransmission { peer: sent.peer, message: sent.bytes.clone() };
                self.transmissions.push_back(transmission);
                continue;
            }
            // A Non-confirmable response or notification is kept only to
            // match a RST (§4.3); its end is no failure (RFC 7641 §4.5).
            let failed = sent.request || sent.confirmable;
            self.outgoing.remove(&handle);
            if failed {
                self.events.push_back(CoAPEvent::Timeout { message: handle });
            }
        }
        let late: Vec<u64> = self
            .incoming
            .iter()
            .filter(|(_, exchange)| exchange.confirmable && !exchange.acknowledged && exchange.deadline <= now)
            .map(|(exchange, _)| *exchange)
            .collect();
        for exchange in late {
            let Some(incoming) = self.incoming.get_mut(&exchange) else { continue };
            incoming.acknowledged = true;
            let ack = CoAPMessage::empty(CoAPType::Acknowledgement, incoming.id);
            let (peer, id) = (incoming.peer, incoming.id);
            if let Ok(bytes) = ack.encode() {
                if let Some(CoAPSeen { reply, .. }) = self.seen.get_mut(&(peer, id)) {
                    *reply = Some(bytes.clone());
                }
                self.transmissions.push_back(CoAPTransmission { peer, message: bytes });
            }
        }
        self.seen.retain(|_, seen| now < seen.until);
        self.release_waiting(now);
    }

    pub fn transmit(&mut self) -> Option<CoAPTransmission> {
        self.transmissions.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<CoAPEvent> {
        self.events.pop_front()
    }
}
