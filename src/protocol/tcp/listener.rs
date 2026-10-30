use alloc::collections::{BTreeMap, VecDeque};
use core::ops::Bound;

use crate::bytes::Writer;
use crate::protocol::ip::{IPEndpoint, IPEndpointPattern};
use crate::runtime::Instant;

use super::{
    TCPConfig, TCPConnection, TCPError, TCPFlags, TCPISNGenerator, TCPSegment, TCPSequence, TCPState, TCPTransmission,
};

/// A passive OPEN (RFC 9293 §3.10.1): the connections for the local
/// endpoints of `local`, from their SYN until they are accepted. Until then
/// the listener gives them their segments and timers, whether they are
/// being set up or established and waiting. A listener never affects
/// another connection (MUST-41), and listens while its connections are
/// being set up (MUST-42).
pub struct TCPListener {
    pub config: TCPConfig,
    pub local: IPEndpointPattern,
    /// The most connections held: being set up and waiting to be accepted.
    pub backlog: usize,
    pub isn: TCPISNGenerator,
    /// The connections held, by their local and remote endpoints.
    pub connections: BTreeMap<(IPEndpoint, IPEndpoint), TCPConnection>,
    /// The endpoints of the connections established and not yet accepted, in order.
    pub ready: VecDeque<(IPEndpoint, IPEndpoint)>,
    /// The resets to send, at most `backlog`: to the endpoint, from the endpoint, and the reset.
    pub resets: VecDeque<(IPEndpoint, IPEndpoint, TCPSequence, Option<TCPSequence>)>,
    /// The connection that sent last: [`TCPListener::transmit`] goes on
    /// from the one after it, so that a round visits each once.
    pub cursor: Option<(IPEndpoint, IPEndpoint)>,
}

impl TCPListener {
    /// A listener; fails with [`TCPError::Config`] for a configuration that cannot work.
    pub fn new(
        config: TCPConfig,
        local: IPEndpointPattern,
        backlog: usize,
        isn: TCPISNGenerator,
    ) -> Result<TCPListener, TCPError> {
        config.check()?;
        Ok(TCPListener {
            config,
            local,
            backlog,
            isn,
            connections: BTreeMap::new(),
            ready: VecDeque::new(),
            resets: VecDeque::new(),
            cursor: None,
        })
    }

    /// Whether the segment from `remote` to `local` is the listener's: its
    /// local endpoint is one of the listener's.
    pub fn matches(&self, local: IPEndpoint) -> bool {
        self.local.matches(&local)
    }

    /// The connections being set up: held, and not established.
    pub fn pending(&self) -> usize {
        self.connections.len() - self.ready.len()
    }

    /// Processes a segment from `remote` to `local` (RFC 9293 §3.10.7.2): a
    /// connection the listener holds takes it; otherwise a SYN opens a
    /// connection if the backlog has room, an ACK is answered with a reset,
    /// and a reset is ignored.
    pub fn receive(&mut self, segment: &TCPSegment, local: IPEndpoint, remote: IPEndpoint, ce: bool, now: Instant) {
        if let Some(connection) = self.connections.get_mut(&(local, remote)) {
            connection.receive(segment, ce, now);
            self.settle(local, remote);
            return;
        }
        let flags = segment.flags;
        if flags.contains(TCPFlags::RST) {
            return;
        }
        if flags.contains(TCPFlags::ACK) {
            if self.resets.len() < self.backlog {
                self.resets.push_back((local, remote, segment.acknowledgment, None));
            }
            return;
        }
        if !flags.contains(TCPFlags::SYN) || self.connections.len() >= self.backlog {
            return;
        }
        let iss = self.isn.generate(local, remote, now);
        if let Ok(connection) = TCPConnection::accept(self.config, local, remote, segment, iss, now) {
            self.connections.insert((local, remote), connection);
        }
    }

    /// Queues a connection that was established for [`TCPListener::accept`],
    /// and forgets one that closed with nothing left to send (RFC 9293
    /// §3.10.7.4: a reset returns to LISTEN).
    pub fn settle(&mut self, local: IPEndpoint, remote: IPEndpoint) {
        let key = (local, remote);
        let Some(connection) = self.connections.get(&key) else { return };
        match connection.state {
            TCPState::SynReceived => {}
            TCPState::Closed if connection.reset_due.is_none() => {
                self.connections.remove(&key);
                self.ready.retain(|ready| *ready != key);
            }
            TCPState::Closed => {}
            _ => {
                if !self.ready.contains(&key) {
                    self.ready.push_back(key);
                }
            }
        }
    }

    /// The next connection established, if any. From then on its segments
    /// are the caller's to give it.
    pub fn accept(&mut self) -> Option<TCPConnection> {
        while let Some(key) = self.ready.pop_front() {
            if let Some(connection) = self.connections.remove(&key) {
                return Some(connection);
            }
        }
        None
    }

    /// The earliest timer of the connections held. What
    /// [`TCPListener::receive`] makes due, such as a SYN-ACK or a reset, is
    /// written by the [`TCPListener::transmit`] calls that follow it.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.connections.values().filter_map(TCPConnection::poll_timeout).min()
    }

    /// Writes the next segment due at `now`, with the endpoints it goes
    /// from and to. Call it until it returns `None`.
    pub fn transmit(
        &mut self,
        now: Instant,
        out: &mut impl Writer,
    ) -> Result<Option<(IPEndpoint, IPEndpoint, TCPTransmission)>, TCPError> {
        if let Some((local, remote, sequence, acknowledgment)) = self.resets.pop_front() {
            let reset = TCPSegment::reset(local.port, remote.port, sequence, acknowledgment);
            reset.encode(local.address, remote.address, out)?;
            return Ok(Some((local, remote, TCPTransmission { length: reset.length(), ect: false })));
        }
        // Each connection is visited at most once per round, from the one after the last that sent.
        let mut key = match self.cursor.take() {
            Some(cursor) => self.following(cursor),
            None => self.connections.keys().next().copied(),
        };
        for _ in 0..self.connections.len() {
            let Some(current) = key else { break };
            let connection = self.connections.get_mut(&current).expect("a key of the map");
            let transmission = connection.transmit(now, out)?;
            // A connection that closed with nothing left to send is forgotten (RFC 9293 §3.10.7.4).
            let finished = connection.state == TCPState::Closed && connection.reset_due.is_none();
            if let Some(transmission) = transmission {
                self.cursor = Some(current);
                return Ok(Some((current.0, current.1, transmission)));
            }
            key = self.following(current).filter(|next| *next != current);
            if finished {
                self.connections.remove(&current);
                self.ready.retain(|ready| *ready != current);
            }
        }
        Ok(None)
    }

    /// The key after `key` in the map, from the first again after the last.
    pub fn following(&self, key: (IPEndpoint, IPEndpoint)) -> Option<(IPEndpoint, IPEndpoint)> {
        self.connections
            .range((Bound::Excluded(key), Bound::Unbounded))
            .next()
            .or_else(|| self.connections.iter().next())
            .map(|(next, _)| *next)
    }
}

impl TCPSegment<'static> {
    /// A reset from `source_port` to `destination_port`: of `sequence`, and
    /// acknowledging `acknowledgment` if given.
    pub fn reset(
        source_port: u16,
        destination_port: u16,
        sequence: TCPSequence,
        acknowledgment: Option<TCPSequence>,
    ) -> TCPSegment<'static> {
        TCPSegment {
            source_port,
            destination_port,
            sequence,
            acknowledgment: acknowledgment.unwrap_or_default(),
            flags: if acknowledgment.is_some() { TCPFlags::RST.union(TCPFlags::ACK) } else { TCPFlags::RST },
            window: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        }
    }
}

impl TCPSegment<'_> {
    /// The reset that answers this segment when no connection exists for it
    /// (RFC 9293 §3.10.7.1); none answers a reset.
    pub fn reset_reply(&self) -> Option<TCPSegment<'static>> {
        if self.flags.contains(TCPFlags::RST) {
            return None;
        }
        Some(if self.flags.contains(TCPFlags::ACK) {
            TCPSegment::reset(self.destination_port, self.source_port, self.acknowledgment, None)
        } else {
            let end = self.sequence.add(self.sequence_length());
            TCPSegment::reset(self.destination_port, self.source_port, TCPSequence(0), Some(end))
        })
    }
}
