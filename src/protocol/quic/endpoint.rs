use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::crypto::random::Random;
use crate::protocol::ip::IPEndpoint;
use crate::protocol::tls::{TLSClientConfig, TLSServerConfig};
use crate::runtime::Instant;

use super::{
    QUICAcceptance, QUICConfig, QUICConnection, QUICConnectionID, QUICECN, QUICError, QUICErrorCode, QUICFrame,
    QUICFrameType, QUICHeader, QUICInvariantHeader, QUICKeys, QUICLongHeader, QUICPacket, QUICPacketKey,
    QUICPacketType, QUICResetToken, QUICRetry, QUICRetryIntegrity, QUICRole, QUICSecret, QUICToken, QUICTokenKey,
    QUICTokenKind, QUICTransmission, QUICVersion, QUICVersionNegotiation,
};

/// The configuration of an endpoint: that of its connections, the TLS
/// configuration of those it accepts, and how it validates clients'
/// addresses (RFC 9000 §8.1).
#[derive(Clone)]
pub struct QUICEndpointConfig {
    pub quic: Arc<QUICConfig>,
    /// The configuration of the connections it accepts; none accepted without one.
    pub tls: Option<Arc<TLSServerConfig>>,
    /// The key of address validation tokens, shared by the servers of a
    /// deployment: Retry tokens and NEW_TOKEN tokens need one.
    pub token_key: Option<[u8; 32]>,
    /// Whether a client without a valid token is sent a Retry first (RFC 9000 §8.1.2).
    pub retry: bool,
    /// The most connections at once: Initial packets past it are dropped.
    pub maximum_connections: usize,
    /// The most stateless packets (Version Negotiation, Retry, resets) queued.
    pub maximum_stateless: usize,
}

impl core::fmt::Debug for QUICEndpointConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QUICEndpointConfig")
            .field("quic", &self.quic)
            .field("accepts", &self.tls.is_some())
            .field("retry", &self.retry)
            .finish()
    }
}

impl QUICEndpointConfig {
    pub fn new(quic: Arc<QUICConfig>, tls: Option<Arc<TLSServerConfig>>) -> QUICEndpointConfig {
        QUICEndpointConfig {
            quic,
            tls,
            token_key: None,
            retry: false,
            maximum_connections: 1024,
            maximum_stateless: 256,
        }
    }
}

/// A QUIC endpoint without I/O (RFC 9000 §5.2): the connections that share
/// a socket, found by the connection IDs of the datagrams that arrive; it
/// answers what no connection takes with Version Negotiation, Retry or a
/// stateless reset, and accepts new connections.
pub struct QUICEndpoint {
    pub config: QUICEndpointConfig,
    pub connections: BTreeMap<u64, QUICConnection>,
    /// The connection of each local connection ID, and of each client's first Destination Connection ID.
    pub routes: BTreeMap<QUICConnectionID, u64>,
    /// The IDs routed to each connection, so that its routes change without a walk of all.
    pub registered: BTreeMap<u64, Vec<QUICConnectionID>>,
    pub token_key: Option<QUICTokenKey>,
    pub next_handle: u64,
    pub random: Box<dyn Random + Send>,
    /// Stateless packets to send, with their destinations.
    pub outgoing: VecDeque<(IPEndpoint, Vec<u8>)>,
    /// The connections accepted that the application has not taken.
    pub accepted: VecDeque<u64>,
    /// The connection whose datagrams go next, so that each has its turn.
    pub turn: u64,
}

impl core::fmt::Debug for QUICEndpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("QUICEndpoint").field("connections", &self.connections.len()).finish()
    }
}

impl QUICEndpoint {
    pub fn new(config: QUICEndpointConfig, random: Box<dyn Random + Send>) -> Result<QUICEndpoint, QUICError> {
        config.quic.check()?;
        if config.retry && config.token_key.is_none() {
            return Err(QUICError::Config);
        }
        let token_key = config.token_key.as_ref().map(QUICTokenKey::new).transpose()?;
        Ok(QUICEndpoint {
            config,
            connections: BTreeMap::new(),
            routes: BTreeMap::new(),
            registered: BTreeMap::new(),
            token_key,
            next_handle: 0,
            random,
            outgoing: VecDeque::new(),
            accepted: VecDeque::new(),
            turn: 0,
        })
    }

    /// Opens a connection to `remote` and returns its handle; `token` is one
    /// a server gave in a NEW_TOKEN frame, for this server (RFC 9000 §8.1.3).
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        &mut self,
        tls: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        remote: IPEndpoint,
        token: Option<Vec<u8>>,
        random: Box<dyn Random + Send>,
        now: Instant,
        time: i64,
    ) -> Result<u64, QUICError> {
        let mut connection =
            QUICConnection::client(self.config.quic.clone(), tls, server_name, remote, random, now, time)?;
        if let Some(token) = token {
            connection.token = token;
        }
        Ok(self.insert(connection))
    }

    pub fn insert(&mut self, connection: QUICConnection) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.connections.insert(handle, connection);
        self.update_routes(handle);
        handle
    }

    pub fn connection(&mut self, handle: u64) -> Option<&mut QUICConnection> {
        self.connections.get_mut(&handle)
    }

    /// The next connection accepted.
    pub fn accept(&mut self) -> Option<u64> {
        self.accepted.pop_front()
    }

    /// Keeps the routes of a connection's IDs current; a connection gone loses them.
    pub fn update_routes(&mut self, handle: u64) {
        let mut current: Vec<QUICConnectionID> = Vec::new();
        if let Some(connection) = self.connections.get(&handle) {
            current.extend(connection.local_ids.ids.values().map(|issued| issued.id));
            // A server's connection also takes the client's first IDs until the handshake completes.
            if connection.role == QUICRole::Server && !connection.handshake_complete {
                current.push(connection.original_destination);
                current.extend(connection.retry_source);
            }
            current.retain(|id| !id.is_empty());
        }
        let previous = self.registered.remove(&handle).unwrap_or_default();
        for id in previous.iter().filter(|id| !current.contains(id)) {
            if self.routes.get(id) == Some(&handle) {
                self.routes.remove(id);
            }
        }
        for id in &current {
            self.routes.insert(*id, handle);
        }
        if !current.is_empty() {
            self.registered.insert(handle, current);
        }
    }

    /// Takes a datagram from `remote`, received at `now` (`time` in seconds
    /// since 1970, for certificates and tokens), and returns the handle of
    /// the connection it went to, if any.
    pub fn receive(
        &mut self,
        datagram: &[u8],
        remote: IPEndpoint,
        ecn: QUICECN,
        now: Instant,
        time: i64,
    ) -> Option<u64> {
        let length = self.config.quic.connection_id_length;
        let invariant = QUICInvariantHeader::decode(datagram, length).ok()?;
        let destination = QUICConnectionID::new(invariant.destination());
        let routed = destination.and_then(|id| self.routes.get(&id).copied());
        // A client's connections with zero-length IDs take what comes from their server.
        let routed = routed.or_else(|| {
            (length == 0)
                .then(|| {
                    self.connections
                        .iter()
                        .find(|(_, connection)| connection.remote == remote)
                        .map(|(handle, _)| *handle)
                })
                .flatten()
        });
        if let Some(handle) = routed {
            let connection = self.connections.get_mut(&handle)?;
            connection.receive(datagram, remote, ecn, now);
            self.after(handle, time);
            return Some(handle);
        }
        match invariant {
            QUICInvariantHeader::Long { version, destination, source } => {
                // Version Negotiation is never answered with another (RFC 9000 §6.1).
                if version == QUICVersion::NEGOTIATION {
                    return None;
                }
                if !self.config.quic.versions.contains(&version) || !version.is_supported() {
                    self.negotiate(datagram, destination, source, remote);
                    return None;
                }
                self.accept_initial(datagram, remote, ecn, now, time)
            }
            QUICInvariantHeader::Short { destination } => {
                // A stateless reset reaches the connection whose peer's token it carries (RFC 9000 §10.3.1).
                let reset = self
                    .connections
                    .iter()
                    .find(|(_, connection)| connection.remote == remote && connection.is_stateless_reset(datagram))
                    .map(|(handle, _)| *handle);
                if let Some(handle) = reset {
                    self.connections.get_mut(&handle)?.receive(datagram, remote, ecn, now);
                    self.after(handle, time);
                    return Some(handle);
                }
                self.reset(datagram, destination, remote);
                None
            }
        }
    }

    /// Answers a packet of an unknown version with Version Negotiation (RFC
    /// 9000 §6.1): only to a datagram the size of a client's first (§14.1).
    pub fn negotiate(&mut self, datagram: &[u8], destination: &[u8], source: &[u8], remote: IPEndpoint) {
        if datagram.len() < QUICConfig::MINIMUM_DATAGRAM_SIZE
            || self.config.tls.is_none()
            || self.outgoing.len() >= self.config.maximum_stateless
        {
            return;
        }
        let mut versions = self.config.quic.supported_versions();
        // A reserved version exercises the client's rule of ignoring them (RFC 9000 §6.3).
        let grease = self.random.next_u32().map(|value| (value & 0xF0F0_F0F0) | 0x0A0A_0A0A).unwrap_or(0x0A0A_0A0A);
        versions.push(super::QUICVersion(grease));
        let unused = self.random.next_u32().map(|value| value as u8).unwrap_or(0);
        let mut packet = Vec::new();
        if QUICVersionNegotiation::encode(destination, source, &versions, unused, &mut packet).is_ok() {
            self.outgoing.push_back((remote, packet));
        }
    }

    /// A stateless reset for a short header packet of no connection (RFC
    /// 9000 §10.3): with the configured key, smaller than the packet, at
    /// least 21 bytes, and only to packets larger than that.
    pub fn reset(&mut self, datagram: &[u8], destination: &[u8], remote: IPEndpoint) {
        let Some(key) = &self.config.quic.reset_key else { return };
        let Some(id) = QUICConnectionID::new(destination) else { return };
        if datagram.len() <= 22 || self.outgoing.len() >= self.config.maximum_stateless {
            return;
        }
        let length = (datagram.len() - 1).min(43);
        let mut packet = alloc::vec![0u8; length];
        if self.random.fill(&mut packet[..length - 16]).is_err() {
            return;
        }
        // A short header with the QUIC bit, unpredictable otherwise (RFC 9000 §10.3).
        packet[0] = (packet[0] & 0x3F) | 0x40;
        packet[length - 16..].copy_from_slice(&QUICResetToken::of(key, &id));
        self.outgoing.push_back((remote, packet));
    }

    /// A client's first Initial packet (RFC 9000 §7.2, §8.1, §14.1): in a
    /// datagram of 1200 bytes, to a Destination Connection ID of 8 bytes at
    /// least. Its token is checked; without a valid one, a Retry goes back
    /// when configured; otherwise a connection is accepted.
    pub fn accept_initial(
        &mut self,
        datagram: &[u8],
        remote: IPEndpoint,
        ecn: QUICECN,
        now: Instant,
        time: i64,
    ) -> Option<u64> {
        let tls = self.config.tls.clone()?;
        if datagram.len() < QUICConfig::MINIMUM_DATAGRAM_SIZE
            || self.connections.len() >= self.config.maximum_connections
        {
            return None;
        }
        let QUICPacket::Protected(packet) = QUICPacket::decode(datagram, self.config.quic.connection_id_length).ok()?
        else {
            return None;
        };
        let QUICHeader::Long(header) = packet.header else { return None };
        if header.packet_type != QUICPacketType::Initial {
            return None;
        }
        let mut acceptance = QUICAcceptance {
            version: header.version,
            original_destination: header.destination,
            destination: header.destination,
            source: header.source,
            retry_source: None,
            validated: false,
        };
        let token = (!header.token.is_empty())
            .then(|| self.token_key.as_ref().and_then(|key| key.open(header.token, &remote)))
            .flatten();
        match token {
            Some(QUICToken {
                kind: QUICTokenKind::Retry { original_destination, retry_source },
                version,
                time: issued,
                ..
            }) if version == header.version
                && retry_source == header.destination
                && (time as u64).saturating_sub(issued) <= QUICTokenKey::RETRY_LIFETIME =>
            {
                acceptance.original_destination = original_destination;
                acceptance.retry_source = Some(retry_source);
                acceptance.validated = true;
            }
            // A Retry token of this server that does not hold: the client
            // takes no other Retry, so it is told at once (RFC 9000 §8.1.2).
            Some(QUICToken { kind: QUICTokenKind::Retry { .. }, .. }) => {
                self.refuse_token(&header, remote);
                return None;
            }
            Some(QUICToken { kind: QUICTokenKind::NewToken, version, time: issued, address, .. })
                if version == header.version
                    && address.address == remote.address
                    && (time as u64).saturating_sub(issued) <= QUICTokenKey::NEW_TOKEN_LIFETIME =>
            {
                acceptance.validated = true;
            }
            _ => {}
        }
        if acceptance.destination.len() < 8 && acceptance.retry_source.is_none() {
            return None;
        }
        if self.config.retry && !acceptance.validated {
            self.send_retry(&acceptance, remote, time);
            return None;
        }
        let random = super::QUICConnection::derived_random(&mut *self.random).ok()?;
        let connection =
            QUICConnection::server(self.config.quic.clone(), tls, acceptance, remote, random, now, time).ok()?;
        let handle = self.insert(connection);
        self.accepted.push_back(handle);
        let connection = self.connections.get_mut(&handle)?;
        connection.receive(datagram, remote, ecn, now);
        self.after(handle, time);
        Some(handle)
    }

    /// A Retry with a token of the client's address and IDs (RFC 9000 §8.1.2, §17.2.5).
    pub fn send_retry(&mut self, acceptance: &QUICAcceptance, remote: IPEndpoint, time: i64) {
        let (Some(key), Some(profile)) = (&self.token_key, acceptance.version.profile()) else { return };
        if self.outgoing.len() >= self.config.maximum_stateless {
            return;
        }
        let length = self.config.quic.connection_id_length.max(8);
        let Ok(source) = QUICConnectionID::random(length, &mut *self.random) else { return };
        let token = QUICToken {
            kind: QUICTokenKind::Retry { original_destination: acceptance.original_destination, retry_source: source },
            address: remote,
            version: acceptance.version,
            time: time.max(0) as u64,
        };
        let Ok(token) = key.seal(&token, &mut *self.random) else { return };
        let retry = QUICRetry {
            version: acceptance.version,
            destination: acceptance.source,
            source,
            token: &token,
            tag: [0; 16],
        };
        let mut packet = Vec::new();
        let unused = self.random.next_u32().map(|value| value as u8).unwrap_or(0);
        if retry.encode_without_tag(unused, &mut packet).is_err() {
            return;
        }
        let Ok(tag) = QUICRetryIntegrity::tag(profile, &acceptance.original_destination, &packet) else { return };
        packet.extend_from_slice(&tag);
        self.outgoing.push_back((remote, packet));
    }

    /// Closes the connection a client's Initial `header` starts, whose Retry
    /// token is invalid, with INVALID_TOKEN (RFC 9000 §8.1.2, §10.2.3): an
    /// Initial packet with CONNECTION_CLOSE, sealed with the server's Initial
    /// keys of the client's Destination Connection ID, keeping no state.
    pub fn refuse_token(&mut self, header: &QUICLongHeader<'_>, remote: IPEndpoint) {
        let Some(profile) = header.version.profile() else { return };
        if self.outgoing.len() >= self.config.maximum_stateless {
            return;
        }
        let Ok(secret) = QUICSecret::initial(profile, &header.destination, QUICRole::Server) else { return };
        let Ok(keys) = QUICKeys::new(profile, &secret) else { return };
        let length = self.config.quic.connection_id_length.max(8);
        let Ok(source) = QUICConnectionID::random(length, &mut *self.random) else { return };
        let close = QUICFrame::ConnectionClose {
            error: QUICErrorCode::INVALID_TOKEN,
            frame_type: QUICFrameType::PADDING,
            reason: &[],
        };
        let mut payload = Vec::new();
        if close.encode(&mut payload).is_err() {
            return;
        }
        // Enough bytes for the header protection's sample (RFC 9001 §5.4.2).
        payload.resize(payload.len().max(4), 0);
        let initial = QUICHeader::Long(QUICLongHeader {
            packet_type: QUICPacketType::Initial,
            version: header.version,
            destination: header.source,
            source,
            token: &[],
        });
        let mut packet = Vec::new();
        let Ok(offset) = initial.encode(true, 0, 1, payload.len() + QUICPacketKey::TAG_LENGTH, &mut packet) else {
            return;
        };
        let header_length = packet.len();
        packet.extend_from_slice(&payload);
        if keys.packet.seal(0, header_length, &mut packet).is_ok() && keys.header.apply(&mut packet, offset, 1).is_ok()
        {
            self.outgoing.push_back((remote, packet));
        }
    }

    /// After a connection's work: its routes, its NEW_TOKEN once confirmed,
    /// and its removal once closed.
    pub fn after(&mut self, handle: u64, time: i64) {
        let Some(connection) = self.connections.get_mut(&handle) else { return };
        if connection.role == super::QUICRole::Server
            && connection.handshake_confirmed
            && !connection.token_issued
            && let Some(key) = &self.token_key
        {
            connection.token_issued = true;
            let token = QUICToken {
                kind: QUICTokenKind::NewToken,
                address: connection.remote,
                version: connection.version,
                time: time.max(0) as u64,
            };
            if let Ok(token) = key.seal(&token, &mut *self.random) {
                connection.pending.new_token = Some(token);
            }
        }
        // A closed connection stays until the application took its events.
        if connection.is_closed() && connection.events.is_empty() {
            self.connections.remove(&handle);
        }
        self.update_routes(handle);
    }

    /// The next datagram to send: stateless packets first, then each
    /// connection's in turn.
    pub fn transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<QUICTransmission> {
        if let Some((destination, packet)) = self.outgoing.pop_front() {
            out.clear();
            out.extend_from_slice(&packet);
            return Some(QUICTransmission { destination, ecn: QUICECN::NotECT });
        }
        let handles: Vec<u64> = self
            .connections
            .range(self.turn..)
            .chain(self.connections.range(..self.turn))
            .map(|(handle, _)| *handle)
            .collect();
        for handle in handles {
            let Some(connection) = self.connections.get_mut(&handle) else { continue };
            if let Some(transmission) = connection.transmit(now, out) {
                self.turn = handle + 1;
                self.update_routes(handle);
                return Some(transmission);
            }
        }
        None
    }

    /// When [`QUICEndpoint::expire`] is next due.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.connections.values().filter_map(QUICConnection::poll_timeout).min()
    }

    /// Fires the timers due at `now` and forgets the connections that closed.
    pub fn expire(&mut self, now: Instant, time: i64) {
        let handles: Vec<u64> = self.connections.keys().copied().collect();
        for handle in handles {
            if let Some(connection) = self.connections.get_mut(&handle) {
                connection.expire(now);
            }
            self.after(handle, time);
        }
    }
}
