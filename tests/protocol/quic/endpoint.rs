//! Two endpoints over a simulated network: routing by connection ID (RFC
//! 9000 §5.2), Retry and tokens (§8.1), Version Negotiation (§6, RFC
//! 9368), stateless resets (§10.3), 0-RTT (RFC 9001 §4.6), migration (§9),
//! key updates (RFC 9001 §6), DATAGRAM frames (RFC 9221) and greasing the
//! QUIC bit (RFC 9287).

use std::sync::Arc;
use std::time::Duration;

use umilib::protocol::ip::IPEndpoint;
use umilib::protocol::quic::{
    QUICCloseReason, QUICConfig, QUICConnection, QUICECN, QUICEndpoint, QUICEndpointConfig, QUICEvent, QUICPacket,
    QUICStreamID, QUICVersion,
};
use umilib::protocol::tls::{TLSClientConfig, TLSEarlyData, TLSReplayCache, TLSServerConfig, TLSSessionCache};
use umilib::runtime::Instant;

use super::connection::Network;
use crate::tls::handshake::{Fixture, TIME};
use crate::tls::resumption::Resumption;

/// What decides that a datagram is lost: whether the client sent it, its bytes.
pub type EndpointDropper = Box<dyn FnMut(bool, &[u8]) -> bool>;

/// A client endpoint and a server endpoint, the datagrams between them, and a clock.
pub struct Endpoints {
    pub client: QUICEndpoint,
    pub server: QUICEndpoint,
    pub tls: Arc<TLSClientConfig>,
    pub now: Instant,
    pub client_address: IPEndpoint,
    pub server_address: IPEndpoint,
    pub on_the_way: Vec<(Instant, bool, IPEndpoint, Vec<u8>)>,
    pub delay: Duration,
    pub log: Vec<(bool, Vec<u8>)>,
    pub drop: EndpointDropper,
}

impl Endpoints {
    pub fn new(client: QUICConfig, server: QUICEndpointConfig, tls: TLSClientConfig) -> Endpoints {
        let client = QUICEndpoint::new(QUICEndpointConfig::new(Arc::new(client), None), Fixture::random(10)).unwrap();
        let server = QUICEndpoint::new(server, Fixture::random(20)).unwrap();
        Endpoints {
            client,
            server,
            tls: Arc::new(tls),
            now: Instant::from_nanos(1_000_000_000),
            client_address: Network::endpoint(2, 50000),
            server_address: Network::endpoint(1, 443),
            on_the_way: Vec::new(),
            delay: Duration::from_millis(10),
            log: Vec::new(),
            drop: Box::new(|_, _| false),
        }
    }

    pub fn server_config(quic: QUICConfig, tls: TLSServerConfig) -> QUICEndpointConfig {
        QUICEndpointConfig::new(Arc::new(quic), Some(Arc::new(tls)))
    }

    pub fn simple() -> Endpoints {
        let (client, server) = Network::configs();
        Endpoints::new(QUICConfig::default(), Endpoints::server_config(QUICConfig::default(), server), client)
    }

    pub fn connect(&mut self, token: Option<Vec<u8>>, seed: u8) -> u64 {
        let tls = self.tls.clone();
        self.client
            .connect(tls, Some("server.example"), self.server_address, token, Fixture::random(seed), self.now, TIME)
            .unwrap()
    }

    /// Moves datagrams until both endpoints are quiet, firing no timer.
    pub fn run(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            let mut out = Vec::new();
            while let Some(transmission) = self.client.transmit(self.now, &mut out) {
                moved = true;
                assert_eq!(transmission.destination, self.server_address);
                self.send(true, self.client_address, std::mem::take(&mut out));
            }
            while let Some(transmission) = self.server.transmit(self.now, &mut out) {
                moved = true;
                self.send(false, transmission.destination, std::mem::take(&mut out));
            }
            let now = self.now;
            let (arrived, later): (Vec<_>, Vec<_>) =
                std::mem::take(&mut self.on_the_way).into_iter().partition(|(time, ..)| *time <= now);
            self.on_the_way = later;
            for (_, from_client, address, datagram) in arrived {
                moved = true;
                self.log.push((from_client, datagram.clone()));
                if from_client {
                    self.server.receive(&datagram, address, QUICECN::NotECT, self.now, TIME);
                } else {
                    self.client.receive(&datagram, self.server_address, QUICECN::NotECT, self.now, TIME);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("never quiet");
    }

    pub fn send(&mut self, from_client: bool, address: IPEndpoint, datagram: Vec<u8>) {
        if (self.drop)(from_client, &datagram) {
            return;
        }
        // The client's datagrams come from its address as the server sees it.
        let address = if from_client { self.client_address } else { address };
        self.on_the_way.push((self.now + self.delay, from_client, address, datagram));
    }

    pub fn tick(&mut self) {
        let arrival = self.on_the_way.iter().map(|(time, ..)| *time).min();
        let next = [self.client.poll_timeout(), self.server.poll_timeout(), arrival].into_iter().flatten().min();
        if let Some(next) = next {
            self.now = self.now.max(next);
        }
        self.client.expire(self.now, TIME);
        self.server.expire(self.now, TIME);
    }

    pub fn until(&mut self, limit: usize, mut done: impl FnMut(&mut Endpoints) -> bool) {
        for _ in 0..limit {
            self.run();
            if done(self) {
                return;
            }
            self.run();
            self.tick();
        }
        panic!("not done after {limit} rounds");
    }

    pub fn client_connection(&mut self, handle: u64) -> &mut QUICConnection {
        self.client.connection(handle).unwrap()
    }

    pub fn only_server(&mut self) -> &mut QUICConnection {
        let handle = *self.server.connections.keys().next().unwrap();
        self.server.connection(handle).unwrap()
    }

    /// Runs until the connection `handle` of the client and the server's are both confirmed.
    pub fn handshake(&mut self, handle: u64) {
        self.until(1000, |endpoints| {
            endpoints.client.connections.get(&handle).is_some_and(|connection| connection.handshake_confirmed)
                && endpoints.server.connections.values().any(|connection| connection.handshake_complete)
        });
    }

    /// Sends `data` on a new stream and reads it back at the server.
    pub fn transfer(&mut self, handle: u64, data: &[u8]) -> QUICStreamID {
        let stream = self.client_connection(handle).open_stream(true).unwrap();
        assert_eq!(self.client_connection(handle).stream_send(stream, data, true).unwrap(), data.len());
        let mut received = Vec::new();
        self.until(2000, |endpoints| {
            let server = endpoints.server.connections.values_mut().next().unwrap();
            let (chunk, fin) = Network::read_all(server, stream);
            received.extend_from_slice(&chunk);
            fin
        });
        assert!(received == data);
        stream
    }
}

#[test]
fn routing_by_connection_id() {
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    assert_eq!(endpoints.server.accept(), Some(*endpoints.server.connections.keys().next().unwrap()));
    // The server's routes are its connection IDs, the client's first ID gone after the handshake.
    let server = endpoints.only_server();
    let ids: Vec<_> = server.local_ids.ids.values().map(|issued| issued.id).collect();
    let original = server.original_destination;
    assert!(ids.iter().all(|id| endpoints.server.routes.contains_key(id)));
    assert!(!endpoints.server.routes.contains_key(&original));
    endpoints.transfer(handle, b"routed");
    // A second connection gets its own server connection.
    let second = endpoints.connect(None, 2);
    endpoints.handshake(second);
    assert_eq!(endpoints.server.connections.len(), 2);
}

#[test]
fn retry_validates_the_address() {
    // RFC 9000 §8.1.2: a Retry, then the Initial with its token; the
    // parameters authenticate the exchange (§7.3).
    let (client, server) = Network::configs();
    let mut config = Endpoints::server_config(QUICConfig::default(), server);
    config.token_key = Some([9; 32]);
    config.retry = true;
    let mut endpoints = Endpoints::new(QUICConfig::default(), config, client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    // One Retry per datagram of the client's first flight at most (RFC 9000
    // §17.2.5.1); the client takes the first (§17.2.5.2).
    let flight = endpoints.log.iter().take_while(|(from_client, _)| *from_client).count();
    let retries: Vec<umilib::protocol::quic::QUICConnectionID> = endpoints
        .log
        .iter()
        .filter_map(|(from_client, datagram)| match QUICPacket::decode(datagram, 8) {
            Ok(QUICPacket::Retry(retry)) if !from_client => Some(retry.source),
            _ => None,
        })
        .collect();
    assert!(!retries.is_empty() && retries.len() <= flight);
    assert_eq!(endpoints.client_connection(handle).retry_source, Some(retries[0]));
    let client = endpoints.client_connection(handle);
    assert!(client.retry_source.is_some() && !client.token.is_empty());
    let retry_source = client.retry_source;
    let server = endpoints.only_server();
    assert_eq!(server.retry_source, retry_source);
    assert!(server.validated);
    endpoints.transfer(handle, b"after a retry");
}

#[test]
fn new_tokens_skip_the_retry() {
    // RFC 9000 §8.1.3: a server's NEW_TOKEN lets a later connection skip the Retry.
    let (client, server) = Network::configs();
    let mut config = Endpoints::server_config(QUICConfig::default(), server);
    config.token_key = Some([9; 32]);
    config.retry = true;
    let mut endpoints = Endpoints::new(QUICConfig::default(), config, client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| {
        let client = endpoints.client.connections.get_mut(&handle).unwrap();
        client.events.iter().any(|event| matches!(event, QUICEvent::NewToken { .. }))
    });
    let token = endpoints
        .client_connection(handle)
        .events
        .iter()
        .find_map(|event| match event {
            QUICEvent::NewToken { token } => Some(token.clone()),
            _ => None,
        })
        .unwrap();
    endpoints.log.clear();
    let second = endpoints.connect(Some(token), 2);
    endpoints.handshake(second);
    assert!(
        endpoints.log.iter().all(|(_, datagram)| !matches!(QUICPacket::decode(datagram, 8), Ok(QUICPacket::Retry(_))))
    );
    assert!(endpoints.client_connection(second).retry_source.is_none());
}

#[test]
fn version_negotiation() {
    // A client of version 2 to a server of version 1: Version Negotiation,
    // then version 1, its downgrade check passing (RFC 9368 §4).
    let (client, server) = Network::configs();
    let server =
        Endpoints::server_config(QUICConfig { versions: vec![QUICVersion::V1], ..QUICConfig::default() }, server);
    let client_config = QUICConfig { versions: vec![QUICVersion::V2, QUICVersion::V1], ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(client_config, server, client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    let negotiation = endpoints
        .log
        .iter()
        .find_map(|(_, datagram)| match QUICPacket::decode(datagram, 8) {
            Ok(QUICPacket::VersionNegotiation(packet)) => Some(packet.versions().collect::<Vec<_>>()),
            _ => None,
        })
        .unwrap();
    assert!(negotiation.contains(&QUICVersion::V1) && negotiation.iter().any(|version| version.is_reserved()));
    let client = endpoints.client_connection(handle);
    assert_eq!((client.version, client.negotiated_from), (QUICVersion::V1, Some(QUICVersion::V2)));
    endpoints.transfer(handle, b"version 1");
}

#[test]
fn version_negotiation_listing_the_version_is_ignored() {
    // RFC 9368 §4: a Version Negotiation that lists the version tried is forged.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    let client = endpoints.client_connection(handle);
    let mut forged = Vec::new();
    umilib::protocol::quic::QUICVersionNegotiation::encode(
        client.original_destination.as_slice(),
        client.initial_source.as_slice(),
        &[client.version, QUICVersion(0x1A2A_3A4A)],
        0,
        &mut forged,
    )
    .unwrap();
    // The fields are swapped back: the forgery answers the client's packet.
    let mut answer = Vec::new();
    umilib::protocol::quic::QUICVersionNegotiation::encode(
        client.initial_source.as_slice(),
        client.original_destination.as_slice(),
        &[client.version],
        0,
        &mut answer,
    )
    .unwrap();
    let version = client.version;
    let (server_address, now) = (endpoints.server_address, endpoints.now);
    let client = endpoints.client_connection(handle);
    client.receive(&answer, server_address, QUICECN::NotECT, now);
    let client = endpoints.client_connection(handle);
    assert_eq!((client.version, client.negotiated_from), (version, None));
    endpoints.handshake(handle);
    let _ = forged;
}

#[test]
fn stateless_reset() {
    // RFC 9000 §10.3: a server that lost the connection answers with a reset
    // the client recognizes by the token of its connection ID.
    let (client, server) = Network::configs();
    let quic = QUICConfig { reset_key: Some([5; 32]), ..QUICConfig::default() };
    let mut endpoints =
        Endpoints::new(QUICConfig::default(), Endpoints::server_config(quic.clone(), server.clone()), client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| endpoints.client.connections[&handle].peer_ids.ids.len() > 1);
    // The server restarts without its state, with the same key.
    endpoints.server = QUICEndpoint::new(Endpoints::server_config(quic, server), Fixture::random(30)).unwrap();
    endpoints.client_connection(handle).ping();
    endpoints.until(100, |endpoints| {
        endpoints.client.connections.get(&handle).is_none_or(|connection| {
            connection
                .events
                .iter()
                .any(|event| *event == QUICEvent::Closed { reason: QUICCloseReason::StatelessReset })
        })
    });
}

#[test]
fn zero_rtt() {
    // RFC 9001 §4.6: a resumed connection sends stream data in 0-RTT packets,
    // which the server reads before the handshake completes.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Network::configs();
    client.sessions = Some(cache.clone());
    client.early_data = true;
    server.tickets = Some(Resumption::keys(1));
    server.maximum_early_data = 1;
    server.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 64)));
    let mut endpoints =
        Endpoints::new(QUICConfig::default(), Endpoints::server_config(QUICConfig::default(), server), client);
    let first = endpoints.connect(None, 1);
    endpoints.handshake(first);
    endpoints.until(10, |_| {
        use umilib::protocol::tls::TLSSessionStore;
        cache.take("server.example").map(|ticket| cache_put(&cache, ticket)).is_some()
    });
    let second = endpoints.connect(None, 2);
    let (now, address) = (endpoints.now, endpoints.client_address);
    let client = endpoints.client_connection(second);
    assert_eq!(client.tls.session.early_data, TLSEarlyData::Offered);
    assert!(client.zero_rtt.is_some(), "0-RTT keys after the ClientHello");
    let stream = client.open_stream(true).unwrap();
    client.stream_send(stream, b"early", true).unwrap();
    let mut out = Vec::new();
    let mut zero_rtt = false;
    let mut datagrams = Vec::new();
    while client.transmit(now, &mut out).is_some() {
        let mut offset = 0;
        while offset < out.len() {
            let Ok(packet) = QUICPacket::decode(&out[offset..], 8) else { break };
            if let QUICPacket::Protected(protected) = packet {
                zero_rtt |= protected.header.packet_type() == umilib::protocol::quic::QUICPacketType::ZeroRTT;
            }
            offset += packet.length(&out[offset..]);
        }
        datagrams.push(std::mem::take(&mut out));
    }
    for datagram in datagrams {
        endpoints.send(true, address, datagram);
    }
    assert!(zero_rtt, "the data goes in 0-RTT packets");
    endpoints.handshake(second);
    let server = endpoints.server.connections.values_mut().last().unwrap();
    assert_eq!(server.tls.session.early_data, TLSEarlyData::Accepted);
    let (data, fin) = Network::read_all(server, stream);
    assert_eq!((data.as_slice(), fin), (&b"early"[..], true));
}

fn cache_put(cache: &TLSSessionCache, ticket: umilib::protocol::tls::TLSSessionTicket) {
    use umilib::protocol::tls::TLSSessionStore;
    cache.put("server.example", ticket);
}

#[test]
fn zero_rtt_rejected() {
    // A server whose limits changed refuses 0-RTT (RFC 9001 §4.6.3): the
    // client's streams are reset and it is told (§4.6.2).
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Network::configs();
    client.sessions = Some(cache.clone());
    client.early_data = true;
    server.tickets = Some(Resumption::keys(1));
    server.maximum_early_data = 1;
    server.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 64)));
    let mut endpoints =
        Endpoints::new(QUICConfig::default(), Endpoints::server_config(QUICConfig::default(), server.clone()), client);
    let first = endpoints.connect(None, 1);
    endpoints.handshake(first);
    endpoints.run();
    let smaller = QUICConfig { initial_max_data: 1000, ..QUICConfig::default() };
    endpoints.server = QUICEndpoint::new(Endpoints::server_config(smaller, server), Fixture::random(40)).unwrap();
    let second = endpoints.connect(None, 2);
    let client = endpoints.client_connection(second);
    let stream = client.open_stream(true).unwrap();
    client.stream_send(stream, b"early", true).unwrap();
    endpoints.handshake(second);
    let client = endpoints.client_connection(second);
    assert_eq!(client.tls.session.early_data, TLSEarlyData::Rejected);
    assert!(client.events.contains(&QUICEvent::ZeroRTTRejected));
    assert!(client.streams.streams.is_empty());
    // Streams open again from the start.
    assert_eq!(client.open_stream(true).unwrap(), QUICStreamID(0));
}

#[test]
fn nat_rebinding() {
    // RFC 9000 §9.3: the client's address changes; the server validates the
    // new path and goes on there.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| endpoints.client.connections[&handle].peer_ids.ids.len() > 1);
    endpoints.client_address = Network::endpoint(3, 40000);
    endpoints.transfer(handle, &vec![1u8; 30_000]);
    let server = endpoints.only_server();
    assert_eq!(server.remote, Network::endpoint(3, 40000));
    endpoints.until(10, |endpoints| endpoints.only_server().path_validated);
}

#[test]
fn active_migration() {
    // RFC 9000 §9.2: a client moves with a new connection ID.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| endpoints.client.connections[&handle].peer_ids.ids.len() > 1);
    let before = endpoints.client_connection(handle).peer_ids.current().unwrap().id;
    let now = endpoints.now;
    endpoints.client_connection(handle).migrate_local(now).unwrap();
    endpoints.client_address = Network::endpoint(4, 41000);
    endpoints.transfer(handle, b"moved");
    let after = endpoints.client_connection(handle).peer_ids.current().unwrap().id;
    assert_ne!(before, after);
    endpoints.until(10, |endpoints| endpoints.only_server().path_validated);
}

#[test]
fn key_updates() {
    // RFC 9001 §6: either end updates; the other follows; data goes on.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.transfer(handle, b"phase 0");
    let now = endpoints.now;
    endpoints.client_connection(handle).update_keys(now).unwrap();
    // A second update waits for an acknowledgment of the first phase (RFC 9001 §6.1).
    endpoints.client_connection(handle).ping();
    endpoints.run();
    let stream = endpoints.client_connection(handle).open_stream(false).unwrap();
    endpoints.client_connection(handle).stream_send(stream, b"phase 1", true).unwrap();
    endpoints.until(100, |endpoints| endpoints.only_server().one_rtt.as_ref().is_some_and(|keys| keys.phase));
    assert!(endpoints.client_connection(handle).one_rtt.as_ref().unwrap().phase);
    endpoints.until(100, |endpoints| endpoints.client.connections[&handle].update_keys_permitted());
}

#[test]
fn datagrams() {
    // RFC 9221: DATAGRAM frames both ways when both ends accept them.
    let (client, server) = Network::configs();
    let quic = QUICConfig { max_datagram_frame_size: 1200, ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(quic.clone(), Endpoints::server_config(quic, server), client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.client_connection(handle).send_datagram(b"unreliable").unwrap();
    endpoints.until(10, |endpoints| !endpoints.only_server().datagrams.is_empty());
    assert_eq!(endpoints.only_server().read_datagram().unwrap(), b"unreliable");
    // Too large for the peer's limit.
    assert!(endpoints.client_connection(handle).send_datagram(&[0; 1300]).is_err());
    // Within a limit larger than packets, only what fits one 1-RTT packet
    // goes, as DATAGRAM frames are not split (RFC 9221 §5).
    let (client, server) = Network::configs();
    let quic = QUICConfig { max_datagram_frame_size: 65_535, ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(quic.clone(), Endpoints::server_config(quic, server), client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    assert!(endpoints.client_connection(handle).send_datagram(&[1; 1200]).is_err());
    endpoints.client_connection(handle).send_datagram(&[2; 1100]).unwrap();
    endpoints.client_connection(handle).send_datagram(b"after").unwrap();
    endpoints.until(10, |endpoints| endpoints.only_server().datagrams.len() == 2);
    assert_eq!(endpoints.only_server().read_datagram().unwrap(), [2; 1100]);
}

#[test]
fn datagrams_not_accepted() {
    // A peer that did not advertise max_datagram_frame_size takes none (RFC 9221 §3).
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    assert!(endpoints.client_connection(handle).send_datagram(b"x").is_err());
}

#[test]
fn greasing_the_quic_bit() {
    // RFC 9287: once both ends advertise grease_quic_bit, packets go with
    // the QUIC bit at random, and are read.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.log.clear();
    endpoints.transfer(handle, &vec![2u8; 20_000]);
    let cleared =
        endpoints.log.iter().filter(|(_, datagram)| datagram[0] & 0x80 == 0 && datagram[0] & 0x40 == 0).count();
    assert!(cleared > 0, "some short headers without the QUIC bit");
    // Without the parameter, the bit is always set (RFC 9287 §3.1).
    let (client, server) = Network::configs();
    let off = QUICConfig { grease_quic_bit: false, ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(off.clone(), Endpoints::server_config(off, server), client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.transfer(handle, &vec![2u8; 20_000]);
    assert!(endpoints.log.iter().all(|(_, datagram)| datagram[0] & 0x40 != 0));
}

#[test]
fn routing_by_protocol_and_name() {
    // QUICRule: the server name and protocol of the handshake, and the version.
    use umilib::protocol::quic::QUICRule;
    use umilib::protocol::tls::TLSNamePattern;
    use umilib::service::Rule;
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    let server = endpoints.only_server();
    assert!(QUICRule::new(TLSNamePattern::parse("server.example")).with_protocol(b"test").matches(server));
    assert!(QUICRule::new(TLSNamePattern::parse("*.example")).matches(server));
    assert!(!QUICRule::new(TLSNamePattern::Any).with_protocol(b"h3").matches(server));
    assert!(!QUICRule::new(TLSNamePattern::parse("other.example")).matches(server));
    let version = server.version;
    assert!(QUICRule::new(TLSNamePattern::Any).with_version(version).matches(server));
    assert!(!QUICRule::new(TLSNamePattern::Any).with_version(QUICVersion(0x0A0A_0A0A)).matches(server));
}

#[test]
fn version_negotiation_is_never_answered() {
    // RFC 9000 §6.1: no Version Negotiation in answer to one; a packet of an
    // unknown version of the same size gets one.
    let mut endpoints = Endpoints::simple();
    let (now, address) = (endpoints.now, endpoints.client_address);
    let mut negotiation = Vec::new();
    let versions = vec![QUICVersion(0x1A2A_3A4A); 300];
    umilib::protocol::quic::QUICVersionNegotiation::encode(&[1; 8], &[2; 8], &versions, 0, &mut negotiation).unwrap();
    assert!(negotiation.len() >= 1200);
    endpoints.server.receive(&negotiation, address, QUICECN::NotECT, now, TIME);
    assert!(endpoints.server.outgoing.is_empty());
    let mut unknown = negotiation.clone();
    unknown[1..5].copy_from_slice(&0x1A2A_3A4Au32.to_be_bytes());
    endpoints.server.receive(&unknown, address, QUICECN::NotECT, now, TIME);
    assert_eq!(endpoints.server.outgoing.len(), 1);
}

#[test]
fn version_negotiation_echoes_the_connection_ids() {
    // RFC 9000 §17.2.1: Version Negotiation carries the client's IDs back,
    // swapped; one that does not answers no packet of this client.
    let (client, server) = Network::configs();
    let config = QUICConfig { versions: vec![QUICVersion::V1, QUICVersion::V2], ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(config, Endpoints::server_config(QUICConfig::default(), server), client);
    let handle = endpoints.connect(None, 1);
    let (server_address, now) = (endpoints.server_address, endpoints.now);
    let client = endpoints.client_connection(handle);
    let (source, original) = (client.initial_source, client.original_destination);
    let negotiation = |destination: &[u8], source: &[u8]| {
        let mut packet = Vec::new();
        umilib::protocol::quic::QUICVersionNegotiation::encode(source, destination, &[QUICVersion::V2], 0, &mut packet)
            .unwrap();
        packet
    };
    // `encode` swaps what it is given, as a server answering does.
    client.receive(&negotiation(&[9; 8], original.as_slice()), server_address, QUICECN::NotECT, now);
    assert_eq!((client.version, client.negotiated_from), (QUICVersion::V1, None));
    client.receive(&negotiation(source.as_slice(), &[9; 8]), server_address, QUICECN::NotECT, now);
    assert_eq!((client.version, client.negotiated_from), (QUICVersion::V1, None));
    client.receive(&negotiation(source.as_slice(), original.as_slice()), server_address, QUICECN::NotECT, now);
    assert_eq!((client.version, client.negotiated_from), (QUICVersion::V2, Some(QUICVersion::V1)));
}

#[test]
fn an_invalid_retry_token_is_refused() {
    // RFC 9000 §8.1.2: an Initial whose Retry token does not hold for it
    // (here another connection's, with another Destination Connection ID)
    // is answered with INVALID_TOKEN, as the client takes no second Retry.
    let (client, server) = Network::configs();
    let mut config = Endpoints::server_config(QUICConfig::default(), server);
    config.token_key = Some([9; 32]);
    config.retry = true;
    let mut endpoints = Endpoints::new(QUICConfig::default(), config, client);
    let first = endpoints.connect(None, 1);
    endpoints.until(100, |endpoints| endpoints.client.connections[&first].retry_source.is_some());
    let token = endpoints.client_connection(first).token.clone();
    let second = endpoints.connect(Some(token), 2);
    endpoints.until(100, |endpoints| {
        endpoints.client.connections.get(&second).is_none_or(|connection| {
            connection.events.iter().any(|event| {
                *event
                    == QUICEvent::Closed {
                        reason: QUICCloseReason::Peer {
                            error: umilib::protocol::quic::QUICErrorCode::INVALID_TOKEN,
                            reason: Vec::new(),
                        },
                    }
            })
        })
    });
    assert!(endpoints.client.connections.contains_key(&second), "the client was told why");
    endpoints.handshake(first);
}

#[test]
fn a_preferred_address() {
    // RFC 9000 §9.6, §5.1.1: the server's preferred address carries its
    // connection ID of sequence 1 and that ID's reset token, which the
    // client then holds like those of NEW_CONNECTION_ID.
    let (client, server) = Network::configs();
    let preferred = umilib::protocol::quic::QUICPreferredAddress {
        ipv4: umilib::protocol::ip::IPv4Address::new(192, 0, 2, 9),
        ipv4_port: 4433,
        ipv6: umilib::protocol::ip::IPv6Address([0; 16]),
        ipv6_port: 0,
        connection_id: umilib::protocol::quic::QUICConnectionID::EMPTY,
        reset_token: [0; 16],
    };
    let quic = QUICConfig { preferred_address: Some(preferred), ..QUICConfig::default() };
    let mut endpoints = Endpoints::new(QUICConfig::default(), Endpoints::server_config(quic, server), client);
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    let server = endpoints.only_server();
    let issued = server.local_ids.ids[&1];
    let advertised = server.local_parameters.preferred_address.unwrap();
    assert_eq!((advertised.ipv4, advertised.ipv4_port), (preferred.ipv4, preferred.ipv4_port));
    assert_eq!(advertised.connection_id, issued.id);
    assert_eq!(Some(advertised.reset_token), issued.reset_token);
    assert!(endpoints.server.routes.contains_key(&issued.id));
    let client = endpoints.client_connection(handle);
    assert_eq!(client.peer_ids.ids.get(&1).copied(), Some(issued));
    endpoints.transfer(handle, b"after a preferred address");
}

/// The client's datagrams of `data` on a new stream, made at once without sending them.
fn datagrams_of(endpoints: &mut Endpoints, handle: u64, data: &[u8]) -> Vec<Vec<u8>> {
    let now = endpoints.now;
    let client = endpoints.client_connection(handle);
    let stream = client.open_stream(false).unwrap();
    client.stream_send(stream, data, true).unwrap();
    client.transmit_all(now)
}

#[test]
fn only_the_newest_packet_moves_the_peer() {
    // RFC 9000 §9.3: the address changes only for the highest-numbered
    // packet that is not probing; an older one from the old address, late,
    // does not move the server back.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| endpoints.client.connections[&handle].peer_ids.ids.len() > 1);
    let (old, new, now) = (endpoints.client_address, Network::endpoint(3, 40000), endpoints.now);
    let older = datagrams_of(&mut endpoints, handle, b"older");
    let newer = datagrams_of(&mut endpoints, handle, b"newer");
    for datagram in &newer {
        endpoints.server.receive(datagram, new, QUICECN::NotECT, now, TIME);
    }
    assert_eq!(endpoints.only_server().remote, new);
    for datagram in &older {
        endpoints.server.receive(datagram, old, QUICECN::NotECT, now, TIME);
    }
    assert_eq!(endpoints.only_server().remote, new);
}

#[test]
fn answers_to_challenges_go_where_they_came_from() {
    // RFC 9000 §8.2.2, §9.3: a client that moves sends PATH_CHALLENGE with
    // its data; the server, moving there, answers there, never to the old address.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.until(10, |endpoints| endpoints.client.connections[&handle].peer_ids.ids.len() > 1);
    let (new, now) = (Network::endpoint(4, 41000), endpoints.now);
    endpoints.client_connection(handle).migrate_local(now).unwrap();
    let moved = datagrams_of(&mut endpoints, handle, b"moved");
    for datagram in &moved {
        endpoints.server.receive(datagram, new, QUICECN::NotECT, now, TIME);
    }
    let mut out = Vec::new();
    let mut destinations = Vec::new();
    while let Some(transmission) = endpoints.server.transmit(now, &mut out) {
        destinations.push(transmission.destination);
    }
    assert!(!destinations.is_empty() && destinations.iter().all(|destination| *destination == new), "{destinations:?}");
}

#[test]
fn answers_to_probes_from_elsewhere_are_limited() {
    // RFC 9000 §8.2.1, §9.1: a probe from an address not validated is
    // answered there, without moving, and in no more than three times its
    // datagram, even if that is less than 1200 bytes.
    let mut endpoints = Endpoints::simple();
    let handle = endpoints.connect(None, 1);
    endpoints.handshake(handle);
    endpoints.run();
    let (elsewhere, now) = (Network::endpoint(5, 42000), endpoints.now);
    let client = endpoints.client_connection(handle);
    // Only the PATH_CHALLENGE: no acknowledgment owed goes with it, as one
    // would not be probing.
    client.spaces[2].unacknowledged = false;
    client.spaces[2].received.acknowledged();
    let mut challenge = Vec::new();
    umilib::protocol::quic::QUICFrame::PathChallenge { data: [3; 8] }.encode(&mut challenge).unwrap();
    client.send_extension_frame(challenge).unwrap();
    let probes = client.transmit_all(now);
    assert_eq!(probes.len(), 1);
    assert!(probes[0].len() < 400);
    let remote = endpoints.only_server().remote;
    endpoints.server.receive(&probes[0], elsewhere, QUICECN::NotECT, now, TIME);
    assert_eq!(endpoints.only_server().remote, remote);
    let mut out = Vec::new();
    let transmission = endpoints.server.transmit(now, &mut out).unwrap();
    assert_eq!(transmission.destination, elsewhere);
    assert!(out.len() <= 3 * probes[0].len(), "{} bytes for {}", out.len(), probes[0].len());
}

#[test]
fn timers_wait_for_what_can_be_sent() {
    // A server that read 0-RTT owes an acknowledgment it can only send in
    // 1-RTT packets, after the handshake (RFC 9000 §12.4, §17.2.3): its timer
    // is not that of the acknowledgment meanwhile, so that it always lies ahead.
    let cache = Arc::new(TLSSessionCache::new(8));
    let (mut client, mut server) = Network::configs();
    client.sessions = Some(cache.clone());
    client.early_data = true;
    server.tickets = Some(Resumption::keys(1));
    server.maximum_early_data = 1;
    server.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 64)));
    let mut endpoints =
        Endpoints::new(QUICConfig::default(), Endpoints::server_config(QUICConfig::default(), server), client);
    let first = endpoints.connect(None, 1);
    endpoints.handshake(first);
    endpoints.run();
    endpoints.delay = Duration::from_millis(50);
    let second = endpoints.connect(None, 2);
    let client = endpoints.client_connection(second);
    let stream = client.open_stream(true).unwrap();
    client.stream_send(stream, b"early", true).unwrap();
    for _ in 0..1000 {
        endpoints.run();
        let now = endpoints.now;
        for connection in endpoints.server.connections.values().chain(endpoints.client.connections.values()) {
            assert!(connection.poll_timeout().is_none_or(|time| time > now), "{:?} at {now:?}", connection.role);
        }
        if endpoints.client.connections[&second].handshake_confirmed {
            return;
        }
        endpoints.tick();
    }
    panic!("no handshake");
}
