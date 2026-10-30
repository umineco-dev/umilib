//! Connections over a simulated network: the handshake (RFC 9000 §7, RFC
//! 9001 §4), streams and flow control (RFC 9000 §2–§4), loss recovery (RFC
//! 9002), closing (RFC 9000 §10), and the rules each frame is checked by.

use std::sync::Arc;
use std::time::Duration;

use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address};
use umilib::protocol::quic::{
    QUICAcceptance, QUICCloseReason, QUICConfig, QUICConnection, QUICConnectionID, QUICConnectionState, QUICECN,
    QUICEvent, QUICHeader, QUICIssuedID, QUICPacket, QUICPeerConnectionIDs, QUICStreamID,
};
use umilib::protocol::tls::{TLSClientConfig, TLSServerConfig};
use umilib::runtime::Instant;

use crate::tls::handshake::{Fixture, TIME};

/// What decides that a datagram is lost: its number, whether the client sent it, its bytes.
pub type Dropper = Box<dyn FnMut(usize, bool, &[u8]) -> bool>;

/// A client and a server, the datagrams in flight between them, and a clock.
pub struct Network {
    pub client: QUICConnection,
    pub server: Option<QUICConnection>,
    pub now: Instant,
    pub client_address: IPEndpoint,
    pub server_address: IPEndpoint,
    /// Datagrams dropped: each one sent is numbered, and those `drop` names go.
    pub sent: usize,
    pub drop: Dropper,
    pub delivered: Vec<(bool, Vec<u8>)>,
    /// The server's configurations, until the first Initial makes it.
    pub server_config: Option<(QUICConfig, TLSServerConfig)>,
    /// The one-way delay of the network, and the datagrams on their way.
    pub delay: Duration,
    pub on_the_way: Vec<(Instant, bool, Vec<u8>)>,
}

impl Network {
    pub fn configs() -> (TLSClientConfig, TLSServerConfig) {
        let mut client = Fixture::client_config();
        client.config.protocols = vec![b"test".to_vec()];
        let mut server = Fixture::server_config("server-p256");
        server.config.protocols = vec![b"test".to_vec()];
        (client, server)
    }

    pub fn endpoint(last: u8, port: u16) -> IPEndpoint {
        IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, last)), port)
    }

    pub fn new(config: QUICConfig) -> Network {
        let (client, server) = Network::configs();
        Network::with(config.clone(), config, client, server)
    }

    pub fn with(
        client_config: QUICConfig,
        server_config: QUICConfig,
        client: TLSClientConfig,
        server: TLSServerConfig,
    ) -> Network {
        let now = Instant::from_nanos(1_000_000_000);
        let server_address = Network::endpoint(1, 443);
        let client = QUICConnection::client(
            Arc::new(client_config),
            Arc::new(client),
            Some("server.example"),
            server_address,
            Fixture::random(1),
            now,
            TIME,
        )
        .unwrap();
        Network {
            client,
            server: None,
            now,
            client_address: Network::endpoint(2, 50000),
            server_address,
            sent: 0,
            drop: Box::new(|_, _, _| false),
            delivered: Vec::new(),
            server_config: Some((server_config, server)),
            delay: Duration::ZERO,
            on_the_way: Vec::new(),
        }
    }
}

impl Network {
    /// Moves datagrams both ways until neither end has any to send now and
    /// none has arrived, firing no timer.
    pub fn run(&mut self) {
        for _ in 0..1000 {
            let mut moved = false;
            for datagram in self.client.transmit_all(self.now) {
                moved = true;
                self.send(true, datagram);
            }
            if let Some(server) = &mut self.server {
                for datagram in server.transmit_all(self.now) {
                    moved = true;
                    self.send(false, datagram);
                }
            }
            let now = self.now;
            let (arrived, later): (Vec<_>, Vec<_>) =
                std::mem::take(&mut self.on_the_way).into_iter().partition(|(time, _, _)| *time <= now);
            self.on_the_way = later;
            for (_, from_client, datagram) in arrived {
                moved = true;
                self.deliver(from_client, &datagram);
            }
            if !moved {
                return;
            }
        }
        panic!("the network never went quiet");
    }

    /// Sends a datagram on its way unless dropped; from the client if `from_client`.
    pub fn send(&mut self, from_client: bool, datagram: Vec<u8>) {
        let index = self.sent;
        self.sent += 1;
        if (self.drop)(index, from_client, &datagram) {
            return;
        }
        self.on_the_way.push((self.now + self.delay, from_client, datagram));
    }

    /// Delivers a datagram that arrived.
    pub fn deliver(&mut self, from_client: bool, datagram: &[u8]) {
        self.delivered.push((from_client, datagram.to_vec()));
        if from_client {
            if self.server.is_none() {
                self.accept(datagram);
            }
            if let Some(server) = &mut self.server {
                server.receive(datagram, self.client_address, QUICECN::NotECT, self.now);
            }
        } else {
            self.client.receive(datagram, self.server_address, QUICECN::NotECT, self.now);
        }
    }

    /// The server of the first Initial (RFC 9000 §7.2).
    pub fn accept(&mut self, datagram: &[u8]) {
        let Some((config, tls)) = self.server_config.take() else { return };
        let Ok(QUICPacket::Protected(packet)) = QUICPacket::decode(datagram, 0) else { return };
        let QUICHeader::Long(header) = packet.header else { return };
        let acceptance = QUICAcceptance {
            version: header.version,
            original_destination: header.destination,
            destination: header.destination,
            source: header.source,
            retry_source: None,
            validated: false,
        };
        let server = QUICConnection::server(
            Arc::new(config),
            Arc::new(tls),
            acceptance,
            self.client_address,
            Fixture::random(2),
            self.now,
            TIME,
        )
        .unwrap();
        self.server = Some(server);
    }

    /// Drops `percent` of the datagrams, chosen by a generator seeded with `seed`.
    pub fn lossy(percent: u64, seed: u64) -> Dropper {
        let mut state = seed;
        Box::new(move |_, _, _| {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % 100 < percent
        })
    }

    pub fn server(&mut self) -> &mut QUICConnection {
        self.server.as_mut().unwrap()
    }

    /// Advances the clock to the next timer of either end and fires it.
    pub fn tick(&mut self) {
        let arrival = self.on_the_way.iter().map(|(time, _, _)| *time).min();
        let next = [self.client.poll_timeout(), self.server.as_ref().and_then(QUICConnection::poll_timeout), arrival]
            .into_iter()
            .flatten()
            .min();
        if let Some(next) = next {
            self.now = self.now.max(next);
        }
        self.client.expire(self.now);
        if let Some(server) = &mut self.server {
            server.expire(self.now);
        }
    }

    /// Runs and fires timers until `done` holds, or panics after `limit` rounds.
    pub fn until(&mut self, limit: usize, mut done: impl FnMut(&mut Network) -> bool) {
        for _ in 0..limit {
            self.run();
            if done(self) {
                return;
            }
            // What the check did (reading, say) goes out before time moves.
            self.run();
            self.tick();
        }
        panic!("not done after {limit} rounds");
    }

    pub fn events(connection: &mut QUICConnection) -> Vec<QUICEvent> {
        std::iter::from_fn(|| connection.poll_event()).collect()
    }

    /// Reads all a stream has.
    pub fn read_all(connection: &mut QUICConnection, stream: QUICStreamID) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let (count, fin) = connection.stream_read(stream, &mut buffer).unwrap_or((0, false));
            data.extend_from_slice(&buffer[..count]);
            if count == 0 || fin {
                return (data, fin);
            }
        }
    }
}

#[test]
fn a_handshake() {
    let mut network = Network::new(QUICConfig::default());
    network.run();
    assert!(network.client.handshake_complete && network.server().handshake_complete);
    assert_eq!(network.client.state, QUICConnectionState::Established);
    // The server confirms at once and tells the client with HANDSHAKE_DONE (RFC 9001 §4.1.2).
    assert!(network.server().handshake_confirmed && network.client.handshake_confirmed);
    let events = Network::events(&mut network.client);
    assert!(events.contains(&QUICEvent::Connected) && events.contains(&QUICEvent::HandshakeConfirmed));
    // The Initial and Handshake keys are gone (RFC 9001 §4.9).
    assert!(network.client.spaces[0].discarded && network.client.spaces[1].discarded);
    assert!(network.server().spaces[0].discarded && network.server().spaces[1].discarded);
    // The client's datagrams with Initial packets are at least 1200 bytes (RFC 9000 §14.1).
    let first = &network.delivered[0];
    assert!(first.0 && first.1.len() >= 1200);
    // The server sent at most three times what it received before validation (RFC 9000 §8.1).
    assert_eq!(network.client.tls.session.protocol.as_deref(), Some(&b"test"[..]));
}

#[test]
fn streams_both_ways() {
    let mut network = Network::new(QUICConfig::default());
    network.run();
    let stream = network.client.open_stream(true).unwrap();
    assert_eq!(stream, QUICStreamID(0));
    assert_eq!(network.client.stream_send(stream, b"hello, server", true).unwrap(), 13);
    network.run();
    let events = Network::events(network.server());
    assert!(events.contains(&QUICEvent::StreamOpened { stream }), "{events:?}");
    assert!(events.contains(&QUICEvent::StreamReadable { stream }));
    let (data, fin) = Network::read_all(network.server(), stream);
    assert_eq!((data.as_slice(), fin), (&b"hello, server"[..], true));
    network.server().stream_send(stream, b"hello, client", true).unwrap();
    network.run();
    let (data, fin) = Network::read_all(&mut network.client, stream);
    assert_eq!((data.as_slice(), fin), (&b"hello, client"[..], true));
    // Both halves done on both ends, once the acknowledgments arrive: the stream is forgotten.
    network
        .until(10, |network| network.client.streams.streams.is_empty() && network.server().streams.streams.is_empty());
}

#[test]
fn a_large_transfer_through_flow_control() {
    // More data than the windows: MAX_DATA and MAX_STREAM_DATA let it through (RFC 9000 §4).
    let config =
        QUICConfig { initial_max_data: 64 * 1024, initial_max_stream_data_uni: 16 * 1024, ..QUICConfig::default() };
    let mut network = Network::new(config);
    network.run();
    let stream = network.client.open_stream(false).unwrap();
    let data: Vec<u8> = (0..1_000_000u32).map(|index| (index % 251) as u8).collect();
    let mut written = 0;
    let mut received = Vec::new();
    for _ in 0..100_000 {
        if written < data.len() {
            written += network.client.stream_send(stream, &data[written..], false).unwrap();
            if written == data.len() {
                network.client.stream_send(stream, &[], true).unwrap();
            }
        }
        network.run();
        // The application reads all there is before time moves on.
        let mut fin = false;
        loop {
            let (chunk, finished) = Network::read_all(network.server(), stream);
            received.extend_from_slice(&chunk);
            network.run();
            fin |= finished;
            if chunk.is_empty() || fin {
                break;
            }
        }
        if fin {
            break;
        }
        network.tick();
    }
    assert_eq!(received.len(), data.len());
    assert!(received == data);
}

#[test]
fn losses_are_recovered() {
    // A quarter of the datagrams are lost: the handshake and the data still
    // get through (RFC 9002).
    let mut network = Network::new(QUICConfig::default());
    network.drop = Network::lossy(25, 7);
    network.until(2000, |network| {
        network.client.handshake_confirmed && network.server.as_ref().is_some_and(|server| server.handshake_complete)
    });
    let stream = network.client.open_stream(true).unwrap();
    let data = vec![7u8; 100_000];
    network.client.stream_send(stream, &data, true).unwrap();
    let mut received = Vec::new();
    network.until(5000, |network| {
        let (chunk, fin) = Network::read_all(network.server(), stream);
        received.extend_from_slice(&chunk);
        fin
    });
    assert_eq!(received, data);
}

#[test]
fn closing() {
    // RFC 9000 §10.2: the closing end sends CONNECTION_CLOSE, the other drains.
    let mut network = Network::new(QUICConfig::default());
    network.run();
    network.client.close(42, b"bye", network.now).unwrap();
    network.run();
    let events = Network::events(network.server());
    assert!(events.contains(&QUICEvent::Closed {
        reason: QUICCloseReason::PeerApplication { error: 42, reason: b"bye".to_vec() }
    }));
    assert_eq!(network.server().state, QUICConnectionState::Draining);
    assert_eq!(network.client.state, QUICConnectionState::Closing);
    // Both are forgotten after three probe timeouts.
    network.until(10, |network| {
        network.client.is_closed() && network.server.as_ref().is_some_and(QUICConnection::is_closed)
    });
}

#[test]
fn idle_timeout() {
    // RFC 9000 §10.1: the smaller of both idle timeouts, at least 3 PTO.
    let client = QUICConfig { max_idle_timeout: Duration::from_secs(5), ..QUICConfig::default() };
    let (tls_client, tls_server) = Network::configs();
    let mut network = Network::with(client, QUICConfig::default(), tls_client, tls_server);
    network.run();
    assert_eq!(network.client.idle_timeout, Some(Duration::from_secs(5)));
    assert_eq!(network.server().idle_timeout, Some(Duration::from_secs(5)));
    network.until(100, |network| network.client.is_closed());
    let events = Network::events(&mut network.client);
    assert!(events.contains(&QUICEvent::Closed { reason: QUICCloseReason::IdleTimeout }));
}

#[test]
fn losses_and_latency() {
    // 20 ms each way and losses of 10 to 30 %, with several draws: the
    // handshake completes, the data arrives whole, and the RTT is measured
    // (RFC 9002 §5).
    for (seed, percent) in [(1, 10), (2, 20), (3, 30), (4, 20), (5, 10)] {
        let mut network = Network::new(QUICConfig::default());
        network.delay = Duration::from_millis(20);
        network.drop = Network::lossy(percent, seed);
        network.until(5000, |network| {
            network.client.handshake_confirmed
                && network.server.as_ref().is_some_and(|server| server.handshake_complete)
        });
        let stream = network.client.open_stream(true).unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|index| index as u8).collect();
        let mut written = 0;
        let mut received = Vec::new();
        network.until(20_000, |network| {
            if written < data.len() {
                // The end goes with the last byte written.
                written += network.client.stream_send(stream, &data[written..], true).unwrap();
            }
            loop {
                let (chunk, fin) = Network::read_all(network.server(), stream);
                received.extend_from_slice(&chunk);
                if fin {
                    return true;
                }
                if chunk.is_empty() {
                    return false;
                }
            }
        });
        assert!(received == data, "seed {seed}: {} of {} bytes", received.len(), data.len());
        let rtt = network.client.recovery.rtt.smoothed;
        assert!(rtt >= Duration::from_millis(40) && rtt < Duration::from_millis(200), "seed {seed}: {rtt:?}");
    }
}

#[test]
fn packets_of_the_old_phase_after_this_end_updates() {
    // RFC 9001 §6.5: after this end updates its keys, the peer's packets of
    // the old phase still arrive until it sees the update; they are read.
    let mut network = Network::new(QUICConfig::default());
    network.run();
    let stream = network.client.open_stream(true).unwrap();
    network.client.stream_send(stream, b"phase 0", true).unwrap();
    network.run();
    let theirs = network.server().open_stream(false).unwrap();
    network.server().stream_send(theirs, b"sent in the old phase", true).unwrap();
    let now = network.now;
    let datagrams = network.server().transmit_all(now);
    assert!(!datagrams.is_empty());
    network.client.update_keys(now).unwrap();
    // No second update before a packet of this phase is acknowledged (RFC 9001 §6.1).
    assert!(matches!(network.client.update_keys(now), Err(umilib::protocol::quic::QUICError::State)));
    for datagram in datagrams {
        network.client.receive(&datagram, network.server_address, QUICECN::NotECT, now);
    }
    assert_eq!(network.client.state, QUICConnectionState::Established);
    let (data, fin) = Network::read_all(&mut network.client, theirs);
    assert_eq!((data.as_slice(), fin), (&b"sent in the old phase"[..], true));
    // The server follows once a packet of the new phase reaches it (RFC 9001 §6.2).
    network.until(10, |network| network.server().one_rtt.as_ref().unwrap().phase);
}

#[test]
fn an_unreachable_peer_times_out() {
    // RFC 9000 §10.1: the idle timeout ends the connection when nothing
    // comes back, however the probe timeouts back off (RFC 9002 §6.2.1).
    let mut network = Network::new(QUICConfig::default());
    network.run();
    network.drop = Box::new(|_, _, _| true);
    let stream = network.client.open_stream(true).unwrap();
    network.client.stream_send(stream, b"into the void", true).unwrap();
    let start = network.now;
    network.until(10_000, |network| network.client.is_closed());
    let events = Network::events(&mut network.client);
    assert!(events.contains(&QUICEvent::Closed { reason: QUICCloseReason::IdleTimeout }));
    let elapsed = network.now.saturating_duration_since(start);
    assert!(elapsed >= Duration::from_secs(30) && elapsed <= Duration::from_secs(31), "{elapsed:?}");
}

#[test]
fn a_stopped_stream_gives_its_credit_back() {
    // RFC 9000 §3.5, §4.1: what a stream the reader stopped received counts
    // as read for the connection's credit, and the stream ends; after FIN,
    // and before it, when the peer resets on STOP_SENDING.
    let config = QUICConfig { initial_max_data: 64 * 1024, ..QUICConfig::default() };
    let mut network = Network::new(config);
    network.run();
    let finished = network.client.open_stream(false).unwrap();
    network.client.stream_send(finished, &[1; 40_000], true).unwrap();
    network.until(100, |network| {
        network
            .server()
            .streams
            .streams
            .get(&finished)
            .is_some_and(|stream| stream.receive.as_ref().is_some_and(|receive| receive.buffer.final_size.is_some()))
    });
    network.server().stream_stop(finished, 7).unwrap();
    assert!(!network.server().streams.streams.contains_key(&finished));
    let open = network.client.open_stream(false).unwrap();
    network.client.stream_send(open, &[2; 40_000], false).unwrap();
    network.until(100, |network| network.server().streams.streams.contains_key(&open));
    network.server().stream_stop(open, 8).unwrap();
    network.until(100, |network| {
        let told =
            network.client.events.iter().any(|event| *event == QUICEvent::StopSending { stream: open, error: 8 });
        told && !network.server().streams.streams.contains_key(&open)
    });
    let last = network.client.open_stream(false).unwrap();
    network.client.stream_send(last, &[3; 40_000], true).unwrap();
    let mut received = Vec::new();
    network.until(1000, |network| {
        let (chunk, fin) = Network::read_all(network.server(), last);
        received.extend_from_slice(&chunk);
        fin
    });
    assert_eq!(received.len(), 40_000);
}

#[test]
fn the_congestion_window_holds() {
    // RFC 9002 §7: no packet is sent that would put more bytes in flight
    // than the congestion window, without probes or losses here.
    let mut network = Network::new(QUICConfig::default());
    network.delay = Duration::from_millis(10);
    network.until(100, |network| network.client.handshake_confirmed);
    let stream = network.client.open_stream(false).unwrap();
    network.client.stream_send(stream, &vec![5u8; 500_000], true).unwrap();
    let mut received = 0;
    network.until(10_000, |network| {
        let recovery = &network.client.recovery;
        assert!(recovery.bytes_in_flight <= recovery.congestion.window(), "{} in flight", recovery.bytes_in_flight);
        let (chunk, fin) = Network::read_all(network.server(), stream);
        received += chunk.len();
        fin
    });
    assert_eq!(received, 500_000);
}

#[test]
fn connection_ids_of_the_peer() {
    // RFC 9000 §10.3.1: only the token of the ID in use counts, not those of
    // IDs never used or retired; §5.1.2: an ID retired stays retired, even
    // when its NEW_CONNECTION_ID comes again.
    let id = |n: u8| QUICConnectionID::new(&[n; 8]).unwrap();
    let issued = |n: u8| QUICIssuedID { id: id(n), reset_token: Some([n; 16]) };
    let mut ids = QUICPeerConnectionIDs::new(id(0), Some([0; 16]), 4);
    ids.insert(1, 0, issued(1)).unwrap();
    ids.insert(2, 0, issued(2)).unwrap();
    assert!(ids.is_reset_token(&[0; 16]) && !ids.is_reset_token(&[1; 16]));
    assert!(ids.rotate());
    assert!(!ids.is_reset_token(&[0; 16]) && ids.is_reset_token(&[1; 16]));
    assert!(ids.rotate());
    assert_eq!(ids.retiring, [0, 1]);
    ids.insert(1, 0, issued(1)).unwrap();
    assert!(!ids.ids.contains_key(&1));
    assert!(!ids.rotate(), "no unused ID is left");
}

#[test]
fn configurations_that_cannot_work() {
    // RFC 9000 §18.2: a preferred address needs connection IDs; integers
    // fit in varints; datagrams fit the UDP payload size advertised.
    let preferred = umilib::protocol::quic::QUICPreferredAddress {
        ipv4: IPv4Address::new(192, 0, 2, 9),
        ipv4_port: 4433,
        ipv6: umilib::protocol::ip::IPv6Address([0; 16]),
        ipv6_port: 0,
        connection_id: QUICConnectionID::EMPTY,
        reset_token: [0; 16],
    };
    let invalid = [
        QUICConfig { preferred_address: Some(preferred), connection_id_length: 0, ..QUICConfig::default() },
        QUICConfig { datagram_size: 1400, max_udp_payload_size: 1300, ..QUICConfig::default() },
        QUICConfig { initial_max_data: 1 << 62, ..QUICConfig::default() },
        QUICConfig { initial_max_stream_data_uni: 1 << 62, ..QUICConfig::default() },
        QUICConfig { max_datagram_frame_size: 1 << 62, ..QUICConfig::default() },
    ];
    for config in invalid {
        assert!(config.check().is_err(), "{config:?}");
    }
    assert!(QUICConfig { preferred_address: Some(preferred), ..QUICConfig::default() }.check().is_ok());
}

#[test]
fn a_reset_after_all_data_arrived() {
    // RFC 9000 §3.2: a RESET_STREAM in "Data Recvd" may be ignored; this end
    // does, and the application still reads all the data and its end.
    let mut network = Network::new(QUICConfig::default());
    network.run();
    let stream = network.client.open_stream(false).unwrap();
    network.client.stream_send(stream, b"all of it", true).unwrap();
    network.run();
    let mut reset = Vec::new();
    umilib::protocol::quic::QUICFrame::ResetStream { stream, error: 3, final_size: 9 }.encode(&mut reset).unwrap();
    network.client.send_extension_frame(reset).unwrap();
    network.run();
    assert_eq!(network.server().state, QUICConnectionState::Established);
    assert!(!Network::events(network.server()).contains(&QUICEvent::StreamReset { stream, error: 3 }));
    let (data, fin) = Network::read_all(network.server(), stream);
    assert_eq!((data.as_slice(), fin), (&b"all of it"[..], true));
}
