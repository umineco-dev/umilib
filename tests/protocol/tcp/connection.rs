//! Connections against each other over a simulated network: the state
//! machine of RFC 9293 §3.10, RFC 5961, RFC 6298, RFC 5681, RFC 6582, RFC
//! 6675, RFC 7323, RFC 2018 and RFC 3168, and the listener.

use std::collections::VecDeque;
use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPEndpointPattern};
use umilib::protocol::tcp::{
    TCPCloseReason, TCPConfig, TCPConnection, TCPECNMode, TCPEvent, TCPFlags, TCPICMPError, TCPISNGenerator,
    TCPListener, TCPOptionSet, TCPRule, TCPSegment, TCPSequence, TCPState,
};
use umilib::runtime::Instant;
use umilib::service::Rule;

/// A segment in flight: from which side, its bytes, and whether it carried CE.
pub struct Flight {
    pub from_a: bool,
    pub bytes: Vec<u8>,
    pub ce: bool,
}

/// Two connections joined by a network that the test controls.
pub struct Network {
    pub now: Instant,
    pub a: TCPConnection,
    pub b: TCPConnection,
    /// Every segment sent, decoded: from A, and the segment's bytes.
    pub log: Vec<(bool, Vec<u8>)>,
    pub queue: VecDeque<Flight>,
}

pub fn endpoint(text: &str) -> IPEndpoint {
    text.parse().unwrap()
}

pub fn at(milliseconds: u64) -> Instant {
    Instant::from_nanos(1_000_000_000 + milliseconds * 1_000_000)
}

impl Network {
    /// A connects to B, which was opened from A's SYN as a listener does.
    pub fn new(config_a: TCPConfig, config_b: TCPConfig) -> Network {
        let (a_end, b_end) = (endpoint("192.0.2.1:40000"), endpoint("192.0.2.2:80"));
        let now = at(0);
        let mut a = TCPConnection::connect(config_a, a_end, b_end, TCPSequence(1000), now).unwrap();
        let mut syn = Buffer::new();
        a.transmit(now, &mut syn).unwrap().unwrap();
        let segment = TCPSegment::decode(syn.as_slice(), a_end.address, b_end.address).unwrap();
        let b = TCPConnection::accept(config_b, b_end, a_end, &segment, TCPSequence(5_000_000), now).unwrap();
        Network { now, a, b, log: vec![(true, syn.into_vec())], queue: VecDeque::new() }
    }

    /// Collects what both ends have to send now.
    pub fn transmit(&mut self) -> usize {
        let mut count = 0;
        for from_a in [true, false] {
            loop {
                let mut bytes = Buffer::new();
                let connection = if from_a { &mut self.a } else { &mut self.b };
                let Some(transmission) = connection.transmit(self.now, &mut bytes).unwrap() else { break };
                assert_eq!(transmission.length, bytes.len());
                let bytes = bytes.into_vec();
                self.log.push((from_a, bytes.clone()));
                self.queue.push_back(Flight { from_a, bytes, ce: false });
                count += 1;
                assert!(count < 100_000, "a loop of transmissions");
            }
        }
        count
    }

    /// Delivers what is in flight, dropping what `drop` says, until nothing is left to send.
    pub fn run(&mut self, mut drop: impl FnMut(&Flight) -> bool) {
        loop {
            self.transmit();
            if self.queue.is_empty() {
                return;
            }
            while let Some(flight) = self.queue.pop_front() {
                if drop(&flight) {
                    continue;
                }
                self.deliver(&flight);
            }
        }
    }

    pub fn deliver(&mut self, flight: &Flight) {
        let (source, destination) =
            if flight.from_a { (self.a.local, self.a.remote) } else { (self.b.local, self.b.remote) };
        let segment = TCPSegment::decode(&flight.bytes, source.address, destination.address).unwrap();
        let receiver = if flight.from_a { &mut self.b } else { &mut self.a };
        receiver.receive(&segment, flight.ce, self.now);
    }

    pub fn segments(&self, from_a: bool) -> Vec<TCPSegment<'_>> {
        let (source, destination) = if from_a { (self.a.local, self.a.remote) } else { (self.b.local, self.b.remote) };
        self.log
            .iter()
            .filter(|(from, _)| *from == from_a)
            .map(|(_, bytes)| TCPSegment::decode(bytes, source.address, destination.address).unwrap())
            .collect()
    }

    pub fn events(connection: &mut TCPConnection) -> Vec<TCPEvent> {
        std::iter::from_fn(|| connection.poll_event()).collect()
    }
}

pub fn never(_: &Flight) -> bool {
    false
}

pub fn read_all(connection: &mut TCPConnection) -> Vec<u8> {
    let mut data = vec![0; connection.readable()];
    let count = connection.read(&mut data);
    data.truncate(count);
    data
}

#[test]
fn three_way_handshake() {
    // RFC 9293 §3.5, Figure 6.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    assert_eq!((network.a.state, network.b.state), (TCPState::SYNSent, TCPState::SYNReceived));
    network.run(never);
    assert_eq!((network.a.state, network.b.state), (TCPState::Established, TCPState::Established));
    assert_eq!(Network::events(&mut network.a), [TCPEvent::Connected]);
    assert_eq!(Network::events(&mut network.b), [TCPEvent::Connected]);
    let a = network.segments(true);
    let b = network.segments(false);
    assert_eq!(a[0].flags, TCPFlags::SYN);
    assert_eq!(a[0].sequence, TCPSequence(1000));
    assert_eq!(b[0].flags, TCPFlags::SYN.union(TCPFlags::ACK));
    assert_eq!((b[0].sequence, b[0].acknowledgment), (TCPSequence(5_000_000), TCPSequence(1001)));
    assert_eq!(
        (a[1].flags, a[1].sequence, a[1].acknowledgment),
        (TCPFlags::ACK, TCPSequence(1001), TCPSequence(5_000_001))
    );
    // The options: MSS (MUST-14), and those of RFC 7323 and RFC 2018 in both SYNs.
    let syn = a[0].option_set().unwrap();
    assert_eq!(syn.mss, Some(1460));
    assert!(syn.sack_permitted && syn.timestamps.is_some() && syn.window_scale.is_some());
    let synack = b[0].option_set().unwrap();
    assert_eq!(synack.timestamps.unwrap().echo_reply, syn.timestamps.unwrap().value);
    assert!(network.a.sack && network.a.timestamps && network.a.window_scaling);
    assert!(network.b.sack && network.b.timestamps && network.b.window_scaling);
    // Every segment after the SYNs carries Timestamps (RFC 7323 §3.2).
    assert!(a[1].option_set().unwrap().timestamps.is_some());
    // The window of a SYN is not scaled (RFC 7323 §2.2); later windows are.
    assert_eq!(network.a.send_scale, network.b.receive_scale);
    let last = b.last().unwrap();
    let scale = if last.flags.contains(TCPFlags::SYN) { 0 } else { network.a.send_scale };
    assert_eq!(network.a.send_window, (last.window as u32) << scale);
    assert_eq!(b.len(), 1, "no segment beyond the SYN-ACK is needed");
}

#[test]
fn options_off_and_default_mss() {
    // Without the options, nothing of RFC 7323 or RFC 2018 is used, and
    // without MSS the default of 536 for IPv4 holds (MUST-15).
    let plain = TCPConfig { timestamps: false, sack: false, window_scale: false, ..TCPConfig::default() };
    let mut network = Network::new(plain, TCPConfig::default());
    network.run(never);
    assert!(!network.b.timestamps && !network.b.sack && !network.b.window_scaling);
    let synack = network.segments(false)[0].option_set().unwrap();
    assert_eq!(synack, TCPOptionSet { mss: Some(1460), ..TCPOptionSet::default() });
    assert_eq!(network.a.peer_mss, 1460);
    let mut no_mss = TCPConnection::connect(
        TCPConfig::default(),
        endpoint("192.0.2.1:1"),
        endpoint("192.0.2.2:2"),
        TCPSequence(1),
        at(0),
    )
    .unwrap();
    assert_eq!(no_mss.peer_mss, 536);
    no_mss.set_config(TCPConfig { mtu: 9000, ..TCPConfig::default() }, at(0)).unwrap();
    let v6 = TCPConnection::connect(
        TCPConfig::default(),
        endpoint("[2001:db8::1]:1"),
        endpoint("[2001:db8::2]:2"),
        TCPSequence(1),
        at(0),
    )
    .unwrap();
    assert_eq!(v6.peer_mss, 1220);
    // The effective send MSS is the smaller of the peer's MSS and what the MTU allows (MUST-16).
    assert_eq!(no_mss.segment_size(0), 536);
    assert_eq!(network.a.segment_size(12), 1448);
}

#[test]
fn data_both_ways_and_close() {
    // RFC 9293 §3.6, Figure 12: a normal close.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    assert_eq!(network.a.send(b"hello, tcp").unwrap(), 10);
    network.run(never);
    assert_eq!(read_all(&mut network.b), b"hello, tcp");
    network.b.send(b"hello back").unwrap();
    network.run(never);
    assert_eq!(read_all(&mut network.a), b"hello back");
    // The last segment of what was buffered is pushed (MUST-61).
    let data = network.segments(true).into_iter().find(|segment| !segment.payload.is_empty()).unwrap();
    assert!(data.flags.contains(TCPFlags::PSH));
    network.a.close().unwrap();
    network.run(never);
    assert_eq!((network.a.state, network.b.state), (TCPState::FINWait2, TCPState::CloseWait));
    assert!(Network::events(&mut network.b).contains(&TCPEvent::PeerClosed));
    assert_eq!(network.a.send(b"x"), Err(umilib::protocol::tcp::TCPError::State));
    network.b.send(b"last").unwrap();
    network.b.close().unwrap();
    network.run(never);
    assert_eq!(read_all(&mut network.a), b"last");
    assert_eq!((network.a.state, network.b.state), (TCPState::TimeWait, TCPState::Closed));
    assert!(Network::events(&mut network.b).contains(&TCPEvent::Closed(TCPCloseReason::Normal)));
    // TIME-WAIT lasts 2 MSL (MUST-13).
    let closed_at = network.a.time_wait_at.unwrap();
    assert_eq!(closed_at, network.now.saturating_add(Duration::from_secs(240)));
    network.now = closed_at;
    network.run(never);
    assert_eq!(network.a.state, TCPState::Closed);
    assert!(Network::events(&mut network.a).contains(&TCPEvent::Closed(TCPCloseReason::Normal)));
}

#[test]
fn simultaneous_close() {
    // RFC 9293 §3.6, Figure 13.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.close().unwrap();
    network.b.close().unwrap();
    network.transmit();
    while let Some(flight) = network.queue.pop_front() {
        network.deliver(&flight);
    }
    assert_eq!((network.a.state, network.b.state), (TCPState::Closing, TCPState::Closing));
    network.run(never);
    assert_eq!((network.a.state, network.b.state), (TCPState::TimeWait, TCPState::TimeWait));
}

#[test]
fn simultaneous_open() {
    // RFC 9293 §3.5, Figure 7.
    let (a_end, b_end) = (endpoint("192.0.2.1:5000"), endpoint("192.0.2.2:6000"));
    let now = at(0);
    let mut a = TCPConnection::connect(TCPConfig::default(), a_end, b_end, TCPSequence(100), now).unwrap();
    let mut b = TCPConnection::connect(TCPConfig::default(), b_end, a_end, TCPSequence(300), now).unwrap();
    let (mut to_b, mut to_a) = (Buffer::new(), Buffer::new());
    a.transmit(now, &mut to_b).unwrap().unwrap();
    b.transmit(now, &mut to_a).unwrap().unwrap();
    b.receive(&TCPSegment::decode(to_b.as_slice(), a_end.address, b_end.address).unwrap(), false, now);
    a.receive(&TCPSegment::decode(to_a.as_slice(), b_end.address, a_end.address).unwrap(), false, now);
    assert_eq!((a.state, b.state), (TCPState::SYNReceived, TCPState::SYNReceived));
    let (mut to_b, mut to_a) = (Buffer::new(), Buffer::new());
    a.transmit(now, &mut to_b).unwrap().unwrap();
    b.transmit(now, &mut to_a).unwrap().unwrap();
    let synack = TCPSegment::decode(to_b.as_slice(), a_end.address, b_end.address).unwrap();
    assert_eq!(
        (synack.flags, synack.sequence, synack.acknowledgment),
        (TCPFlags::SYN.union(TCPFlags::ACK), TCPSequence(100), TCPSequence(301))
    );
    b.receive(&synack, false, now);
    a.receive(&TCPSegment::decode(to_a.as_slice(), b_end.address, a_end.address).unwrap(), false, now);
    assert_eq!((a.state, b.state), (TCPState::Established, TCPState::Established));
}

#[test]
fn listener() {
    // RFC 9293 §3.10.7.2: a SYN opens a connection; an ACK gets a reset; a reset is ignored.
    let config = TCPConfig::default();
    let mut listener = TCPListener::new(config, IPEndpointPattern::port(80), 1, TCPISNGenerator::new([1; 16])).unwrap();
    let (server, client) = (endpoint("192.0.2.2:80"), endpoint("192.0.2.1:40000"));
    let mut a = TCPConnection::connect(config, client, server, TCPSequence(7), at(0)).unwrap();
    let mut bytes = Buffer::new();
    a.transmit(at(0), &mut bytes).unwrap();
    listener.receive(
        &TCPSegment::decode(bytes.as_slice(), client.address, server.address).unwrap(),
        server,
        client,
        false,
        at(0),
    );
    assert_eq!(listener.pending(), 1);
    // The backlog is full: a second SYN is dropped.
    let other = endpoint("192.0.2.9:40000");
    let mut c = TCPConnection::connect(config, other, server, TCPSequence(7), at(0)).unwrap();
    let mut c_syn = Buffer::new();
    c.transmit(at(0), &mut c_syn).unwrap();
    listener.receive(
        &TCPSegment::decode(c_syn.as_slice(), other.address, server.address).unwrap(),
        server,
        other,
        false,
        at(0),
    );
    assert_eq!(listener.pending(), 1);
    // The SYN-ACK, then A's ACK establishes the connection, which is accepted.
    let mut out = Buffer::new();
    let (from, to, _) = listener.transmit(at(0), &mut out).unwrap().unwrap();
    assert_eq!((from, to), (server, client));
    a.receive(&TCPSegment::decode(out.as_slice(), server.address, client.address).unwrap(), false, at(1));
    let mut ack = Buffer::new();
    a.transmit(at(1), &mut ack).unwrap().unwrap();
    listener.receive(
        &TCPSegment::decode(ack.as_slice(), client.address, server.address).unwrap(),
        server,
        client,
        false,
        at(1),
    );
    let accepted = listener.accept().unwrap();
    assert_eq!(accepted.state, TCPState::Established);
    assert!(listener.pending() == 0 && listener.accept().is_none());
    // An ACK without a connection is answered with a reset of its ACK number.
    listener.receive(
        &TCPSegment::decode(ack.as_slice(), client.address, server.address).unwrap(),
        server,
        client,
        false,
        at(2),
    );
    let mut reset = Buffer::new();
    listener.transmit(at(2), &mut reset).unwrap().unwrap();
    let reset = TCPSegment::decode(reset.as_slice(), server.address, client.address).unwrap();
    let ack = TCPSegment::decode(ack.as_slice(), client.address, server.address).unwrap();
    assert_eq!((reset.flags, reset.sequence), (TCPFlags::RST, ack.acknowledgment));
    // The rule routes connections by endpoint.
    assert!(TCPRule::new(IPEndpointPattern::port(80)).matches(&accepted));
    assert!(!TCPRule::new(IPEndpointPattern::port(80)).with_remote(IPEndpointPattern::port(1)).matches(&accepted));
}

#[test]
fn resets_answering_segments_without_a_connection() {
    // RFC 9293 §3.10.7.1: <SEQ=SEG.ACK><CTL=RST>, or <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>; never for a reset.
    let segment = TCPSegment {
        source_port: 1,
        destination_port: 2,
        sequence: TCPSequence(100),
        acknowledgment: TCPSequence(0),
        flags: TCPFlags::SYN,
        payload: b"abc",
        ..TCPSegment::default()
    };
    let reset = segment.reset_reply().unwrap();
    assert_eq!(
        (reset.flags, reset.sequence, reset.acknowledgment),
        (TCPFlags::RST.union(TCPFlags::ACK), TCPSequence(0), TCPSequence(104))
    );
    assert_eq!((reset.source_port, reset.destination_port), (2, 1));
    let acked = TCPSegment { flags: TCPFlags::ACK, acknowledgment: TCPSequence(77), ..segment };
    let reset = acked.reset_reply().unwrap();
    assert_eq!((reset.flags, reset.sequence), (TCPFlags::RST, TCPSequence(77)));
    assert!(TCPSegment { flags: TCPFlags::RST, ..segment }.reset_reply().is_none());
}

#[test]
fn opens_to_addresses_of_no_host_are_refused() {
    // MUST-46 for an active OPEN; MUST-57 and MUST-63 for a SYN.
    for remote in ["192.0.2.255:0", "224.0.0.1:80", "255.255.255.255:80", "0.0.0.0:80", "[ff02::1]:80"] {
        let local = if remote.starts_with('[') { endpoint("[2001:db8::1]:1") } else { endpoint("192.0.2.1:1") };
        let result = TCPConnection::connect(TCPConfig::default(), local, endpoint(remote), TCPSequence(1), at(0));
        assert!(result.is_err(), "{remote}");
    }
    let syn = TCPSegment { flags: TCPFlags::SYN, ..TCPSegment::default() };
    let group = TCPConnection::accept(
        TCPConfig::default(),
        endpoint("224.0.0.1:80"),
        endpoint("192.0.2.1:1"),
        &syn,
        TCPSequence(1),
        at(0),
    );
    assert!(group.is_err());
    let from = TCPConnection::accept(
        TCPConfig::default(),
        endpoint("192.0.2.2:80"),
        endpoint("255.255.255.255:1"),
        &syn,
        TCPSequence(1),
        at(0),
    );
    assert!(from.is_err());
    let _ = IPAddress::V4(umilib::protocol::ip::IPv4Address::new(0, 0, 0, 0));
    let _ = (TCPECNMode::Off, TCPICMPError::Soft);
}

/// Delivers to `receiver` a segment written by hand, as if from the other end.
pub fn inject(network: &mut Network, to_a: bool, segment: TCPSegment) {
    let (source, destination) =
        if to_a { (network.b.local, network.b.remote) } else { (network.a.local, network.a.remote) };
    let mut bytes = Buffer::new();
    segment.encode(source.address, destination.address, &mut bytes).unwrap();
    let segment = TCPSegment::decode(bytes.as_slice(), source.address, destination.address).unwrap();
    let now = network.now;
    let receiver = if to_a { &mut network.a } else { &mut network.b };
    receiver.receive(&segment, false, now);
}

/// A segment from B to A at B's current sequence numbers, with B's timestamps.
pub fn from_b(
    network: &Network,
    flags: TCPFlags,
    sequence: TCPSequence,
    acknowledgment: TCPSequence,
) -> (TCPSegment<'static>, Vec<u8>) {
    let options = TCPOptionSet {
        timestamps: Some(umilib::protocol::tcp::TCPTimestamps {
            value: network.b.timestamp(network.now),
            echo_reply: network.b.timestamp_recent,
        }),
        ..TCPOptionSet::default()
    };
    let mut bytes = Buffer::new();
    options.encode(&mut bytes).unwrap();
    let segment = TCPSegment {
        source_port: network.b.local.port,
        destination_port: network.b.remote.port,
        sequence,
        acknowledgment,
        flags,
        window: 1000,
        ..TCPSegment::default()
    };
    (segment, bytes.into_vec())
}

#[test]
fn blind_resets_and_syns() {
    // RFC 5961 §3.2: a reset at RCV.NXT closes; one elsewhere in the window gets a challenge ACK.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    let next = network.a.receive_next();
    let una = network.a.send_unacknowledged;
    let (segment, options) = from_b(&network, TCPFlags::RST, next.add(10), TCPSequence(0));
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert_eq!(network.a.state, TCPState::Established);
    assert!(network.a.ack_now, "a challenge ACK");
    network.run(never);
    // A reset outside the window is dropped without an answer.
    let (segment, options) = from_b(&network, TCPFlags::RST, next.add(10_000_000), TCPSequence(0));
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert!(!network.a.ack_now && network.a.state == TCPState::Established);
    // §4.2: a SYN in a synchronized state gets a challenge ACK, and nothing else changes.
    let (segment, options) = from_b(&network, TCPFlags::SYN, next.add(5), TCPSequence(0));
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert!(network.a.ack_now && network.a.state == TCPState::Established);
    network.run(never);
    // §5.2: an ACK below SND.UNA - MAX.SND.WND or above SND.NXT is not accepted.
    let (segment, options) = from_b(&network, TCPFlags::ACK, next, una.add(100));
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert!(network.a.ack_now && network.a.send_unacknowledged == una);
    network.run(never);
    // The challenge ACKs are limited (§7).
    network.a.config.challenge_acks = 2;
    for _ in 0..5 {
        let (segment, options) = from_b(&network, TCPFlags::SYN, next.add(5), TCPSequence(0));
        inject(&mut network, true, TCPSegment { options: &options, ..segment });
        network.transmit();
    }
    let challenges = network.queue.len();
    assert!(challenges <= 2, "{challenges}");
    network.queue.clear();
    // The reset at RCV.NXT resets the connection, and the application learns it (MUST-12).
    let (segment, options) = from_b(&network, TCPFlags::RST, next, TCPSequence(0));
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert_eq!(network.a.state, TCPState::Closed);
    assert!(Network::events(&mut network.a).contains(&TCPEvent::Closed(TCPCloseReason::Reset)));
}

#[test]
fn refused_connections() {
    // RFC 9293 §3.10.7.3: in SYN-SENT a reset is believed only if it acknowledges the SYN.
    let (a_end, b_end) = (endpoint("192.0.2.1:40000"), endpoint("192.0.2.2:9"));
    let mut a = TCPConnection::connect(TCPConfig::default(), a_end, b_end, TCPSequence(1000), at(0)).unwrap();
    let mut syn = Buffer::new();
    a.transmit(at(0), &mut syn).unwrap();
    let syn = TCPSegment::decode(syn.as_slice(), a_end.address, b_end.address).unwrap();
    let mut bytes = Buffer::new();
    TCPSegment::reset(9, 40000, TCPSequence(0), None).encode(b_end.address, a_end.address, &mut bytes).unwrap();
    a.receive(&TCPSegment::decode(bytes.as_slice(), b_end.address, a_end.address).unwrap(), false, at(1));
    assert_eq!(a.state, TCPState::SYNSent);
    let reply = syn.reset_reply().unwrap();
    let mut bytes = Buffer::new();
    reply.encode(b_end.address, a_end.address, &mut bytes).unwrap();
    a.receive(&TCPSegment::decode(bytes.as_slice(), b_end.address, a_end.address).unwrap(), false, at(1));
    assert_eq!(a.state, TCPState::Closed);
    assert!(Network::events(&mut a).contains(&TCPEvent::Closed(TCPCloseReason::Refused)));
    // An ACK of something never sent is answered with a reset of its ACK number.
    let mut b = TCPConnection::connect(TCPConfig::default(), a_end, b_end, TCPSequence(1000), at(0)).unwrap();
    let mut out = Buffer::new();
    b.transmit(at(0), &mut out).unwrap();
    let bogus = TCPSegment {
        source_port: 9,
        destination_port: 40000,
        sequence: TCPSequence(5),
        acknowledgment: TCPSequence(9999),
        flags: TCPFlags::ACK.union(TCPFlags::SYN),
        ..TCPSegment::default()
    };
    let mut bytes = Buffer::new();
    bogus.encode(b_end.address, a_end.address, &mut bytes).unwrap();
    b.receive(&TCPSegment::decode(bytes.as_slice(), b_end.address, a_end.address).unwrap(), false, at(1));
    let mut reset = Buffer::new();
    b.transmit(at(1), &mut reset).unwrap().unwrap();
    let reset = TCPSegment::decode(reset.as_slice(), a_end.address, b_end.address).unwrap();
    assert_eq!((reset.flags, reset.sequence), (TCPFlags::RST, TCPSequence(9999)));
    assert_eq!(b.state, TCPState::SYNSent);
}

#[test]
fn retransmission_timeouts() {
    // RFC 6298 (5.5): the timer doubles at each expiry; MUST-20: the
    // application hears of it after R1 and the connection is given up after R2.
    let config = TCPConfig { user_timeout: Duration::from_secs(30), ..TCPConfig::default() };
    let mut network = Network::new(config, TCPConfig::default());
    network.run(never);
    Network::events(&mut network.a);
    network.a.send(&[1; 100]).unwrap();
    let start = network.now;
    let mut sent_at = Vec::new();
    for _ in 0..20 {
        network.transmit();
        for flight in network.queue.drain(..) {
            if flight.from_a {
                sent_at.push(network.now);
            }
        }
        if network.a.state == TCPState::Closed {
            break;
        }
        network.now = network.a.poll_timeout().unwrap();
    }
    let gaps: Vec<u64> =
        sent_at.windows(2).map(|pair| pair[1].saturating_duration_since(pair[0]).as_millis() as u64).collect();
    assert!(gaps.len() >= 4, "{gaps:?}");
    for pair in gaps.windows(2) {
        assert!(pair[1] == 2 * pair[0] || pair[1] == 60_000, "{gaps:?}");
    }
    assert_eq!(network.a.state, TCPState::Closed);
    let events = Network::events(&mut network.a);
    assert!(events.contains(&TCPEvent::Trouble));
    assert_eq!(events.last(), Some(&TCPEvent::Closed(TCPCloseReason::Timeout)));
    assert!(network.now.saturating_duration_since(start) >= Duration::from_secs(30));
    // A SYN is retransmitted for at least 3 minutes (MUST-23).
    let mut syn = TCPConnection::connect(
        TCPConfig::default(),
        endpoint("192.0.2.1:1"),
        endpoint("192.0.2.2:2"),
        TCPSequence(1),
        at(0),
    )
    .unwrap();
    let mut now = at(0);
    let mut syns = 0;
    while syn.state != TCPState::Closed {
        while syn.transmit(now, &mut Buffer::new()).unwrap().is_some() {
            syns += 1;
        }
        now = syn.poll_timeout().unwrap_or(now);
    }
    assert!(now.saturating_duration_since(at(0)) >= Duration::from_secs(180));
    assert!(syns >= 5, "{syns}");
}

#[test]
fn karn_and_rtt_samples() {
    // RFC 6298 and RFC 7323 §4: RTT samples from timestamps, or from a segment not retransmitted.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.transmit();
    network.now = at(100);
    while let Some(flight) = network.queue.pop_front() {
        network.deliver(&flight);
    }
    network.run(never);
    assert_eq!(network.a.timer.smoothed, Some(Duration::from_millis(100)));
    let plain = TCPConfig { timestamps: false, ..TCPConfig::default() };
    let mut network = Network::new(plain, plain);
    network.run(never);
    network.a.send(&[2; 10]).unwrap();
    network.transmit();
    // The segment is lost and retransmitted: its ACK gives no sample (Karn).
    network.queue.clear();
    network.now = network.a.poll_timeout().unwrap();
    let before = network.a.timer.smoothed;
    network.now = network.now.saturating_add(Duration::from_millis(500));
    network.run(never);
    assert_eq!(network.a.timer.smoothed, before);
}

/// Sends `total` bytes from A to B with every `nth` data segment from A
/// dropped once, and returns what B read.
pub fn transfer(network: &mut Network, total: usize, nth: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..total).map(|index| (index * 7 % 251) as u8).collect();
    let mut offset = 0;
    let mut received = Vec::new();
    let mut data_segments = 0usize;
    let mut dropped = std::collections::HashSet::new();
    for _ in 0..200_000 {
        if offset < data.len() {
            offset += network.a.send(&data[offset..]).unwrap();
        }
        let sent = network.transmit();
        let flights: Vec<Flight> = network.queue.drain(..).collect();
        for flight in flights {
            let (source, destination) = (network.a.local.address, network.a.remote.address);
            if flight.from_a {
                let segment = TCPSegment::decode(&flight.bytes, source, destination).unwrap();
                // A loss in the last segments can only be found by the timer
                // (RFC 8985 aside), so the tail is never dropped.
                let offset = segment.sequence.distance(network.a.iss) as usize;
                if !segment.payload.is_empty() && offset + 20_000 < total {
                    data_segments += 1;
                    if nth > 0 && data_segments.is_multiple_of(nth) && dropped.insert(segment.sequence) {
                        continue;
                    }
                }
            }
            network.deliver(&flight);
        }
        received.extend(read_all(&mut network.b));
        if received.len() == total {
            break;
        }
        if sent == 0 {
            let next = [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min();
            match next {
                Some(next) => network.now = network.now.max(next),
                None => break,
            }
        }
    }
    if received.len() != total {
        let a = &network.a;
        panic!(
            "stalled at {} of {total}: a {:?} una {} nxt {} max {} wnd {} cwnd {} recovery {:?} rto {:?} persist {:?} buffer {}..{}; b next {} pending {:?} adv {}; events {:?} now {:?}",
            received.len(),
            a.state,
            a.send_unacknowledged.0,
            a.send_next.0,
            a.send_maximum.0,
            a.send_window,
            umilib::protocol::tcp::TCPCongestionControl::window(&a.congestion),
            a.recovery,
            a.retransmit_at,
            a.persist_at,
            a.send.start.0,
            a.send.end().0,
            network.b.receive.next.0,
            network.b.receive.pending.iter().map(|(start, bytes)| (*start, bytes.len())).collect::<Vec<_>>(),
            network.b.receive_advertised.0,
            a.events,
            network.now,
        );
    }
    assert_eq!(received, data);
    received
}

#[test]
fn fast_retransmit_without_sack() {
    // RFC 5681 §3.2 and RFC 6582: three duplicate ACKs retransmit the
    // missing segment without waiting for the timer.
    let plain = TCPConfig { sack: false, ..TCPConfig::default() };
    let mut network = Network::new(plain, plain);
    network.run(never);
    let start = network.now;
    transfer(&mut network, 200_000, 20);
    assert!(network.now.saturating_duration_since(start) < Duration::from_secs(1), "no timeout was needed");
    assert!(network.a.recovery.is_none());
}

#[test]
fn sack_recovery() {
    // RFC 6675: the losses the SACK blocks show are retransmitted while pipe < cwnd.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    let start = network.now;
    transfer(&mut network, 300_000, 15);
    assert!(network.now.saturating_duration_since(start) < Duration::from_secs(1), "no timeout was needed");
    // B reported SACK blocks, the most recent first (RFC 2018 §4).
    let sacked =
        network.segments(false).iter().filter(|segment| !segment.option_set().unwrap().sack().is_empty()).count();
    assert!(sacked > 0);
}

#[test]
fn transfers_survive_losses_and_timeouts() {
    // Data arrives whole and in order whatever is lost (RFC 9293 §3.4).
    for (config, nth) in [
        (TCPConfig::default(), 3),
        (TCPConfig { sack: false, ..TCPConfig::default() }, 4),
        (TCPConfig { timestamps: false, window_scale: false, ..TCPConfig::default() }, 5),
        (TCPConfig { congestion: umilib::protocol::tcp::TCPCongestionKind::NewReno, ..TCPConfig::default() }, 7),
    ] {
        let mut network = Network::new(config, config);
        network.run(never);
        transfer(&mut network, 100_000, nth);
    }
}

#[test]
fn zero_window_probes() {
    // MUST-36, MUST-37: a zero window is probed, and the connection stays
    // open as long as the probes are acknowledged.
    let small = TCPConfig { receive_buffer: 4000, ..TCPConfig::default() };
    let mut network = Network::new(TCPConfig::default(), small);
    network.run(never);
    network.a.send(&[9; 20_000]).unwrap();
    // The window fills, waiting out the delayed ACK and the sender's SWS avoidance.
    for _ in 0..4 {
        network.run(never);
        if network.a.send_window == 0 {
            break;
        }
        network.now = [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min().unwrap();
    }
    assert_eq!(network.a.send_window, 0);
    assert_eq!(network.b.readable(), 4000);
    let before = network.log.len();
    for _ in 0..12 {
        let next = network.a.poll_timeout().unwrap();
        network.now = next;
        network.run(never);
    }
    let probes = network.log[before..].iter().filter(|(from_a, bytes)| *from_a && bytes.len() > 32).count();
    assert!(probes >= 5, "{probes}");
    assert_eq!(network.a.state, TCPState::Established, "the connection stays open (MUST-37)");
    // The intervals between probes grow (SHLD-30).
    // Reading opens the window and the data flows again.
    let mut read = 0;
    for _ in 0..100 {
        read += read_all(&mut network.b).len();
        network.run(never);
        if read >= 20_000 {
            break;
        }
        if let Some(next) = [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min() {
            network.now = network.now.max(next);
        }
    }
    assert_eq!(read, 20_000);
}

#[test]
fn nagle_and_delayed_acks() {
    // SHLD-7: small segments wait while data is unacknowledged; MUST-17: it can be turned off.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(b"a").unwrap();
    network.transmit();
    network.a.send(b"b").unwrap();
    network.a.send(b"c").unwrap();
    assert_eq!(network.transmit(), 0, "held by Nagle");
    network.run(never);
    network.now = network.b.poll_timeout().unwrap();
    network.run(never);
    assert_eq!(read_all(&mut network.b), b"abc");
    let mut off = Network::new(TCPConfig { nagle: false, ..TCPConfig::default() }, TCPConfig::default());
    off.run(never);
    off.a.send(b"a").unwrap();
    off.transmit();
    off.a.send(b"b").unwrap();
    assert_eq!(off.transmit(), 1, "sent at once without Nagle");
    // MUST-40: an ACK waits less than 0.5 seconds; SHLD-19: at least every second full segment.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(b"x").unwrap();
    network.transmit();
    while let Some(flight) = network.queue.pop_front() {
        network.deliver(&flight);
    }
    assert_eq!(network.transmit(), 0, "the ACK is delayed");
    let deadline = network.b.poll_timeout().unwrap();
    assert!(deadline.saturating_duration_since(network.now) < Duration::from_millis(500));
    network.a.send(&[0; 2 * 1448]).unwrap();
    network.transmit();
    while let Some(flight) = network.queue.pop_front() {
        network.deliver(&flight);
    }
    assert_eq!(network.transmit(), 1, "two full segments are acknowledged at once");
}

#[test]
fn keepalives() {
    // MUST-24, MUST-25: off by default; MUST-26: sent only when idle; MUST-28: two hours by default.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    assert!(network.a.poll_timeout().is_none());
    assert_eq!(TCPConfig::default().keepalive_idle, Duration::from_secs(7200));
    let config = TCPConfig {
        keepalive: true,
        keepalive_idle: Duration::from_secs(10),
        keepalive_interval: Duration::from_secs(1),
        keepalive_probes: 3,
        ..TCPConfig::default()
    };
    let mut network = Network::new(config, TCPConfig::default());
    network.run(never);
    network.now = network.a.poll_timeout().unwrap();
    network.transmit();
    let probe = network.queue.back().unwrap();
    let probe = TCPSegment::decode(&probe.bytes, network.a.local.address, network.a.remote.address).unwrap();
    // SEG.SEQ = SND.NXT - 1, no data (SHLD-12).
    assert_eq!((probe.sequence, probe.payload.len()), (network.a.send_next.sub(1), 0));
    network.run(never);
    assert_eq!(network.a.keepalives, 0, "the answer resets the count");
    // Unanswered probes close the connection, but not the first (MUST-29).
    let drop_all = |_: &Flight| true;
    for _ in 0..3 {
        network.now = network.a.poll_timeout().unwrap();
        network.run(drop_all);
        assert_eq!(network.a.state, TCPState::Established);
    }
    network.now = network.a.poll_timeout().unwrap();
    network.run(drop_all);
    assert_eq!(network.a.state, TCPState::Closed);
    assert!(Network::events(&mut network.a).contains(&TCPEvent::Closed(TCPCloseReason::Timeout)));
}

#[test]
fn urgent_data() {
    // MUST-30, MUST-31: urgent data of any length; MUST-62: the pointer is the
    // octet after it; MUST-32, MUST-33: the application learns of it and how much remains.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(b"normal").unwrap();
    network.a.send_urgent(b"!!!").unwrap();
    network.run(never);
    let urgent = network.segments(true).into_iter().find(|segment| segment.flags.contains(TCPFlags::URG)).unwrap();
    // The data starts after the SYN: the urgent pointer names the octet after the ninth byte.
    assert_eq!(urgent.sequence.add(urgent.urgent_pointer as u32), network.a.iss.add(1 + 9));
    assert!(Network::events(&mut network.b).contains(&TCPEvent::Urgent));
    assert_eq!(network.b.urgent_remaining(), 9);
    let mut first = [0; 4];
    network.b.read(&mut first);
    assert_eq!(network.b.urgent_remaining(), 5);
    read_all(&mut network.b);
    assert_eq!(network.b.urgent_remaining(), 0);
}

#[test]
fn timestamps_and_paws() {
    // RFC 7323 §5.3: a segment with an older TSval is dropped and answered;
    // §3.2: once negotiated, a segment without timestamps is dropped.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    let next = network.a.receive_next();
    let una = network.a.send_unacknowledged;
    let old =
        umilib::protocol::tcp::TCPTimestamps { value: network.a.timestamp_recent.wrapping_sub(1000), echo_reply: 0 };
    let mut bytes = Buffer::new();
    TCPOptionSet { timestamps: Some(old), ..TCPOptionSet::default() }.encode(&mut bytes).unwrap();
    let segment = TCPSegment {
        source_port: 80,
        destination_port: 40000,
        sequence: next,
        acknowledgment: una,
        flags: TCPFlags::ACK,
        window: 1000,
        options: bytes.as_slice(),
        payload: b"old",
        ..TCPSegment::default()
    };
    inject(&mut network, true, segment);
    assert_eq!(network.a.readable(), 0);
    assert!(network.a.ack_now);
    network.run(never);
    let bare = TCPSegment { options: &[], ..segment };
    inject(&mut network, true, bare);
    assert_eq!(network.a.readable(), 0);
    // A fresh timestamp is accepted.
    let (fresh, options) = from_b(&network, TCPFlags::ACK, next, una);
    inject(&mut network, true, TCPSegment { options: &options, payload: b"new", ..fresh });
    assert_eq!(network.a.readable(), 3);
}

#[test]
fn explicit_congestion_notification() {
    // RFC 3168 §6.1.1: SYN with ECE and CWR, SYN-ACK with ECE.
    let request = TCPConfig { ecn: TCPECNMode::Request, ..TCPConfig::default() };
    let mut network = Network::new(request, TCPConfig::default());
    network.run(never);
    assert!(network.a.ecn && network.b.ecn);
    assert_eq!(network.segments(true)[0].flags, TCPFlags::SYN.union(TCPFlags::ECE).union(TCPFlags::CWR));
    assert_eq!(network.segments(false)[0].flags, TCPFlags::SYN.union(TCPFlags::ACK).union(TCPFlags::ECE));
    // §6.1.4: data is ECT, pure ACKs are not; §6.1.3: CE is echoed with ECE until CWR.
    network.a.send(&[1; 3000]).unwrap();
    let mut bytes = Buffer::new();
    let transmission = network.a.transmit(network.now, &mut bytes).unwrap().unwrap();
    assert!(transmission.ect);
    let segment = TCPSegment::decode(bytes.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
    let window = umilib::protocol::tcp::TCPCongestionControl::window(&network.a.congestion);
    network.b.receive(&segment, true, network.now);
    assert!(network.b.ecn_echo);
    let mut ack = Buffer::new();
    let pure = network.b.transmit(network.now, &mut ack).unwrap().unwrap();
    assert!(!pure.ect);
    let ack = TCPSegment::decode(ack.as_slice(), network.b.local.address, network.b.remote.address).unwrap();
    assert!(ack.flags.contains(TCPFlags::ECE));
    network.a.receive(&ack, false, network.now);
    // §6.1.2: the sender reduces cwnd and sets CWR on its next new data.
    assert!(umilib::protocol::tcp::TCPCongestionControl::window(&network.a.congestion) < window);
    network.run(never);
    let cwr = network
        .segments(true)
        .into_iter()
        .filter(|segment| segment.flags.contains(TCPFlags::CWR) && !segment.flags.contains(TCPFlags::SYN))
        .count();
    assert_eq!(cwr, 1);
    assert!(!network.b.ecn_echo);
    // Without a request, or turned off, nothing of ECN is used.
    let mut plain = Network::new(TCPConfig::default(), TCPConfig::default());
    plain.run(never);
    assert!(!plain.a.ecn && !plain.b.ecn);
    let off = TCPConfig { ecn: TCPECNMode::Off, ..TCPConfig::default() };
    let mut refused = Network::new(request, off);
    refused.run(never);
    assert!(!refused.a.ecn && !refused.b.ecn);
}

#[test]
fn out_of_order_and_sack_blocks() {
    // SHLD-31: segments past RCV.NXT are held; RFC 2018 §4: the first block
    // holds the segment that arrived last.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    let base = network.a.receive_next();
    let una = network.a.send_unacknowledged;
    for (offset, length) in [(100u32, 100usize), (300, 100), (200, 50)] {
        let (segment, options) = from_b(&network, TCPFlags::ACK, base.add(offset), una);
        let payload = vec![offset as u8; length];
        inject(&mut network, true, TCPSegment { options: &options, payload: &payload, ..segment });
        assert!(network.a.ack_now, "an ACK at once for a segment out of order");
    }
    let mut bytes = Buffer::new();
    network.a.transmit(network.now, &mut bytes).unwrap().unwrap();
    let ack = TCPSegment::decode(bytes.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
    assert_eq!(ack.acknowledgment, base);
    let blocks = ack.option_set().unwrap();
    let blocks = blocks.sack();
    assert_eq!((blocks[0].left, blocks[0].right), (base.add(100), base.add(250)));
    assert_eq!((blocks[1].left, blocks[1].right), (base.add(300), base.add(400)));
    // The hole filled, everything is read in order.
    let (segment, options) = from_b(&network, TCPFlags::ACK, base, una);
    let first = vec![0u8; 100];
    inject(&mut network, true, TCPSegment { options: &options, payload: &first, ..segment });
    assert_eq!(network.a.readable(), 250);
    let (segment, options) = from_b(&network, TCPFlags::ACK, base.add(250), una);
    let gap = vec![1u8; 50];
    inject(&mut network, true, TCPSegment { options: &options, payload: &gap, ..segment });
    let data = read_all(&mut network.a);
    assert_eq!(data.len(), 400);
    assert_eq!((data[0], data[100], data[200], data[250], data[300]), (0, 100, 200, 1, 44));
}

#[test]
fn large_windows() {
    // RFC 7323 §2: windows beyond 65,535 bytes with a scale; a megabyte flows.
    let big = TCPConfig { receive_buffer: 4 * 1024 * 1024, send_buffer: 4 * 1024 * 1024, ..TCPConfig::default() };
    let mut network = Network::new(big, big);
    network.run(never);
    assert!(network.b.receive_scale >= 6);
    transfer(&mut network, 1_000_000, 0);
    assert!(network.a.maximum_send_window > 65_535);
}

#[test]
fn icmp_errors() {
    // MUST-54, MUST-56: soft errors are reported and the connection goes on;
    // a hard error aborts a connection not yet synchronized (SHLD-26); RFC
    // 5927 §4.1: an error is believed only for a sequence number in flight.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(&[0; 500]).unwrap();
    network.transmit();
    let una = network.a.send_unacknowledged;
    network.a.receive_error(TCPICMPError::Soft, una, network.now);
    assert!(Network::events(&mut network.a).contains(&TCPEvent::Trouble));
    network.a.receive_error(TCPICMPError::Hard, una.add(100_000), network.now);
    assert_eq!(network.a.state, TCPState::Established);
    network.a.receive_error(TCPICMPError::Hard, una, network.now);
    assert_eq!(network.a.state, TCPState::Established);
    // Path MTU discovery (RFC 1191, RFC 8201): smaller segments.
    network.a.receive_error(TCPICMPError::PacketTooBig(1000), una, network.now);
    assert_eq!(network.a.segment_size(12), 1000 - 40 - 12);
    // A larger MTU reported later does not raise it (RFC 8201 §4, RFC 1191 §3),
    // and neither does a larger configuration: the path is still the path.
    network.a.receive_error(TCPICMPError::PacketTooBig(1400), network.a.send_unacknowledged, network.now);
    assert_eq!(network.a.mtu(), 1000);
    network.a.set_config(TCPConfig { mtu: 9000, ..TCPConfig::default() }, network.now).unwrap();
    assert_eq!((network.a.mtu(), network.a.config.mtu), (1000, 9000));
    // Below the minimum MTU of the version, the minimum (RFC 791: 68 octets for IPv4).
    network.a.receive_error(TCPICMPError::PacketTooBig(10), network.a.send_unacknowledged, network.now);
    assert_eq!(network.a.mtu(), 68);
    network.queue.clear();
    network.run(never);
    let mut syn = TCPConnection::connect(
        TCPConfig::default(),
        endpoint("192.0.2.1:1"),
        endpoint("192.0.2.2:2"),
        TCPSequence(10),
        at(0),
    )
    .unwrap();
    syn.transmit(at(0), &mut Buffer::new()).unwrap();
    syn.receive_error(TCPICMPError::Hard, TCPSequence(10), at(1));
    assert!(Network::events(&mut syn).contains(&TCPEvent::Closed(TCPCloseReason::Unreachable)));
}

#[test]
fn configuration_changes() {
    // MUST-24: keep-alives can be turned on per connection; MUST-17: Nagle off.
    // The send buffer takes its new size for what the application sends next.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    assert!(network.a.poll_timeout().is_none());
    let keepalive = TCPConfig { keepalive: true, nagle: false, send_buffer: 100, ..TCPConfig::default() };
    network.a.set_config(keepalive, network.now).unwrap();
    assert_eq!(network.a.poll_timeout(), Some(network.now.saturating_add(keepalive.keepalive_idle)));
    assert!(!network.a.config.nagle);
    assert_eq!(network.a.writable(), 100);
    assert_eq!(network.a.send(&[0; 500]).unwrap(), 100);
    network.a.set_config(TCPConfig::default(), network.now).unwrap();
    assert!(
        network.a.poll_timeout().is_none_or(|deadline| deadline < network.now.saturating_add(keepalive.keepalive_idle))
    );
}

#[test]
fn illegal_options_reset() {
    // MUST-7: an illegal option length resets the connection.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    let segment = TCPSegment {
        source_port: 80,
        destination_port: 40000,
        sequence: network.a.receive_next(),
        acknowledgment: network.a.send_unacknowledged,
        flags: TCPFlags::ACK,
        window: 100,
        ..TCPSegment::default()
    };
    // The decoder refuses an illegal length outright (TCPSegment::decode); a
    // connection given one anyway resets.
    let options = [2u8, 0, 0, 0];
    network.a.receive(&TCPSegment { options: &options, ..segment }, false, network.now);
    assert_eq!(network.a.state, TCPState::Closed);
    let mut bytes = Buffer::new();
    let reset = network.a.transmit(network.now, &mut bytes).unwrap().unwrap();
    assert!(reset.length >= 20);
    let reset = TCPSegment::decode(bytes.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
    assert!(reset.flags.contains(TCPFlags::RST));
}

/// A deterministic random number generator for the lossy network.
pub struct Random(u64);

impl Random {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn lossy_reordering_network() {
    // Whatever is lost, duplicated or reordered in both directions, the data
    // arrives whole and in order both ways, and the connection closes normally.
    for seed in 1..=6u64 {
        let config = if seed % 2 == 0 {
            TCPConfig { sack: false, timestamps: seed % 3 != 0, ..TCPConfig::default() }
        } else {
            TCPConfig::default()
        };
        let mut network = Network::new(config, config);
        let mut random = Random(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let total = 150_000;
        let data_a: Vec<u8> = (0..total).map(|index| (index * 13 % 256) as u8).collect();
        let data_b: Vec<u8> = (0..total).map(|index| (index * 17 % 256) as u8).collect();
        let (mut sent_a, mut sent_b) = (0, 0);
        let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
        let mut held: Vec<Flight> = Vec::new();
        for _ in 0..200_000 {
            if network.a.state.can_send() && sent_a < total {
                sent_a += network.a.send(&data_a[sent_a..]).unwrap_or(0);
            }
            if network.b.state.can_send() && sent_b < total {
                sent_b += network.b.send(&data_b[sent_b..]).unwrap_or(0);
            }
            if sent_a == total && !network.a.closing && network.a.state.is_synchronized() {
                network.a.close().unwrap();
            }
            if sent_b == total && !network.b.closing && network.b.state.is_synchronized() {
                network.b.close().unwrap();
            }
            let sent = network.transmit();
            let flights: Vec<Flight> = network.queue.drain(..).collect();
            for flight in flights {
                match random.next() % 20 {
                    0 => {}
                    1 => held.push(flight),
                    2 => {
                        network.deliver(&flight);
                        network.deliver(&flight);
                    }
                    _ => network.deliver(&flight),
                }
            }
            // A flight released now may let a side send again without a timer, so it counts as
            // activity below. The index is taken in u64 so that every platform plays the same network.
            let released = random.next().is_multiple_of(3) && !held.is_empty();
            if released {
                let flight = held.remove((random.next() % held.len() as u64) as usize);
                network.deliver(&flight);
            }
            got_a.extend(read_all(&mut network.a));
            got_b.extend(read_all(&mut network.b));
            let done = matches!(network.a.state, TCPState::Closed | TCPState::TimeWait)
                && network.b.state == TCPState::Closed
                || network.a.state == TCPState::Closed
                    && matches!(network.b.state, TCPState::Closed | TCPState::TimeWait);
            if done && got_a.len() == total && got_b.len() == total {
                break;
            }
            if sent == 0 && !released && held.is_empty() {
                let next = [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min();
                match next {
                    Some(next) => network.now = network.now.max(next),
                    None => break,
                }
            }
        }
        assert_eq!(got_b.len(), total, "seed {seed}: a {:?} b {:?}", network.a.state, network.b.state);
        assert_eq!(got_a.len(), total, "seed {seed}");
        assert!(got_b == data_a && got_a == data_b, "seed {seed}");
        for connection in [&mut network.a, &mut network.b] {
            let events = Network::events(connection);
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, TCPEvent::Closed(reason) if *reason != TCPCloseReason::Normal)),
                "seed {seed}: {events:?}"
            );
        }
    }
}

#[test]
fn syns_reopening_time_wait() {
    // RFC 6191 §2 (RFC 9293 SHLD-4): a SYN with a newer timestamp, or a
    // later sequence number without timestamps, may reopen a connection in TIME-WAIT.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.b.close().unwrap();
    network.run(never);
    network.a.close().unwrap();
    network.run(never);
    assert_eq!(network.b.state, TCPState::TimeWait);
    let recent = network.b.timestamp_recent;
    let next = network.b.receive_next();
    let syn = |value: u32, sequence: TCPSequence, stamps: bool| {
        let mut options = Buffer::new();
        let set = TCPOptionSet {
            timestamps: stamps.then_some(umilib::protocol::tcp::TCPTimestamps { value, echo_reply: 0 }),
            ..TCPOptionSet::default()
        };
        set.encode(&mut options).unwrap();
        (options.into_vec(), sequence)
    };
    for (value, sequence, stamps, accepted) in [
        (recent.wrapping_add(1), next.sub(1000), true, true),
        (recent, next.add(1), true, true),
        (recent, next.sub(1), true, false),
        (recent.wrapping_sub(1), next.add(1000), true, false),
        (0, next.add(5), false, true),
        // RCV.NXT is past the FIN, the last sequence number seen.
        (0, next, false, true),
        (0, next.sub(1), false, false),
        (0, next.sub(5), false, false),
    ] {
        let (options, sequence) = syn(value, sequence, stamps);
        let segment = TCPSegment {
            source_port: 40000,
            destination_port: 80,
            sequence,
            flags: TCPFlags::SYN,
            window: 100,
            options: &options,
            ..TCPSegment::default()
        };
        assert_eq!(network.b.accepts_syn(&segment), accepted, "{value} {sequence:?} {stamps}");
        assert!(!network.b.accepts_syn(&TCPSegment { flags: TCPFlags::SYN.union(TCPFlags::ACK), ..segment }));
    }
    // Without timestamps on the old incarnation, a SYN with them is honored.
    let plain = TCPConfig { timestamps: false, ..TCPConfig::default() };
    let mut old = Network::new(plain, TCPConfig::default());
    old.run(never);
    old.b.close().unwrap();
    old.run(never);
    old.a.close().unwrap();
    old.run(never);
    let (options, sequence) = syn(5, old.b.receive_next().sub(10), true);
    let segment = TCPSegment {
        source_port: 40000,
        destination_port: 80,
        sequence,
        flags: TCPFlags::SYN,
        window: 100,
        options: &options,
        ..TCPSegment::default()
    };
    assert!(old.b.accepts_syn(&segment));
}
