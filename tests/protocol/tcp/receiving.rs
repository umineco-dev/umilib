//! What a connection and a listener do with the segments they receive, case
//! by case (RFC 9293 §3.10.7), the bounds of the out-of-order queue and the
//! scoreboard, and the operations of the application (RFC 9293 §3.10.4,
//! §3.10.5).

use std::time::Duration;

use umilib::bytes::Buffer;
use umilib::protocol::ip::IPEndpointPattern;
use umilib::protocol::tcp::{
    TCPCloseReason, TCPConfig, TCPConnection, TCPError, TCPEvent, TCPFlags, TCPICMPError, TCPISNGenerator, TCPListener,
    TCPOptionSet, TCPReceiveBuffer, TCPSACKBlock, TCPScoreboard, TCPSegment, TCPSequence, TCPState, TCPTimestamps,
};

use super::connection::{Network, at, endpoint, from_b, inject, never, read_all};

#[test]
fn retransmitted_syn_ack_is_acknowledged() {
    // RFC 9293 §3.10.7.4, first: a SYN-ACK that comes again in ESTABLISHED
    // is not acceptable and is answered with an ACK, which completes the
    // peer's handshake when the first ACK was lost.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.transmit();
    let synack = network.queue.pop_front().unwrap();
    network.deliver(&synack);
    assert_eq!(network.a.state, TCPState::Established);
    network.transmit();
    network.queue.clear();
    network.now = network.b.poll_timeout().unwrap();
    assert_eq!(network.transmit(), 1, "B sends its SYN-ACK again");
    network.run(never);
    assert_eq!(network.b.state, TCPState::Established);
}

/// A client that sent its SYN to a listener on port 80, and the listener.
fn listening() -> (TCPListener, TCPConnection) {
    let config = TCPConfig::default();
    let mut listener = TCPListener::new(config, IPEndpointPattern::port(80), 4, TCPISNGenerator::new([2; 16])).unwrap();
    let (server, client) = (endpoint("192.0.2.2:80"), endpoint("192.0.2.1:40000"));
    let mut a = TCPConnection::connect(config, client, server, TCPSequence(7), at(0)).unwrap();
    let mut syn = Buffer::new();
    a.transmit(at(0), &mut syn).unwrap();
    let syn = TCPSegment::decode(syn.as_slice(), client.address, server.address).unwrap();
    listener.receive(&syn, server, client, false, at(0));
    (listener, a)
}

/// Gives the listener what `a` has to send at `now`.
fn to_listener(listener: &mut TCPListener, a: &mut TCPConnection, now: u64) {
    loop {
        let mut bytes = Buffer::new();
        if a.transmit(at(now), &mut bytes).unwrap().is_none() {
            return;
        }
        let segment = TCPSegment::decode(bytes.as_slice(), a.local.address, a.remote.address).unwrap();
        listener.receive(&segment, a.remote, a.local, false, at(now));
    }
}

/// Gives `a` what the listener has to send at `now`, and returns those segments' flags.
fn from_listener(listener: &mut TCPListener, a: &mut TCPConnection, now: u64) -> Vec<TCPFlags> {
    let mut flags = Vec::new();
    loop {
        let mut bytes = Buffer::new();
        let Some((local, remote, _)) = listener.transmit(at(now), &mut bytes).unwrap() else { return flags };
        let segment = TCPSegment::decode(bytes.as_slice(), local.address, remote.address).unwrap();
        flags.push(segment.flags);
        a.receive(&segment, false, at(now));
    }
}

#[test]
fn listeners_serve_connections_until_they_are_accepted() {
    // MUST-41 and RFC 9293 §3.10.7.4: the final ACK and data that follow it
    // before the application accepts belong to the connection; they are not
    // answered with a reset, and the connection's timers run.
    let (mut listener, mut a) = listening();
    from_listener(&mut listener, &mut a, 1);
    assert_eq!(a.state, TCPState::Established);
    a.send(b"before accept").unwrap();
    to_listener(&mut listener, &mut a, 2);
    assert_eq!((listener.pending(), listener.ready.len()), (0, 1));
    assert!(listener.resets.is_empty());
    // The delayed ACK of the data is sent from the listener at its time.
    let deadline = listener.poll_timeout().expect("the held connection's delayed ACK");
    let flags = from_listener(&mut listener, &mut a, (deadline.as_nanos() - at(0).as_nanos()) / 1_000_000);
    assert!(!flags.is_empty() && flags.iter().all(|flags| !flags.contains(TCPFlags::RST)), "{flags:?}");
    assert_eq!(a.state, TCPState::Established);
    assert_eq!(a.send_unacknowledged, a.send_next, "the data was acknowledged");
    let mut accepted = listener.accept().unwrap();
    assert_eq!(read_all(&mut accepted), b"before accept");
    assert!(listener.accept().is_none() && listener.connections.is_empty());
}

#[test]
fn passive_half_open_connections_return_to_listen() {
    // RFC 9293 §3.10.7.4, fourth: a SYN in the window of a passive
    // SYN-RECEIVED connection returns it to LISTEN, silently.
    let (mut listener, mut a) = listening();
    from_listener(&mut listener, &mut a, 1);
    let held = listener.connections.values().next().unwrap();
    let next = held.receive_next();
    let options = TCPOptionSet {
        timestamps: Some(TCPTimestamps { value: a.timestamp(at(1)), echo_reply: 0 }),
        ..TCPOptionSet::default()
    };
    let mut options_bytes = Buffer::new();
    options.encode(&mut options_bytes).unwrap();
    let syn = TCPSegment {
        source_port: a.local.port,
        destination_port: a.remote.port,
        sequence: next.add(10),
        flags: TCPFlags::SYN,
        window: 1000,
        options: options_bytes.as_slice(),
        ..TCPSegment::default()
    };
    listener.receive(&syn, a.remote, a.local, false, at(1));
    assert!(listener.connections.is_empty() && listener.resets.is_empty());
}

#[test]
fn zero_windows_still_take_acknowledgments() {
    // RFC 9293 §3.10.7.4: with RCV.WND = 0 no text is taken, but the ACK of
    // a segment at RCV.NXT is processed and answered.
    let small = TCPConfig { receive_buffer: 1000, ..TCPConfig::default() };
    let mut network = Network::new(small, TCPConfig::default());
    network.run(never);
    network.b.send(&[3; 1000]).unwrap();
    network.run(never);
    assert_eq!(network.a.receive_window(), 0);
    network.a.send(&[4; 100]).unwrap();
    network.transmit();
    network.queue.clear();
    let (segment, options) = from_b(&network, TCPFlags::ACK, network.a.receive_next(), network.a.send_next);
    inject(&mut network, true, TCPSegment { options: &options, payload: &[5], ..segment });
    assert_eq!(network.a.send_unacknowledged, network.a.send_next, "the ACK was taken");
    assert_eq!(network.a.readable(), 1000, "the byte was not");
    assert!(network.a.ack_now);
}

#[test]
fn fins_beyond_the_window_are_trimmed() {
    // RFC 9293 §3.10.7.4: a segment is trimmed to the window, FIN included;
    // the window never wraps past its right edge.
    let small = TCPConfig { receive_buffer: 1000, ..TCPConfig::default() };
    let mut network = Network::new(small, TCPConfig::default());
    network.run(never);
    let next = network.a.receive_next();
    let (segment, options) = from_b(&network, TCPFlags::ACK.union(TCPFlags::FIN), next, network.a.send_next);
    inject(&mut network, true, TCPSegment { options: &options, payload: &[6; 1000], ..segment });
    assert_eq!(network.a.readable(), 1000);
    assert!(!network.a.fin_received && network.a.state == TCPState::Established);
    assert_eq!(network.a.receive_window(), 0);
    assert!(!network.a.acceptable(network.a.receive_next().add(2_000_000_000), 0));
    assert!(network.a.ack_now, "the FIN is acknowledged as not taken");
    // Once the window opens, the FIN sent again is taken.
    read_all(&mut network.a);
    network.run(never);
    let (segment, options) =
        from_b(&network, TCPFlags::ACK.union(TCPFlags::FIN), network.a.receive_next(), network.a.send_next);
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert_eq!(network.a.state, TCPState::CloseWait);
}

#[test]
fn time_wait_restarts_only_for_the_fin_again() {
    // RFC 9293 §3.10.7.4: in TIME-WAIT a retransmission of the remote FIN
    // restarts the 2 MSL timeout; another FIN does not.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.close().unwrap();
    network.run(never);
    network.b.close().unwrap();
    network.run(never);
    assert_eq!(network.a.state, TCPState::TimeWait);
    let deadline = network.a.time_wait_at.unwrap();
    network.now = network.now.saturating_add(Duration::from_secs(1));
    let fin = TCPFlags::ACK.union(TCPFlags::FIN);
    let (segment, options) = from_b(&network, fin, network.a.receive_next().add(100_000), network.a.send_next);
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert_eq!(network.a.time_wait_at, Some(deadline));
    let (segment, options) = from_b(&network, fin, network.a.receive_next().sub(1), network.a.send_next);
    inject(&mut network, true, TCPSegment { options: &options, ..segment });
    assert_eq!(network.a.time_wait_at, Some(network.now.saturating_add(network.a.config.time_wait)));
    assert!(network.a.ack_now);
}

#[test]
fn the_fin_is_acknowledged_after_a_timeout() {
    // RFC 9293 §3.10.7.4, fifth: an ACK past the FIN acknowledges it, even
    // when it arrives after a timeout made the FIN due again.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.close().unwrap();
    network.transmit();
    let fin = network.queue.pop_front().unwrap();
    network.deliver(&fin);
    network.transmit();
    let ack = network.queue.pop_front().unwrap();
    network.now = network.a.poll_timeout().unwrap();
    network.a.expire(network.now);
    network.deliver(&ack);
    assert_eq!(network.a.state, TCPState::FINWait2);
    assert!(network.a.transmit(network.now, &mut Buffer::new()).unwrap().is_none());
}

#[test]
fn closed_connections_do_not_exist() {
    // RFC 9293 §3.10.4, §3.10.5: CLOSE and ABORT of a closed connection
    // fail ("connection does not exist"), and the application is told of
    // the close once.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    Network::events(&mut network.a);
    network.a.abort().unwrap();
    assert_eq!(network.a.close(), Err(TCPError::State));
    assert_eq!(network.a.abort(), Err(TCPError::State));
    assert_eq!(Network::events(&mut network.a), [TCPEvent::Closed(TCPCloseReason::Aborted)]);
    assert_eq!(network.a.close(), Err(TCPError::State));
    assert!(Network::events(&mut network.a).is_empty());
    // A second CLOSE after the first fails too.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.close().unwrap();
    assert_eq!(network.a.close(), Err(TCPError::State));
}

#[test]
fn old_acknowledgments_leave_the_window() {
    // RFC 9293 §3.10.7.4, fifth: the window is updated only by an ACK in
    // [SND.UNA, SND.NXT]; an older one in RFC 5961's range is ignored.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(&[1; 2000]).unwrap();
    network.b.send(&[2]).unwrap();
    network.run(never);
    let window = network.a.send_window;
    let next = network.a.receive_next();
    let old = network.a.send_unacknowledged.sub(100);
    let (segment, options) = from_b(&network, TCPFlags::ACK, next, old);
    inject(&mut network, true, TCPSegment { options: &options, payload: &[3], window: 0, ..segment });
    assert_eq!(network.a.send_window, window);
    assert_eq!(read_all(&mut network.a), [2, 3], "the text was taken");
}

#[test]
fn hard_errors_abort_when_configured() {
    // SHLD-26: hard ICMP errors abort a synchronized connection when the
    // configuration follows it; by default they are reported (RFC 5927 §4.2).
    for abort in [false, true] {
        let config = TCPConfig { hard_error_abort: abort, ..TCPConfig::default() };
        let mut network = Network::new(config, TCPConfig::default());
        network.run(never);
        Network::events(&mut network.a);
        network.a.send(&[0; 100]).unwrap();
        network.transmit();
        let una = network.a.send_unacknowledged;
        network.a.receive_error(TCPICMPError::Hard, una, network.now);
        let expected = if abort { TCPEvent::Closed(TCPCloseReason::Unreachable) } else { TCPEvent::Trouble };
        assert_eq!(Network::events(&mut network.a), [expected]);
    }
}

#[test]
fn unanswered_window_probes_give_up() {
    // RFC 9293 §3.8.6.1: the connection stays open while probes are
    // answered (MUST-37); probes unanswered for R2 give it up.
    let config = TCPConfig { user_timeout: Duration::from_secs(10), ..TCPConfig::default() };
    let small = TCPConfig { receive_buffer: 1000, ..TCPConfig::default() };
    let mut network = Network::new(config, small);
    network.run(never);
    network.a.send(&[1; 5000]).unwrap();
    for _ in 0..10 {
        network.run(never);
        if network.a.send_window == 0 {
            break;
        }
        network.now = [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min().unwrap();
    }
    assert_eq!(network.a.send_window, 0);
    let silent = network.now;
    for _ in 0..100 {
        let Some(deadline) = network.a.poll_timeout() else { break };
        network.now = deadline;
        network.transmit();
        network.queue.clear();
        if network.a.state == TCPState::Closed {
            break;
        }
    }
    assert!(Network::events(&mut network.a).contains(&TCPEvent::Closed(TCPCloseReason::Timeout)));
    assert!(network.now.saturating_duration_since(silent) >= Duration::from_secs(10));
}

#[test]
fn configurations_that_cannot_work_are_refused() {
    let base = TCPConfig::default();
    assert_eq!(base.check(), Ok(()));
    for broken in [
        TCPConfig { mtu: 67, ..base },
        TCPConfig { send_buffer: 0, ..base },
        TCPConfig { receive_buffer: 0, ..base },
        TCPConfig { keepalive_probes: 0, ..base },
        TCPConfig { minimum_rto: Duration::from_secs(2), maximum_rto: Duration::from_secs(1), ..base },
        TCPConfig { initial_rto: Duration::from_millis(10), ..base },
        TCPConfig { clock_granularity: Duration::ZERO, ..base },
        TCPConfig { initial_window: Some(0), ..base },
        TCPConfig { minimum_rto: Duration::ZERO, initial_rto: Duration::ZERO, ..base },
        TCPConfig { receive_buffer: TCPConfig::MAXIMUM_BUFFER + 1, ..base },
        TCPConfig { send_buffer: TCPConfig::MAXIMUM_BUFFER + 1, ..base },
    ] {
        assert_eq!(broken.check(), Err(TCPError::Config), "{broken:?}");
        let opened =
            TCPConnection::connect(broken, endpoint("192.0.2.1:1"), endpoint("192.0.2.2:2"), TCPSequence(1), at(0));
        assert_eq!(opened.err(), Some(TCPError::Config));
        assert!(TCPListener::new(broken, IPEndpointPattern::ANY, 1, TCPISNGenerator::new([0; 16])).is_err());
        let mut network = Network::new(base, base);
        network.run(never);
        assert_eq!(network.a.set_config(broken, network.now), Err(TCPError::Config));
        assert_eq!(network.a.config, base);
    }
    // A minimum RTO below RFC 6298's second, as Linux has, is the user's choice.
    assert_eq!(
        TCPConfig { minimum_rto: Duration::from_millis(200), initial_rto: Duration::from_millis(200), ..base }.check(),
        Ok(())
    );
}

#[test]
fn events_say_what_is_so_once() {
    let mut network = Network::new(TCPConfig::default(), TCPConfig { nagle: false, ..TCPConfig::default() });
    network.run(never);
    Network::events(&mut network.a);
    for _ in 0..50 {
        network.b.send(&[1; 10]).unwrap();
        network.run(never);
    }
    let events = Network::events(&mut network.a);
    assert_eq!(events, [TCPEvent::Readable]);
    assert_eq!(network.a.readable(), 500);
}

#[test]
fn out_of_order_blocks_are_bounded() {
    // RFC 9293 SHLD-31 keeps out-of-order data; how much and in how many
    // blocks is bounded by the buffer.
    let capacity = 64 * TCPReceiveBuffer::BLOCK_COST;
    let mut buffer = TCPReceiveBuffer::new(TCPSequence(u32::MAX - 100), capacity);
    let start = buffer.next;
    let limit = start.add(capacity as u32);
    for index in 0..1000u32 {
        buffer.insert(start.add(2 + 2 * index), &[index as u8], limit);
    }
    assert_eq!(buffer.pending.len(), buffer.block_limit());
    assert_eq!(buffer.pending_len(), buffer.pending.values().map(Vec::len).sum::<usize>());
    // Filling the hole pulls everything that follows in order, across the wrap of sequence numbers.
    let added = buffer.insert(start, &[0xAA; 2], limit);
    assert_eq!(added, 3);
    assert_eq!(buffer.next, start.add(3));
    // Overlapping data keeps the bytes held first.
    let mut buffer = TCPReceiveBuffer::new(TCPSequence(0), 4096);
    let limit = TCPSequence(4096);
    buffer.insert(TCPSequence(10), &[1; 10], limit);
    buffer.insert(TCPSequence(15), &[2; 10], limit);
    buffer.insert(TCPSequence(5), &[3; 8], limit);
    let (start, bytes) = buffer.pending.iter().next().unwrap();
    assert_eq!(*start, 5);
    assert_eq!(bytes.as_slice(), [[3u8; 5].as_slice(), &[1; 10], &[2; 5]].concat());
    // RFC 2018 §4: the block of the latest segment first, then the others by recency.
    let mut buffer = TCPReceiveBuffer::new(TCPSequence(0), 4096);
    for at in [100, 200, 300] {
        buffer.insert(TCPSequence(at), &[0; 10], limit);
    }
    let block = |left: u32, right: u32| TCPSACKBlock { left: TCPSequence(left), right: TCPSequence(right) };
    let (blocks, count) = buffer.sack_blocks(4);
    assert_eq!(&blocks[..count], [block(300, 310), block(200, 210), block(100, 110)]);
    buffer.insert(TCPSequence(110), &[0; 5], limit);
    let (blocks, count) = buffer.sack_blocks(3);
    assert_eq!(&blocks[..count], [block(100, 115), block(300, 310), block(200, 210)]);
}

#[test]
fn scoreboards_are_bounded() {
    let una = TCPSequence(1000);
    let max = una.add(10_000);
    let block = |left: u32, right: u32| TCPSACKBlock { left: una.add(left), right: una.add(right) };
    let mut scoreboard = TCPScoreboard::default();
    for index in 0..10 {
        scoreboard.update(&[block(10 * index + 1, 10 * index + 2)], una, max, 4);
    }
    assert_eq!(scoreboard.blocks.len(), 4);
    // A block that joins those held is still taken.
    scoreboard.update(&[block(2, 11)], una, max, 4);
    assert_eq!(scoreboard.blocks[0], block(1, 12));
    // RFC 6675 IsLost: DupThresh blocks above, or more than (DupThresh - 1) SMSS SACKed above.
    let mut scoreboard = TCPScoreboard::default();
    scoreboard.update(&[block(100, 200), block(300, 400)], una, max, 100);
    assert!(!scoreboard.is_lost(una, una, max, 1000));
    scoreboard.update(&[block(500, 600)], una, max, 100);
    assert!(scoreboard.is_lost(una, una, max, 1000));
    assert!(!scoreboard.is_lost(una.add(400), una, max, 1000), "two blocks above");
    let mut scoreboard = TCPScoreboard::default();
    scoreboard.update(&[block(100, 2101)], una, max, 100);
    assert!(scoreboard.is_lost(una, una, max, 1000), "2001 > 2 SMSS bytes above");
    assert!(!scoreboard.is_lost(una.add(5000), una, max, 1000), "nothing SACKed above the last hole");
    assert_eq!(scoreboard.highest_unsacked(una, max), Some((una.add(2101), max)));
    assert_eq!(scoreboard.next_unsacked(una, una, max), Some((una, 100)));
}

#[test]
fn packet_too_big_during_the_handshake() {
    // RFC 9293 §3.10.7.3, RFC 5927 §4.1: Packet Too Big about the SYN lowers
    // the MTU, and the SYN-ACK that follows still completes the handshake.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    let iss = network.a.iss;
    network.a.receive_error(TCPICMPError::PacketTooBig(1280), iss, network.now);
    assert_eq!(network.a.mtu(), 1280);
    network.run(never);
    assert_eq!((network.a.state, network.b.state), (TCPState::Established, TCPState::Established));
    assert_eq!(network.a.segment_size(0), 1280 - 40);
}

#[test]
fn idle_periods_count_from_data() {
    // RFC 5681 §4.1: cwnd restarts when no data was sent for an RTO; pure
    // ACKs sent meanwhile do not count.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.a.send(&[1; 60_000]).unwrap();
    for _ in 0..20 {
        network.run(never);
        match [network.a.poll_timeout(), network.b.poll_timeout()].into_iter().flatten().min() {
            Some(next) if network.a.unsent() > 0 || network.a.flight() > 0 => network.now = next,
            _ => break,
        }
    }
    let grown = umilib::protocol::tcp::TCPCongestionControl::window(&network.a.congestion);
    network.now = network.now.saturating_add(Duration::from_secs(10));
    network.b.send(&[2; 10]).unwrap();
    network.run(never);
    network.now = network.now.saturating_add(Duration::from_millis(100));
    network.a.send(&[3; 10]).unwrap();
    network.run(never);
    let restarted = umilib::protocol::tcp::TCPCongestionControl::window(&network.a.congestion);
    assert!(restarted < grown, "{restarted} < {grown}");
}

#[test]
fn configuration_changes_keep_what_the_connection_chose() {
    // What the handshake negotiated and the congestion control stay; the
    // RTO's bounds apply from then on.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    let changed = TCPConfig {
        window_scale: false,
        sack: false,
        timestamps: false,
        congestion: umilib::protocol::tcp::TCPCongestionKind::NewReno,
        minimum_rto: Duration::from_millis(200),
        initial_rto: Duration::from_millis(200),
        ..TCPConfig::default()
    };
    network.a.set_config(changed, network.now).unwrap();
    network.run(never);
    assert!(network.a.window_scaling && network.a.sack && network.a.timestamps);
    assert!(network.a.config.window_scale && network.a.config.sack && network.a.config.timestamps);
    assert_eq!(network.a.config.congestion, TCPConfig::default().congestion);
    assert_eq!(network.a.config.minimum_rto, Duration::from_millis(200));
    assert_eq!(network.a.timer.minimum, Duration::from_millis(200));
}

#[test]
fn urgent_pointers_are_forgotten_once_read() {
    // MUST-32, MUST-33: the urgent data remaining counts to the pointer, and a
    // pointer read past leaves nothing that could wrap.
    let mut network = Network::new(TCPConfig::default(), TCPConfig::default());
    network.run(never);
    network.b.send_urgent(b"urgent").unwrap();
    network.run(never);
    assert_eq!(network.a.urgent_remaining(), 6);
    read_all(&mut network.a);
    assert_eq!((network.a.urgent_remaining(), network.a.receive_urgent), (0, None));
}

#[test]
fn listeners_visit_each_connection_once_a_round() {
    // A listener writes what its connections have, each once per round, and
    // finds nothing only after a whole round.
    let config = TCPConfig::default();
    let mut listener =
        TCPListener::new(config, IPEndpointPattern::port(80), 64, TCPISNGenerator::new([3; 16])).unwrap();
    let server = endpoint("192.0.2.2:80");
    for port in 0..32u16 {
        let client = endpoint(&format!("192.0.2.1:{}", 40000 + port));
        let mut a = TCPConnection::connect(config, client, server, TCPSequence(7), at(0)).unwrap();
        let mut syn = Buffer::new();
        a.transmit(at(0), &mut syn).unwrap();
        let syn = TCPSegment::decode(syn.as_slice(), client.address, server.address).unwrap();
        listener.receive(&syn, server, client, false, at(0));
    }
    let mut remotes = std::collections::BTreeSet::new();
    while let Some((_, remote, _)) = listener.transmit(at(0), &mut Buffer::new()).unwrap() {
        assert!(remotes.insert(remote), "one SYN-ACK each");
    }
    assert_eq!(remotes.len(), 32);
}
