//! Loss recovery and congestion signals case by case: the SACK recovery of
//! RFC 6675, the `recover` point of RFC 6582 and RFC 6675 §5.1, and the
//! sender's rules of RFC 3168 §6.1.

use umilib::bytes::Buffer;
use umilib::protocol::tcp::{
    TCPConfig, TCPCongestionControl, TCPECNMode, TCPFlags, TCPOptionSet, TCPSACKBlock, TCPSegment, TCPSequence,
    TCPTimestamps,
};

use super::connection::{Network, never};

/// A configuration that sends each segment as soon as it is given (MUST-17).
fn eager() -> TCPConfig {
    TCPConfig { nagle: false, ..TCPConfig::default() }
}

/// Sends `count` segments of `size` bytes from A, which the network loses: their sequence numbers.
fn lost_segments(network: &mut Network, count: usize, size: usize) -> Vec<TCPSequence> {
    let mut starts = Vec::new();
    for index in 0..count {
        starts.push(network.a.send_next);
        network.a.send(&vec![index as u8; size]).unwrap();
        network.transmit();
    }
    network.queue.clear();
    starts.push(network.a.send_next);
    starts
}

/// An ACK from B to A of `acknowledgment`, with `sack` blocks, `window`
/// (unscaled), `flags` added to ACK, and B's timestamps.
fn ack(network: &mut Network, acknowledgment: TCPSequence, sack: &[TCPSACKBlock], window: u16, flags: TCPFlags) {
    let options = TCPOptionSet {
        timestamps: Some(TCPTimestamps {
            value: network.b.timestamp(network.now),
            echo_reply: network.b.timestamp_recent,
        }),
        ..TCPOptionSet::default()
    }
    .with_sack(sack);
    let mut options_bytes = Buffer::new();
    options.encode(&mut options_bytes).unwrap();
    let segment = TCPSegment {
        source_port: network.b.local.port,
        destination_port: network.b.remote.port,
        sequence: network.b.send_next,
        acknowledgment,
        flags: TCPFlags::ACK.union(flags),
        window,
        options: options_bytes.as_slice(),
        ..TCPSegment::default()
    };
    let mut bytes = Buffer::new();
    segment.encode(network.b.local.address, network.b.remote.address, &mut bytes).unwrap();
    let segment = TCPSegment::decode(bytes.as_slice(), network.b.local.address, network.b.remote.address).unwrap();
    let now = network.now;
    network.a.receive(&segment, false, now);
}

/// The window A last received, as B would write it.
fn window(network: &Network) -> u16 {
    (network.a.send_window >> network.a.send_scale) as u16
}

fn block(left: TCPSequence, right: TCPSequence) -> TCPSACKBlock {
    TCPSACKBlock { left, right }
}

#[test]
fn sack_recovery_of_small_segments() {
    // RFC 6675 §5 (1), (4.3): DupThresh duplicates enter the recovery and
    // retransmit HighACK + 1 at once, even when the SACKed bytes are too few
    // for IsLost (segments of 100 bytes).
    let mut network = Network::new(eager(), TCPConfig::default());
    network.run(never);
    let first = network.a.send_next;
    let mut data = Vec::new();
    for index in 0..6u8 {
        network.a.send(&[index; 100]).unwrap();
        data.extend([index; 100]);
        network.transmit();
    }
    // The first segment is lost; the others arrive one by one, and B SACKs
    // each (segments queued together would share one ACK, MUST-58).
    network.queue.pop_front();
    let start = network.now;
    let flights: Vec<_> = network.queue.drain(..).collect();
    for flight in flights {
        network.deliver(&flight);
        network.transmit();
    }
    network.run(never);
    let sent: Vec<_> = network
        .segments(true)
        .into_iter()
        .filter(|segment| segment.sequence == first && !segment.payload.is_empty())
        .collect();
    // The segment and its fast retransmission, which ends where the SACKed
    // data starts. RescueRxt moves past it too, so the rescue of NextSeg (4)
    // does not repeat it (RFC 6675 (4.3)).
    assert_eq!(sent.iter().map(|segment| segment.payload.len()).collect::<Vec<_>>(), [100, 100]);
    assert_eq!(network.now, start);
    assert_eq!(super::connection::read_all(&mut network.b), data);
    assert!(network.a.recovery.is_none(), "the cumulative ACK of RecoveryPoint ended the recovery");
}

#[test]
fn duplicate_acknowledgments_with_sack() {
    // RFC 6675 §2: with SACK, an ACK is a duplicate when it SACKs data not
    // SACKed before, whatever its window or acknowledgment number; one that
    // SACKs nothing new is not.
    let mut network = Network::new(eager(), TCPConfig::default());
    network.run(never);
    let starts = lost_segments(&mut network, 5, 1000);
    let una = starts[0];
    let window_now = window(&network);
    ack(&mut network, una, &[block(starts[1], starts[2])], window_now, TCPFlags::NONE);
    assert_eq!(network.a.duplicate_acks, 1);
    ack(&mut network, una, &[block(starts[1], starts[2])], window_now, TCPFlags::NONE);
    assert_eq!(network.a.duplicate_acks, 1, "no new SACK information");
    ack(&mut network, una, &[block(starts[2], starts[3]), block(starts[1], starts[2])], window_now - 1, TCPFlags::NONE);
    assert_eq!(network.a.duplicate_acks, 2, "a new block counts though the window changed");
    // A cumulative ACK resets DupAcks; the new SACK block it carries counts again (RFC 6675 §5).
    ack(&mut network, starts[1], &[block(starts[3], starts[4])], window_now, TCPFlags::NONE);
    assert_eq!(network.a.duplicate_acks, 1);
    assert!(network.a.recovery.is_none());
}

#[test]
fn no_new_recovery_before_recover() {
    // RFC 6582 §3.2 (1) and (4), RFC 6675 §5.1: after a timeout, duplicate
    // ACKs for data sent before it do not start a fast recovery.
    for sack in [false, true] {
        let config = TCPConfig { sack, ..eager() };
        let mut network = Network::new(config, TCPConfig::default());
        network.run(never);
        let starts = lost_segments(&mut network, 4, 1000);
        network.now = network.a.retransmit_at.unwrap();
        network.transmit();
        network.queue.clear();
        assert_eq!(network.a.recover, starts[4], "recover is the highest data sent");
        let una = network.a.send_unacknowledged;
        for index in 1..=3 {
            let window_now = window(&network);
            let blocks = [block(starts[index], starts[index + 1])];
            ack(&mut network, una, if sack { &blocks } else { &[] }, window_now, TCPFlags::NONE);
        }
        assert!(network.a.recovery.is_none(), "sack {sack}: no recovery below recover");
        assert!(network.a.retransmit_due.is_none());
    }
}

/// Two ends that negotiated ECN (RFC 3168 §6.1.1).
fn ecn_network(config_a: TCPConfig) -> Network {
    let mut network = Network::new(TCPConfig { ecn: TCPECNMode::Request, ..config_a }, TCPConfig::default());
    network.run(never);
    assert!(network.a.ecn && network.b.ecn);
    network
}

#[test]
fn window_probes_carry_no_ect_or_cwr() {
    // RFC 3168 §6.1.6: the sender MUST NOT set ECT or CWR on window probes.
    let mut network = ecn_network(eager());
    let una = network.a.send_unacknowledged;
    ack(&mut network, una, &[], 0, TCPFlags::NONE);
    assert_eq!(network.a.send_window, 0);
    network.a.ecn_cwr_due = true;
    network.a.send(&[1; 100]).unwrap();
    assert_eq!(network.transmit(), 0, "nothing goes into a zero window");
    network.now = network.a.persist_at.expect("the persist timer runs");
    let mut out = Buffer::new();
    let probe = network.a.transmit(network.now, &mut out).unwrap().expect("a probe");
    let segment = TCPSegment::decode(out.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
    assert_eq!(segment.payload.len(), 1);
    assert!(!probe.ect && !segment.flags.contains(TCPFlags::CWR));
    assert!(network.a.ecn_cwr_due, "CWR waits for new data");
}

#[test]
fn echoes_of_congestion() {
    // RFC 3168 §6.1.2: an ECE reduces cwnd as a loss does, at most once per
    // window of data, and the ACK that carries it does not grow cwnd.
    let mut network = ecn_network(TCPConfig { sack: false, ..eager() });
    let starts = lost_segments(&mut network, 4, 1000);
    let before = network.a.congestion.window();
    let window_now = window(&network);
    ack(&mut network, starts[1], &[], window_now, TCPFlags::ECE);
    let reduced = network.a.congestion.window();
    assert!(reduced < before, "{reduced} < {before}");
    assert!(network.a.ecn_cwr_due);
    ack(&mut network, starts[2], &[], window_now, TCPFlags::ECE);
    assert_eq!(network.a.congestion.window(), reduced, "one reduction per window, and no growth");
    // A loss in the same window does not reduce it again; it is still retransmitted.
    let threshold = network.a.congestion.threshold();
    for _ in 0..3 {
        ack(&mut network, starts[2], &[], window_now, TCPFlags::NONE);
    }
    assert!(network.a.recovery.is_some() && network.a.retransmit_due == Some(starts[2]));
    assert_eq!(network.a.congestion.threshold(), threshold);
}

#[test]
fn echo_with_a_window_of_one_segment() {
    // RFC 3168 §6.1.2: with cwnd at one MSS, an ECE resets the retransmit
    // timer, and new data waits until it expires.
    let mut network = ecn_network(eager());
    let starts = lost_segments(&mut network, 2, 500);
    let mss = network.a.mss();
    network.a.congestion.set_window(mss);
    network.a.reduced_until = None;
    let window_now = window(&network);
    ack(&mut network, starts[1], &[], window_now, TCPFlags::ECE);
    let hold = network.a.ecn_hold.expect("new data is held");
    assert!(network.a.poll_timeout().is_some_and(|deadline| deadline <= hold));
    network.a.send(&[7; 500]).unwrap();
    let mut out = Buffer::new();
    assert!(network.a.transmit(network.now, &mut out).unwrap().is_none_or(|_| {
        let segment = TCPSegment::decode(out.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
        segment.payload.is_empty() || segment.sequence.is_before(starts[2])
    }));
    assert_eq!(network.a.unsent(), 500, "the new data waits");
    network.now = hold;
    network.a.transmit(network.now, &mut Buffer::new()).unwrap();
    assert!(network.a.ecn_hold.is_none());
}

#[test]
fn congestion_experienced_on_a_cwr_segment() {
    // RFC 3168 §6.1.3: CWR stops the echo, but CE on that same segment starts it again.
    let mut network = ecn_network(TCPConfig::default());
    network.a.send(&[1; 100]).unwrap();
    network.transmit();
    let flight = network.queue.pop_front().unwrap();
    let segment = TCPSegment::decode(&flight.bytes, network.a.local.address, network.a.remote.address).unwrap();
    let marked = TCPSegment { flags: segment.flags.union(TCPFlags::CWR), ..segment };
    let mut bytes = Buffer::new();
    marked.encode(network.a.local.address, network.a.remote.address, &mut bytes).unwrap();
    let marked = TCPSegment::decode(bytes.as_slice(), network.a.local.address, network.a.remote.address).unwrap();
    network.b.ecn_echo = true;
    let now = network.now;
    network.b.receive(&marked, true, now);
    assert!(network.b.ecn_echo);
}

#[test]
fn sack_recovery_of_segments_smaller_than_the_mss() {
    // RFC 6675 §5: the scoreboard MUST be updated with every SACK block of an
    // honest receiver, also when the segments are smaller than the MSS.
    let mut network = Network::new(eager(), TCPConfig::default());
    network.run(never);
    let mut data = Vec::new();
    for index in 0..8u8 {
        network.a.send(&[index; 100]).unwrap();
        data.extend([index; 100]);
        network.transmit();
    }
    // Every other segment is lost; B SACKs the others, one by one.
    let flights: Vec<_> = network.queue.drain(..).collect();
    let start = network.now;
    for flight in flights.into_iter().skip(1).step_by(2) {
        network.deliver(&flight);
        network.run(never);
    }
    // Four blocks above SND.UNA make it lost (IsLost), and the holes are
    // sent again without a timeout.
    assert_eq!(network.now, start, "no timeout was needed");
    assert_eq!(super::connection::read_all(&mut network.b), data);
}

#[test]
fn window_probes_are_not_losses() {
    // RFC 9293 §3.8.6.1: a closed window is not a loss, so the answers to
    // window probes are not duplicate ACKs (RFC 5681 §2), however many.
    let mut network = Network::new(TCPConfig { sack: false, ..TCPConfig::default() }, TCPConfig::default());
    network.run(never);
    let una = network.a.send_unacknowledged;
    ack(&mut network, una, &[], 0, TCPFlags::NONE);
    network.a.send(&[1; 100]).unwrap();
    network.transmit();
    let window_before = network.a.congestion.window();
    for _ in 0..6 {
        network.now = network.a.poll_timeout().unwrap();
        network.transmit();
        network.queue.clear();
        ack(&mut network, una, &[], 0, TCPFlags::NONE);
    }
    assert!(network.a.recovery.is_none() && network.a.duplicate_acks == 0);
    assert_eq!(network.a.congestion.window(), window_before);
}

#[test]
fn reductions_are_forgotten_once_acknowledged() {
    // RFC 3168 §6.1.2, RFC 5681 §3.2: the guard of one reduction per window
    // ends with that window, so a later loss or ECE reduces cwnd again
    // however much data passed in between.
    let mut network = ecn_network(TCPConfig { sack: false, ..eager() });
    let starts = lost_segments(&mut network, 2, 1000);
    let window_now = window(&network);
    ack(&mut network, starts[1], &[], window_now, TCPFlags::ECE);
    assert_eq!(network.a.reduced_until, Some(starts[2]));
    ack(&mut network, starts[2], &[], window_now, TCPFlags::NONE);
    assert_eq!(network.a.reduced_until, None);
}
