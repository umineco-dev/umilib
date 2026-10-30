//! The parts of loss recovery that stand alone (RFC 9002): the probe
//! timeout and its backoff, and pacing.

use std::time::Duration;

use umilib::protocol::quic::{QUICNewReno, QUICPacer, QUICPacketNumberSpace, QUICRecovery};
use umilib::runtime::Instant;

#[test]
fn probe_timeouts_back_off() {
    // RFC 9002 §6.2.1: smoothed_rtt + max(4 × rttvar, kGranularity), with
    // max_ack_delay in the application space, doubled per timeout in a row.
    let mut recovery = QUICRecovery::new(Duration::from_millis(100), Box::new(QUICNewReno::new(1200)), None);
    recovery.max_ack_delay = Duration::from_millis(25);
    let base = Duration::from_millis(100 + 4 * 50);
    assert_eq!(recovery.base_probe_timeout(QUICPacketNumberSpace::Initial), base);
    assert_eq!(recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData), base + Duration::from_millis(25));
    recovery.pto_count = 3;
    assert_eq!(recovery.probe_timeout(QUICPacketNumberSpace::Initial), base * 8);
    assert_eq!(recovery.base_probe_timeout(QUICPacketNumberSpace::Initial), base);
}

#[test]
fn pacing_releases_what_it_waited_for() {
    // RFC 9002 §7.7: a sender that waits as long as the pacer says may then
    // send, whatever the rate and the bytes missing.
    for (window, rtt) in [(12_000, 1_000_000), (23_982, 333_000_000), (1_000_000, 7), (2_400, 3)] {
        for size in [1, 2, 1199, 1200, 1500] {
            let mut pacer = QUICPacer::new(0);
            pacer.burst = 1 << 20;
            let rtt = Duration::from_nanos(rtt);
            let start = Instant::from_nanos(1_000_000_000);
            pacer.refill(window, rtt, start);
            let release = pacer.next(size, window, rtt).unwrap();
            pacer.refill(window, rtt, release);
            assert!(pacer.next(size, window, rtt).is_none(), "window {window} rtt {rtt:?} size {size}");
        }
    }
}
