//! Initial sequence numbers (RFC 6528), the retransmission timer (RFC
//! 6298) and congestion control (RFC 5681, RFC 9438).

use std::time::Duration;

use umilib::protocol::ip::IPEndpoint;
use umilib::protocol::tcp::{
    TCPCUBIC, TCPCongestion, TCPCongestionControl, TCPCongestionKind, TCPISNGenerator, TCPNewReno,
    TCPRetransmissionTimer, TCPSequence,
};
use umilib::runtime::Instant;

fn endpoint(text: &str) -> IPEndpoint {
    text.parse().unwrap()
}

fn at(milliseconds: u64) -> Instant {
    Instant::from_nanos(milliseconds * 1_000_000)
}

#[test]
fn initial_sequence_numbers() {
    // RFC 6528 §3: ISN = M + F(localip, localport, remoteip, remoteport, secretkey),
    // M a timer of 4 microseconds.
    let generator = TCPISNGenerator::new([7; 16]);
    let (local, remote) = (endpoint("192.0.2.1:40000"), endpoint("192.0.2.2:80"));
    let base = generator.generate(local, remote, Instant::ZERO);
    assert_eq!(generator.generate(local, remote, Instant::from_nanos(4_000)), base.add(1));
    assert_eq!(generator.generate(local, remote, Instant::from_nanos(4_000_000)), base.add(1000));
    assert_eq!(generator.generate(local, remote, Instant::from_nanos(3_999)), base);
    // F depends on every parameter and on the key (MUST-9).
    let others = [
        generator.generate(endpoint("192.0.2.1:40001"), remote, Instant::ZERO),
        generator.generate(local, endpoint("192.0.2.3:80"), Instant::ZERO),
        generator.generate(remote, local, Instant::ZERO),
        TCPISNGenerator::new([8; 16]).generate(local, remote, Instant::ZERO),
        generator.generate(endpoint("[::ffff:192.0.2.1]:40000"), endpoint("[::ffff:192.0.2.2]:80"), Instant::ZERO),
    ];
    for other in others {
        assert_ne!(other, base);
    }
    assert_ne!(TCPSequence(0), base);
}

#[test]
fn retransmission_timer() {
    // RFC 6298 (2.1): 1 second before any sample.
    let second = Duration::from_secs(1);
    let mut timer = TCPRetransmissionTimer::new(second, second, Duration::from_secs(60), Duration::from_millis(1));
    assert_eq!(timer.current(), second);
    // (2.2): SRTT = R, RTTVAR = R/2, RTO = SRTT + max(G, 4 RTTVAR), at least 1 second (2.4).
    timer.sample(Duration::from_millis(100));
    assert_eq!((timer.smoothed, timer.variation), (Some(Duration::from_millis(100)), Duration::from_millis(50)));
    assert_eq!(timer.current(), second);
    timer.sample(Duration::from_millis(500));
    assert_eq!(timer.smoothed, Some(Duration::from_millis(150)));
    assert_eq!(timer.variation, Duration::from_millis(137) + Duration::from_micros(500));
    // 150 + 4 x 137.5 = 700 ms, raised to the minimum of a second (2.4).
    assert_eq!(timer.current(), second);
    // A minimum below a second is the caller's choice; the formula holds.
    let mut fast = TCPRetransmissionTimer::new(
        second,
        Duration::from_millis(200),
        Duration::from_secs(60),
        Duration::from_millis(1),
    );
    fast.sample(Duration::from_millis(100));
    assert_eq!(fast.current(), Duration::from_millis(300));
    fast.sample(Duration::from_millis(100));
    assert_eq!(fast.current(), Duration::from_millis(250));
    // (5.5): the RTO doubles at each expiry, up to the maximum (2.5).
    timer.expire();
    assert_eq!(timer.current(), Duration::from_secs(2));
    for _ in 0..10 {
        timer.expire();
    }
    assert_eq!(timer.current(), Duration::from_secs(60));
    timer.sample(Duration::from_millis(150));
    assert_eq!(timer.backoff, 0);
    // (5.7): a lost SYN leaves an RTO of at least 3 seconds for the data.
    let mut syn = TCPRetransmissionTimer::new(second, second, Duration::from_secs(60), Duration::from_millis(1));
    syn.expire();
    syn.restore_after_syn_loss();
    assert_eq!(syn.current(), Duration::from_secs(3));
}

#[test]
fn reno() {
    // RFC 5681 §3.1, equation 1: IW = min(4 SMSS, max(2 SMSS, 4380)).
    assert_eq!(TCPCongestion::initial_window(536), 2144);
    assert_eq!(TCPCongestion::initial_window(1460), 4380);
    assert_eq!(TCPCongestion::initial_window(3000), 6000);
    let mss = 1000;
    let mut reno = TCPNewReno::new(4000);
    // Slow start: cwnd += min(N, SMSS) (equation 2).
    reno.acknowledge(2000, mss, Duration::from_millis(50), false, at(0));
    assert_eq!(reno.window(), 5000);
    reno.acknowledge(500, mss, Duration::from_millis(50), false, at(0));
    assert_eq!(reno.window(), 5500);
    // A sender with less in flight than cwnd does not grow it (RFC 7661).
    reno.acknowledge(1000, mss, Duration::from_millis(50), true, at(0));
    assert_eq!(reno.window(), 5500);
    // Loss: ssthresh = max(FlightSize / 2, 2 SMSS) (equation 4).
    reno.congestion(8000, mss, false, at(1));
    assert_eq!((reno.threshold(), reno.window()), (4000, 4000));
    reno.congestion(1000, mss, false, at(1));
    assert_eq!(reno.threshold(), 2000);
    // Congestion avoidance: about one SMSS per RTT.
    let mut avoiding = TCPNewReno { window: 10_000, threshold: 5000, acknowledged: 0 };
    for _ in 0..10 {
        avoiding.acknowledge(1000, mss, Duration::from_millis(50), false, at(2));
    }
    assert_eq!(avoiding.window(), 11_000);
    // A timeout: cwnd is the loss window of one segment.
    avoiding.timeout(11_000, mss, at(3));
    assert_eq!((avoiding.window(), avoiding.threshold()), (1000, 5500));
    // Restart after idleness (RFC 5681 §4.1).
    let mut idle = TCPNewReno::new(20_000);
    idle.restart(4000, at(4));
    assert_eq!(idle.window(), 4000);
}

#[test]
fn cubic() {
    let mss = 1000;
    let rtt = Duration::from_millis(100);
    // RFC 9438 Figure 2: K = cbrt((W_max - cwnd_epoch) / C); W_max 100, cwnd_epoch 70: cbrt(75) = 4.217 s.
    assert_eq!(TCPCUBIC::period_for(100 * mss, 70 * mss, mss), 4217);
    assert_eq!(TCPCUBIC::period_for(70 * mss, 100 * mss, mss), -4217);
    assert_eq!(TCPCUBIC::cube_root(27), 3);
    assert_eq!(TCPCUBIC::cube_root(26), 2);
    assert_eq!(TCPCUBIC::cube_root(u64::MAX as u128), 2_642_245);
    // Figure 5: on loss ssthresh = 0.7 flight_size and cwnd = ssthresh; W_max is cwnd before.
    let mut cubic = TCPCUBIC::new(10 * mss);
    cubic.fast_convergence = false;
    cubic.window = 100 * mss;
    cubic.congestion(100 * mss, mss, false, at(0));
    assert_eq!(
        (cubic.window(), cubic.threshold(), cubic.maximum, cubic.prior),
        (70 * mss, 70 * mss, 100 * mss, 100 * mss)
    );
    // W_cubic(K) = W_max; W_cubic(0) = cwnd_epoch; the curve is concave below W_max.
    cubic.acknowledge(mss, mss, rtt, false, at(0));
    assert_eq!(cubic.period, 4217);
    assert_eq!(cubic.cubic(Duration::from_millis(4217), mss), 100 * mss as u64);
    assert!(cubic.cubic(Duration::ZERO, mss).abs_diff(70 * mss as u64) < mss as u64);
    let mut previous = cubic.window();
    let mut time = 0;
    while time < 8000 {
        time += 10;
        cubic.acknowledge(mss, mss, rtt, false, at(time));
        assert!(cubic.window() >= previous);
        previous = cubic.window();
    }
    // After about K the window is near W_max, then it probes above it (convex).
    assert!(cubic.window() > 100 * mss, "{}", cubic.window());
    // Fast convergence (§4.7): a loss below W_max lowers W_max to cwnd (1 + β) / 2.
    let mut converging = TCPCUBIC::new(10 * mss);
    converging.window = 80 * mss;
    converging.maximum = 100 * mss;
    converging.congestion(80 * mss, mss, false, at(0));
    assert_eq!(converging.maximum, 68 * mss);
    // An ECN-Echo may take cwnd down to one segment, a loss to two (Figure 5).
    let mut small = TCPCUBIC::new(2 * mss);
    small.congestion(mss, mss, true, at(0));
    assert_eq!((small.threshold(), small.window()), (2 * mss, 2 * mss));
    // A timeout (§4.8): cwnd is one segment, ssthresh 0.7 flight_size, and the
    // next stage starts with K = 0 and W_max = cwnd_epoch.
    let mut timed = TCPCUBIC::new(10 * mss);
    timed.window = 50 * mss;
    timed.timeout(50 * mss, mss, at(0));
    assert_eq!((timed.window(), timed.threshold()), (mss, 35 * mss));
    timed.window = 40 * mss;
    timed.threshold = 30 * mss;
    timed.acknowledge(mss, mss, rtt, false, at(1));
    assert_eq!((timed.period, timed.epoch_window), (0, 40 * mss));
    // The Reno-friendly region (§4.3): with a short RTT W_est leads, growing by
    // α = 9/17 segment for each window acknowledged.
    let mut friendly = TCPCUBIC::new(10 * mss);
    friendly.fast_convergence = false;
    friendly.window = 100 * mss;
    friendly.congestion(100 * mss, mss, false, at(0));
    for _ in 0..70 {
        friendly.acknowledge(mss, mss, Duration::from_millis(1), false, at(1));
    }
    // About 9/17 of a segment, a little less as cwnd follows W_est up.
    assert!((70 * mss + 520..=70 * mss + 530).contains(&friendly.estimate), "{}", friendly.estimate);
    assert_eq!(friendly.window(), friendly.estimate);
    // Application-limited time is not part of t (§5.8).
    let mut limited = TCPCUBIC::new(10 * mss);
    limited.window = 100 * mss;
    limited.congestion(100 * mss, mss, false, at(0));
    limited.acknowledge(mss, mss, rtt, false, at(0));
    let epoch = limited.epoch.unwrap();
    limited.acknowledge(mss, mss, rtt, true, at(5000));
    assert_eq!(limited.epoch, Some(epoch.saturating_add(Duration::from_secs(5))));
    // The kinds.
    assert!(matches!(TCPCongestion::new(TCPCongestionKind::NewReno, 4380), TCPCongestion::NewReno(_)));
    assert_eq!(TCPCongestion::new(TCPCongestionKind::default(), 4380).window(), 4380);
}
