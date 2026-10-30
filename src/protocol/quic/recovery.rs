use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::time::Duration;

use crate::runtime::Instant;

use super::{QUICECNCounts, QUICPacketNumberSpace, QUICSentPacket};

/// The round-trip time estimates of a path (RFC 9002 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICRTT {
    pub latest: Duration,
    pub smoothed: Duration,
    pub variation: Duration,
    pub minimum: Duration,
    /// When the first sample was taken: packets before it do not count
    /// toward persistent congestion (RFC 9002 §7.6.2).
    pub first_sample: Option<Instant>,
}

impl QUICRTT {
    /// The timer granularity: 1 ms (RFC 9002 §6.1.2).
    pub const GRANULARITY: Duration = Duration::from_millis(1);

    /// The estimates before any sample, from `initial` (RFC 9002 §5.3: 333 ms by default).
    pub fn new(initial: Duration) -> QUICRTT {
        QUICRTT {
            latest: initial,
            smoothed: initial,
            variation: initial / 2,
            minimum: Duration::ZERO,
            first_sample: None,
        }
    }

    /// A sample `latest` with the peer's acknowledgment delay `ack_delay`,
    /// limited by `max_ack_delay` once the handshake is confirmed (RFC 9002 §5.3).
    pub fn update(&mut self, latest: Duration, ack_delay: Duration, max_ack_delay: Option<Duration>, now: Instant) {
        self.latest = latest;
        if self.first_sample.is_none() {
            self.first_sample = Some(now);
            self.minimum = latest;
            self.smoothed = latest;
            self.variation = latest / 2;
            return;
        }
        self.minimum = self.minimum.min(latest);
        let ack_delay = max_ack_delay.map_or(ack_delay, |maximum| ack_delay.min(maximum));
        // The delay is subtracted only while the sample stays above the minimum.
        let adjusted = if latest >= self.minimum + ack_delay { latest - ack_delay } else { latest };
        let difference = self.smoothed.abs_diff(adjusted);
        self.variation = (self.variation * 3 + difference) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    /// The probe timeout without backoff and without max_ack_delay:
    /// smoothed_rtt + max(4 × rttvar, kGranularity) (RFC 9002 §6.2.1).
    pub fn probe_timeout(&self) -> Duration {
        self.smoothed + (self.variation * 4).max(QUICRTT::GRANULARITY)
    }

    /// The delay after which a packet sent before one acknowledged is lost:
    /// 9/8 × max(smoothed_rtt, latest_rtt), at least kGranularity (RFC 9002 §6.1.2).
    pub fn loss_delay(&self) -> Duration {
        (self.latest.max(self.smoothed) * 9 / 8).max(QUICRTT::GRANULARITY)
    }
}

/// A congestion controller of QUIC (RFC 9002 §7): it decides how many
/// bytes may be in flight, from what the recovery tells it.
pub trait QUICCongestionControl: Send + core::fmt::Debug {
    /// The congestion window, in bytes.
    fn window(&self) -> u64;

    /// `packet`, in flight, was acknowledged at `now`. `limited` says that
    /// the sender was limited by the application or flow control, not the
    /// window: the window does not grow then (RFC 9002 §7.8).
    fn acknowledge(&mut self, packet: &QUICSentPacket, rtt: &QUICRTT, limited: bool, now: Instant);

    /// A congestion event at `now` for the packet sent at `sent`: a loss or
    /// an ECN-CE mark (RFC 9002 §7.3.2). One per round trip reduces the window.
    fn congestion(&mut self, sent: Instant, now: Instant);

    /// Persistent congestion (RFC 9002 §7.6): the window falls to the minimum.
    fn collapse(&mut self);

    /// The largest datagram changed, as path MTU discovery finds (RFC 9002 §7.2).
    fn set_datagram_size(&mut self, size: usize);
}

/// NewReno as RFC 9002 §7 and Appendix B define it for QUIC: slow start,
/// congestion avoidance, and one reduction per recovery period.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICNewReno {
    pub window: u64,
    pub threshold: u64,
    /// When the current recovery period began.
    pub recovery_start: Option<Instant>,
    pub datagram_size: u64,
    /// The bytes acknowledged in congestion avoidance not yet turned into window.
    pub acknowledged: u64,
}

impl QUICNewReno {
    /// The initial window of `datagram_size`: 10 datagrams, limited to
    /// max(14720, 2 datagrams) (RFC 9002 §7.2).
    pub fn initial_window(datagram_size: usize) -> u64 {
        let size = datagram_size as u64;
        (10 * size).min(14_720u64.max(2 * size))
    }

    /// The minimum window: 2 datagrams (RFC 9002 §7.2).
    pub fn minimum_window(datagram_size: usize) -> u64 {
        2 * datagram_size as u64
    }

    pub fn new(datagram_size: usize) -> QUICNewReno {
        QUICNewReno {
            window: QUICNewReno::initial_window(datagram_size),
            threshold: u64::MAX,
            recovery_start: None,
            datagram_size: datagram_size as u64,
            acknowledged: 0,
        }
    }

    /// Whether a packet sent at `sent` belongs to the current recovery period.
    pub fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|start| sent <= start)
    }
}

impl QUICCongestionControl for QUICNewReno {
    fn window(&self) -> u64 {
        self.window
    }

    fn acknowledge(&mut self, packet: &QUICSentPacket, _rtt: &QUICRTT, limited: bool, _now: Instant) {
        if self.in_recovery(packet.time) || limited {
            return;
        }
        let size = packet.size as u64;
        if self.window < self.threshold {
            self.window += size;
        } else {
            // One datagram per window of bytes acknowledged (RFC 9002 §7.3.3).
            self.acknowledged += size;
            if self.acknowledged >= self.window {
                self.acknowledged -= self.window;
                self.window += self.datagram_size;
            }
        }
    }

    fn congestion(&mut self, sent: Instant, now: Instant) {
        if self.in_recovery(sent) {
            return;
        }
        self.recovery_start = Some(now);
        self.threshold = (self.window / 2).max(2 * self.datagram_size);
        self.window = self.threshold;
        self.acknowledged = 0;
    }

    fn collapse(&mut self) {
        self.window = 2 * self.datagram_size;
        self.recovery_start = None;
    }

    fn set_datagram_size(&mut self, size: usize) {
        self.datagram_size = size as u64;
        self.window = self.window.max(2 * self.datagram_size);
    }
}

/// The pacing of a sender (RFC 9002 §7.7): datagrams spread over the round
/// trip at 1.25 × cwnd / smoothed_rtt, with bursts of up to `burst` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICPacer {
    /// The bytes that may go now.
    pub credit: u64,
    pub burst: u64,
    pub last: Option<Instant>,
}

impl QUICPacer {
    pub fn new(burst: u64) -> QUICPacer {
        QUICPacer { credit: burst, burst, last: None }
    }

    /// The rate in bytes per second.
    pub fn rate(window: u64, rtt: Duration) -> u64 {
        let nanoseconds = rtt.as_nanos().max(1);
        ((window as u128 * 5 / 4 * 1_000_000_000) / nanoseconds).min(u64::MAX as u128) as u64
    }

    /// Refills the credit for the time since the last call.
    pub fn refill(&mut self, window: u64, rtt: Duration, now: Instant) {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_nanos();
            let earned = (QUICPacer::rate(window, rtt) as u128 * elapsed / 1_000_000_000).min(u64::MAX as u128);
            self.credit = (self.credit + earned as u64).min(self.burst);
        }
        self.last = Some(now);
    }

    /// When `size` bytes may go, or `None` if now. The wait is rounded up,
    /// so that what [`QUICPacer::refill`] earns by then, rounded down, is enough.
    pub fn next(&self, size: usize, window: u64, rtt: Duration) -> Option<Instant> {
        let missing = (size as u64).checked_sub(self.credit).filter(|missing| *missing > 0)?;
        let rate = QUICPacer::rate(window, rtt).max(1) as u128;
        let wait = (missing as u128 * 1_000_000_000).div_ceil(rate);
        Some(self.last? + Duration::from_nanos(wait.min(u64::MAX as u128) as u64))
    }

    pub fn spend(&mut self, size: usize) {
        self.credit = self.credit.saturating_sub(size as u64);
    }
}

/// The loss recovery of one packet number space (RFC 9002 Appendix A.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICSpaceRecovery {
    pub sent: BTreeMap<u64, QUICSentPacket>,
    pub largest_acknowledged: Option<u64>,
    pub last_ack_eliciting: Option<Instant>,
    /// When the earliest packet not yet lost by time will be.
    pub loss_time: Option<Instant>,
    /// The ECN-CE count last reported by the peer.
    pub ecn: QUICECNCounts,
}

impl QUICSpaceRecovery {
    pub fn ack_eliciting_in_flight(&self) -> bool {
        self.sent.values().any(|packet| packet.ack_eliciting)
    }
}

/// What an acknowledgment did: the packets it newly acknowledged, and those
/// found lost because of it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICAcknowledgment {
    pub acknowledged: Vec<QUICSentPacket>,
    pub lost: Vec<QUICSentPacket>,
}

/// Loss detection and congestion control of a connection (RFC 9002): the
/// packets sent in each space, the RTT, the probe timeout, and the bytes
/// in flight under the congestion window.
#[derive(Debug)]
pub struct QUICRecovery {
    pub spaces: [QUICSpaceRecovery; 3],
    pub rtt: QUICRTT,
    pub congestion: alloc::boxed::Box<dyn QUICCongestionControl>,
    pub pacer: Option<QUICPacer>,
    pub bytes_in_flight: u64,
    /// The probe timeouts in a row (RFC 9002 §6.2.1).
    pub pto_count: u32,
    /// The peer's max_ack_delay, which the probe timeout of the
    /// application space adds (RFC 9002 §6.2.1).
    pub max_ack_delay: Duration,
}

impl QUICRecovery {
    /// A packet acknowledged when `kPacketThreshold` later ones are (RFC 9002 §6.1.1).
    pub const PACKET_THRESHOLD: u64 = 3;
    /// The probe timeouts of persistent congestion (RFC 9002 §7.6.1).
    pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

    pub fn new(
        initial_rtt: Duration,
        congestion: alloc::boxed::Box<dyn QUICCongestionControl>,
        pacer: Option<QUICPacer>,
    ) -> QUICRecovery {
        QUICRecovery {
            spaces: Default::default(),
            rtt: QUICRTT::new(initial_rtt),
            congestion,
            pacer,
            bytes_in_flight: 0,
            pto_count: 0,
            max_ack_delay: Duration::ZERO,
        }
    }

    /// The bytes that may still be sent under the congestion window.
    pub fn congestion_credit(&self) -> u64 {
        self.congestion.window().saturating_sub(self.bytes_in_flight)
    }

    /// Records a packet sent in `space` (RFC 9002 Appendix A.5). A packet
    /// neither ack-eliciting nor in flight is not kept: nothing of it is
    /// sent again, and a peer need never acknowledge it (RFC 9000 §13.2.1).
    pub fn sent(&mut self, space: QUICPacketNumberSpace, packet: QUICSentPacket) {
        let recovery = &mut self.spaces[space.index()];
        if packet.in_flight {
            if packet.ack_eliciting {
                recovery.last_ack_eliciting = Some(packet.time);
            }
            self.bytes_in_flight += packet.size as u64;
        }
        if let Some(pacer) = &mut self.pacer {
            pacer.spend(packet.size);
        }
        if packet.ack_eliciting || packet.in_flight {
            recovery.sent.insert(packet.number, packet);
        }
    }

    /// An ACK frame of `space` acknowledging `ranges` (largest first), with
    /// the delay `ack_delay` and the ECN counts if any (RFC 9002 Appendix
    /// A.7). `handshake_confirmed` caps the delay at max_ack_delay (§5.3);
    /// `limited` passes to the congestion controller. Returns the packets
    /// newly acknowledged and those lost.
    #[allow(clippy::too_many_arguments)]
    pub fn acknowledge(
        &mut self,
        space: QUICPacketNumberSpace,
        ranges: impl Iterator<Item = core::ops::RangeInclusive<u64>>,
        ack_delay: Duration,
        ecn: Option<QUICECNCounts>,
        handshake_confirmed: bool,
        limited: bool,
        now: Instant,
    ) -> QUICAcknowledgment {
        let ranges: Vec<core::ops::RangeInclusive<u64>> = ranges.collect();
        let Some(frame_largest) = ranges.first().map(|range| *range.end()) else {
            return QUICAcknowledgment::default();
        };
        let recovery = &mut self.spaces[space.index()];
        recovery.largest_acknowledged = recovery.largest_acknowledged.max(Some(frame_largest));
        let mut acknowledged = Vec::new();
        for range in ranges {
            let numbers: Vec<u64> = recovery.sent.range(range).map(|(number, _)| *number).collect();
            acknowledged.extend(numbers.into_iter().filter_map(|number| recovery.sent.remove(&number)));
        }
        if acknowledged.is_empty() {
            return QUICAcknowledgment::default();
        }
        acknowledged.sort_by_key(|packet| packet.number);
        // An RTT sample when the largest acknowledged is newly acknowledged
        // and so is something ack-eliciting (RFC 9002 §5.1).
        if let Some(packet) = acknowledged.last().filter(|packet| packet.number == frame_largest)
            && acknowledged.iter().any(|packet| packet.ack_eliciting)
        {
            let latest = now.saturating_duration_since(packet.time);
            let ack_delay = if space == QUICPacketNumberSpace::ApplicationData { ack_delay } else { Duration::ZERO };
            let maximum = handshake_confirmed.then_some(self.max_ack_delay);
            self.rtt.update(latest, ack_delay, maximum, now);
        }
        // ECN-CE marks are congestion (RFC 9002 §7.1, Appendix B.4).
        let recovery = &mut self.spaces[space.index()];
        if let Some(counts) = ecn
            && counts.ce > recovery.ecn.ce
        {
            recovery.ecn = counts;
            let sent = acknowledged.last().map(|packet| packet.time).unwrap_or(now);
            self.congestion.congestion(sent, now);
        }
        let lost = self.detect_lost(space, now);
        self.lost(&lost, &acknowledged, now);
        for packet in &acknowledged {
            if packet.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size as u64);
                self.congestion.acknowledge(packet, &self.rtt, limited, now);
            }
        }
        QUICAcknowledgment { acknowledged, lost }
    }

    /// The packets of `space` lost by the packet or time threshold, and the
    /// loss time of those that will be (RFC 9002 §6.1, Appendix A.10).
    pub fn detect_lost(&mut self, space: QUICPacketNumberSpace, now: Instant) -> Vec<QUICSentPacket> {
        let delay = self.rtt.loss_delay();
        let recovery = &mut self.spaces[space.index()];
        recovery.loss_time = None;
        let Some(largest) = recovery.largest_acknowledged else { return Vec::new() };
        let mut lost = Vec::new();
        let numbers: Vec<u64> = recovery.sent.range(..=largest).map(|(number, _)| *number).collect();
        for number in numbers {
            let packet = &recovery.sent[&number];
            let by_time = packet.time + delay <= now;
            let by_number = largest >= number + QUICRecovery::PACKET_THRESHOLD;
            if by_time || by_number {
                if let Some(packet) = recovery.sent.remove(&number) {
                    lost.push(packet);
                }
            } else {
                let time = packet.time + delay;
                recovery.loss_time = Some(recovery.loss_time.map_or(time, |loss| loss.min(time)));
            }
        }
        lost
    }

    /// Accounts for `lost` (RFC 9002 Appendix B.8): out of flight, one
    /// congestion event, and persistent congestion if they span more than
    /// three probe timeouts with nothing acknowledged between.
    pub fn lost(&mut self, lost: &[QUICSentPacket], acknowledged: &[QUICSentPacket], now: Instant) {
        let mut last_loss = None;
        for packet in lost.iter().filter(|packet| packet.in_flight) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size as u64);
            last_loss = last_loss.max(Some(packet.time));
        }
        if let Some(sent) = last_loss {
            self.congestion.congestion(sent, now);
        }
        if self.in_persistent_congestion(lost, acknowledged) {
            self.congestion.collapse();
        }
    }

    /// Whether `lost` shows persistent congestion (RFC 9002 §7.6.2): two
    /// ack-eliciting packets sent after the first RTT sample, further apart
    /// than the persistent congestion duration, and none in between
    /// acknowledged. The packets are those lost and acknowledged by one
    /// acknowledgment or timeout: one acknowledged earlier between them
    /// would have had them declared lost then.
    pub fn in_persistent_congestion(&self, lost: &[QUICSentPacket], acknowledged: &[QUICSentPacket]) -> bool {
        let Some(first_sample) = self.rtt.first_sample else { return false };
        let eliciting: Vec<&QUICSentPacket> =
            lost.iter().filter(|packet| packet.ack_eliciting && packet.time > first_sample).collect();
        let (Some(first), Some(last)) =
            (eliciting.iter().map(|packet| packet.time).min(), eliciting.iter().map(|packet| packet.time).max())
        else {
            return false;
        };
        let duration = (self.rtt.probe_timeout() + self.max_ack_delay) * QUICRecovery::PERSISTENT_CONGESTION_THRESHOLD;
        last.saturating_duration_since(first) > duration
            && !acknowledged.iter().any(|packet| packet.time > first && packet.time < last)
    }

    /// The probe timeout of `space` without backoff, with max_ack_delay for
    /// the application space (RFC 9002 §6.2.1): the period that the idle
    /// timeout, closing and old keys count in.
    pub fn base_probe_timeout(&self, space: QUICPacketNumberSpace) -> Duration {
        let duration = self.rtt.probe_timeout();
        if space == QUICPacketNumberSpace::ApplicationData { duration + self.max_ack_delay } else { duration }
    }

    /// The probe timeout of `space` backed off by 2^pto_count, as the
    /// loss detection timer waits it (RFC 9002 §6.2.1).
    pub fn probe_timeout(&self, space: QUICPacketNumberSpace) -> Duration {
        self.base_probe_timeout(space) * (1u32 << self.pto_count.min(16))
    }

    /// The earliest loss time and its space (RFC 9002 Appendix A.8).
    pub fn loss_time(&self) -> Option<(Instant, QUICPacketNumberSpace)> {
        QUICPacketNumberSpace::ALL
            .into_iter()
            .filter_map(|space| self.spaces[space.index()].loss_time.map(|time| (time, space)))
            .min_by_key(|(time, _)| *time)
    }

    /// When the probe timeout fires and in which space, among those
    /// `usable` (with keys, and the application space only once the
    /// handshake is confirmed) (RFC 9002 Appendix A.8).
    pub fn probe_time(
        &self,
        usable: impl Fn(QUICPacketNumberSpace) -> bool,
    ) -> Option<(Instant, QUICPacketNumberSpace)> {
        QUICPacketNumberSpace::ALL
            .into_iter()
            .filter(|space| usable(*space))
            .filter_map(|space| {
                let recovery = &self.spaces[space.index()];
                if !recovery.ack_eliciting_in_flight() {
                    return None;
                }
                recovery.last_ack_eliciting.map(|time| (time + self.probe_timeout(space), space))
            })
            .min_by_key(|(time, _)| *time)
    }

    /// Forgets `space`, whose keys were discarded (RFC 9002 §6.4): its
    /// packets leave flight without being lost.
    pub fn discard(&mut self, space: QUICPacketNumberSpace) {
        let recovery = core::mem::take(&mut self.spaces[space.index()]);
        for packet in recovery.sent.values().filter(|packet| packet.in_flight) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.size as u64);
        }
        self.pto_count = 0;
    }
}
