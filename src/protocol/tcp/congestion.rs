use core::time::Duration;

use crate::runtime::Instant;

use super::{TCPCUBIC, TCPNewReno};

/// What a connection tells its congestion control, and what it reads back:
/// the congestion window (cwnd) and the slow start threshold (ssthresh), in
/// bytes. The connection keeps the loss recovery of RFC 6582 and RFC 6675;
/// the congestion control decides how the window grows and how much it is
/// reduced (RFC 9293 MUST-19, RFC 5681).
pub trait TCPCongestionControl {
    /// cwnd.
    fn window(&self) -> u32;

    /// ssthresh.
    fn threshold(&self) -> u32;

    /// Sets cwnd, as loss recovery does (RFC 6582 §3.2, RFC 6675 §5).
    fn set_window(&mut self, window: u32);

    /// `acknowledged` bytes of new data were acknowledged at `now`, outside
    /// loss recovery, with the smoothed round-trip time `rtt`. `limited` is
    /// whether the sender had less data in flight than cwnd allows, in which
    /// case cwnd does not grow (RFC 7661 §4.3, RFC 9438 §5.8).
    fn acknowledge(&mut self, acknowledged: u32, mss: u32, rtt: Duration, limited: bool, now: Instant);

    /// A congestion event at `now` with `in_flight` bytes outstanding: loss
    /// found by duplicate acknowledgments or SACK, or an ECN-Echo (`ecn`,
    /// RFC 3168 §6.1.2). ssthresh and cwnd are reduced at once.
    fn congestion(&mut self, in_flight: u32, mss: u32, ecn: bool, now: Instant);

    /// The retransmission timer expired at `now` with `in_flight` bytes
    /// outstanding: cwnd falls to one segment (RFC 5681 §3.1).
    fn timeout(&mut self, in_flight: u32, mss: u32, now: Instant);

    /// The connection was idle for more than an RTO: cwnd is restarted at
    /// `restart` bytes (RFC 5681 §4.1).
    fn restart(&mut self, restart: u32, now: Instant);
}

/// The congestion controls of this crate, chosen by [`TCPCongestionKind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TCPCongestion {
    NewReno(TCPNewReno),
    CUBIC(TCPCUBIC),
}

/// Which congestion control a connection uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCPCongestionKind {
    /// RFC 5681 and RFC 6582.
    NewReno = 0,
    /// RFC 9438.
    #[default]
    CUBIC = 1,
}

impl TCPCongestion {
    /// The congestion control of `kind` with the initial window `window` (RFC 5681 §3.1).
    pub fn new(kind: TCPCongestionKind, window: u32) -> TCPCongestion {
        match kind {
            TCPCongestionKind::NewReno => TCPCongestion::NewReno(TCPNewReno::new(window)),
            TCPCongestionKind::CUBIC => TCPCongestion::CUBIC(TCPCUBIC::new(window)),
        }
    }

    /// The initial window of RFC 5681 §3.1 (equation 1) for `mss`: up to 4
    /// segments, and no more than 4,380 bytes unless that is under 2 segments.
    pub fn initial_window(mss: u32) -> u32 {
        (4 * mss).min((2 * mss).max(4380))
    }

    pub fn control(&self) -> &dyn TCPCongestionControl {
        match self {
            TCPCongestion::NewReno(control) => control,
            TCPCongestion::CUBIC(control) => control,
        }
    }

    pub fn control_mut(&mut self) -> &mut dyn TCPCongestionControl {
        match self {
            TCPCongestion::NewReno(control) => control,
            TCPCongestion::CUBIC(control) => control,
        }
    }
}

impl TCPCongestionControl for TCPCongestion {
    fn window(&self) -> u32 {
        self.control().window()
    }

    fn threshold(&self) -> u32 {
        self.control().threshold()
    }

    fn set_window(&mut self, window: u32) {
        self.control_mut().set_window(window);
    }

    fn acknowledge(&mut self, acknowledged: u32, mss: u32, rtt: Duration, limited: bool, now: Instant) {
        self.control_mut().acknowledge(acknowledged, mss, rtt, limited, now);
    }

    fn congestion(&mut self, in_flight: u32, mss: u32, ecn: bool, now: Instant) {
        self.control_mut().congestion(in_flight, mss, ecn, now);
    }

    fn timeout(&mut self, in_flight: u32, mss: u32, now: Instant) {
        self.control_mut().timeout(in_flight, mss, now);
    }

    fn restart(&mut self, restart: u32, now: Instant) {
        self.control_mut().restart(restart, now);
    }
}
