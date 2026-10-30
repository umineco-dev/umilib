use core::time::Duration;

use crate::runtime::Instant;

use super::TCPCongestionControl;

/// The congestion control of RFC 5681 (slow start and congestion
/// avoidance), whose loss recovery is NewReno's (RFC 6582) or SACK's (RFC
/// 6675), kept by the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPNewReno {
    pub window: u32,
    pub threshold: u32,
    /// Bytes acknowledged in congestion avoidance since cwnd last grew (RFC 5681 §3.1).
    pub acknowledged: u32,
}

impl TCPNewReno {
    /// A control with cwnd `window` and an ssthresh as high as can be (RFC 5681 §3.1).
    pub fn new(window: u32) -> TCPNewReno {
        TCPNewReno { window, threshold: u32::MAX, acknowledged: 0 }
    }

    /// ssthresh after a congestion event: half the flight size, at least two
    /// segments (RFC 5681 §3.1, equation 4).
    pub fn reduced(in_flight: u32, mss: u32) -> u32 {
        (in_flight / 2).max(2 * mss)
    }
}

impl TCPCongestionControl for TCPNewReno {
    fn window(&self) -> u32 {
        self.window
    }

    fn threshold(&self) -> u32 {
        self.threshold
    }

    fn set_window(&mut self, window: u32) {
        self.window = window;
    }

    fn acknowledge(&mut self, acknowledged: u32, mss: u32, _rtt: Duration, limited: bool, _now: Instant) {
        if limited {
            return;
        }
        if self.window < self.threshold {
            // Slow start: at most one segment for each acknowledgment (RFC 5681 §3.1, equation 2).
            self.window = self.window.saturating_add(acknowledged.min(mss));
            return;
        }
        // Congestion avoidance: one segment for each window acknowledged (RFC 5681 §3.1).
        self.acknowledged = self.acknowledged.saturating_add(acknowledged);
        if self.acknowledged >= self.window {
            self.acknowledged -= self.window;
            self.window = self.window.saturating_add(mss);
        }
    }

    fn congestion(&mut self, in_flight: u32, mss: u32, ecn: bool, _now: Instant) {
        let minimum = if ecn { mss } else { 2 * mss };
        self.threshold = (in_flight / 2).max(minimum);
        self.window = self.threshold;
        self.acknowledged = 0;
    }

    fn timeout(&mut self, in_flight: u32, mss: u32, _now: Instant) {
        self.threshold = TCPNewReno::reduced(in_flight, mss);
        self.window = mss;
        self.acknowledged = 0;
    }

    fn restart(&mut self, restart: u32, _now: Instant) {
        self.window = self.window.min(restart);
        self.acknowledged = 0;
    }
}
