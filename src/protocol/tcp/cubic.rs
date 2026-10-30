use core::time::Duration;

use crate::runtime::Instant;

use super::TCPCongestionControl;

/// The congestion control CUBIC (RFC 9438), in bytes and in integers: the
/// window grows by the cubic function W_cubic(t) = C (t - K)^3 + W_max in
/// congestion avoidance, never slower than Reno's estimate W_est, and is
/// reduced by β = 0.7. Slow start is Reno's (RFC 5681).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPCUBIC {
    /// cwnd.
    pub window: u32,
    /// ssthresh.
    pub threshold: u32,
    /// W_max.
    pub maximum: u32,
    /// cwnd_prior.
    pub prior: u32,
    /// t_epoch, while in a congestion avoidance stage.
    pub epoch: Option<Instant>,
    /// cwnd_epoch.
    pub epoch_window: u32,
    /// K, in milliseconds: negative when the stage starts above W_max (RFC 9438 Figure 2).
    pub period: i64,
    /// W_est.
    pub estimate: u32,
    /// The fractions of a byte that W_est and cwnd gained but did not yet add.
    pub estimate_remainder: u64,
    pub window_remainder: u64,
    /// Whether fast convergence is used (RFC 9438 §4.7).
    pub fast_convergence: bool,
    /// Whether the stage follows a timeout (RFC 9438 §4.8).
    pub after_timeout: bool,
    /// When the last acknowledgment came, to keep application-limited time
    /// out of t (RFC 9438 §5.8).
    pub last: Option<Instant>,
}

impl TCPCUBIC {
    /// C, in segments per second cubed: 4/10.
    pub const C: (u64, u64) = (4, 10);
    /// β_cubic: 7/10.
    pub const BETA: (u64, u64) = (7, 10);
    /// α_cubic = 3 (1 - β) / (1 + β): 9/17.
    pub const ALPHA: (u64, u64) = (9, 17);

    pub fn new(window: u32) -> TCPCUBIC {
        TCPCUBIC {
            window,
            threshold: u32::MAX,
            maximum: 0,
            prior: 0,
            epoch: None,
            epoch_window: window,
            period: 0,
            estimate: window,
            estimate_remainder: 0,
            window_remainder: 0,
            fast_convergence: true,
            after_timeout: false,
            last: None,
        }
    }

    /// W_cubic at `elapsed` from the epoch, in bytes of segments of `mss`.
    pub fn cubic(&self, elapsed: Duration, mss: u32) -> u64 {
        let t = elapsed.as_millis() as i128 - self.period as i128;
        // C (t - K)^3 in segments with t in milliseconds: 4 t^3 / 10^10.
        let growth = TCPCUBIC::C.0 as i128 * t * t * t * mss as i128 / (TCPCUBIC::C.1 as i128 * 1_000_000_000);
        (self.maximum as i128 + growth).clamp(0, u64::MAX as i128) as u64
    }

    /// K for a stage that starts at cwnd_epoch `window`: the cube root of
    /// (W_max - cwnd_epoch) / C, in milliseconds (RFC 9438 Figure 2).
    pub fn period_for(maximum: u32, window: u32, mss: u32) -> i64 {
        let gap = maximum.abs_diff(window) as u128;
        // (gap / mss) / (4/10) seconds cubed, in milliseconds cubed.
        let cubed = gap * TCPCUBIC::C.1 as u128 * 1_000_000_000 / (TCPCUBIC::C.0 as u128 * mss.max(1) as u128);
        let root = TCPCUBIC::cube_root(cubed) as i64;
        if maximum >= window { root } else { -root }
    }

    /// The integer cube root of `value`, rounded down.
    pub fn cube_root(value: u128) -> u64 {
        let (mut low, mut high) = (0u64, 1u64 << 43);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            let cube = (middle as u128).pow(3);
            if cube <= value { low = middle } else { high = middle - 1 }
        }
        low
    }

    /// Adds `numerator / denominator` bytes to `value`, keeping the fraction in `remainder`.
    pub fn grow(value: &mut u32, remainder: &mut u64, numerator: u64, denominator: u64) {
        let denominator = denominator.max(1);
        let total = *remainder as u128 + numerator as u128;
        let whole = (total / denominator as u128).min(u32::MAX as u128) as u32;
        *remainder = (total % denominator as u128) as u64;
        *value = value.saturating_add(whole);
    }

    /// The reduction of a congestion event or a timeout (RFC 9438 Figure 5, §4.7).
    pub fn reduce(&mut self, in_flight: u32, mss: u32) {
        let convergent = self.fast_convergence && self.window < self.maximum;
        self.maximum = if convergent {
            (self.window as u64 * (TCPCUBIC::BETA.1 + TCPCUBIC::BETA.0) / (2 * TCPCUBIC::BETA.1)) as u32
        } else {
            self.window
        };
        self.prior = self.window;
        let threshold = (in_flight as u64 * TCPCUBIC::BETA.0 / TCPCUBIC::BETA.1) as u32;
        self.threshold = threshold.max(2 * mss);
        self.epoch = None;
        self.window_remainder = 0;
        self.estimate_remainder = 0;
    }
}

impl TCPCongestionControl for TCPCUBIC {
    fn window(&self) -> u32 {
        self.window
    }

    fn threshold(&self) -> u32 {
        self.threshold
    }

    fn set_window(&mut self, window: u32) {
        self.window = window;
    }

    fn acknowledge(&mut self, acknowledged: u32, mss: u32, rtt: Duration, limited: bool, now: Instant) {
        let last = self.last.replace(now);
        if limited {
            // Time without growth is not part of t (RFC 9438 §5.8).
            if let (Some(epoch), Some(last)) = (self.epoch, last) {
                self.epoch = Some(epoch.saturating_add(now.saturating_duration_since(last)));
            }
            return;
        }
        if self.window < self.threshold {
            self.window = self.window.saturating_add(acknowledged.min(mss));
            return;
        }
        let epoch = match self.epoch {
            Some(epoch) => epoch,
            None => {
                self.epoch = Some(now);
                self.epoch_window = self.window;
                if self.after_timeout {
                    // After a timeout, W_max is cwnd_epoch and K is 0 (RFC 9438 §4.8).
                    self.maximum = self.window;
                }
                self.period = TCPCUBIC::period_for(self.maximum, self.window, mss);
                self.after_timeout = false;
                self.estimate = self.window;
                now
            }
        };
        let elapsed = now.saturating_duration_since(epoch);
        let window = self.window as u64;
        // W_est grows by α segments per window acknowledged; α is 1 once W_est reaches cwnd_prior (RFC 9438 §4.3).
        let (alpha, scale) = if self.estimate >= self.prior { (1, 1) } else { TCPCUBIC::ALPHA };
        TCPCUBIC::grow(
            &mut self.estimate,
            &mut self.estimate_remainder,
            acknowledged as u64 * mss as u64 * alpha,
            window * scale,
        );
        if self.cubic(elapsed, mss) < self.estimate as u64 {
            // The Reno-friendly region.
            self.window = self.estimate;
            return;
        }
        let target = self.cubic(elapsed.saturating_add(rtt), mss).clamp(window, window * 3 / 2);
        TCPCUBIC::grow(&mut self.window, &mut self.window_remainder, (target - window) * acknowledged as u64, window);
    }

    fn congestion(&mut self, in_flight: u32, mss: u32, ecn: bool, _now: Instant) {
        self.reduce(in_flight, mss);
        let minimum = if ecn { mss } else { 2 * mss };
        self.window = self.threshold.max(minimum);
    }

    fn timeout(&mut self, in_flight: u32, mss: u32, _now: Instant) {
        self.reduce(in_flight, mss);
        self.window = mss;
        self.after_timeout = true;
    }

    fn restart(&mut self, restart: u32, _now: Instant) {
        self.window = self.window.min(restart);
        self.epoch = None;
    }
}
