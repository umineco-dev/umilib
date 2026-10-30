use core::time::Duration;

/// The retransmission timer of RFC 6298: the smoothed round-trip time and
/// its variation, the retransmission timeout (RTO) computed from them, and
/// its exponential backoff. RTT samples follow Karn's algorithm (RFC 9293
/// MUST-18): the caller takes none from a retransmitted segment unless
/// timestamps tell them apart (RFC 7323 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPRetransmissionTimer {
    /// SRTT, once a sample was taken.
    pub smoothed: Option<Duration>,
    /// RTTVAR.
    pub variation: Duration,
    /// The RTO before backoff.
    pub timeout: Duration,
    /// How many times the RTO was doubled since the last sample (RFC 6298 (5.5)).
    pub backoff: u32,
    /// The lower bound of the RTO (RFC 6298 (2.4)).
    pub minimum: Duration,
    /// The upper bound of the RTO, at least 60 seconds (RFC 6298 (2.5)).
    pub maximum: Duration,
    /// G, the granularity of the clock (RFC 6298 §2).
    pub granularity: Duration,
}

impl TCPRetransmissionTimer {
    /// The RTO a lost SYN leaves for the data (RFC 6298 (5.7)).
    pub const SYN_LOSS_TIMEOUT: Duration = Duration::from_secs(3);

    /// A timer of RTO `initial` (RFC 6298 (2.1): 1 second) before any sample.
    pub fn new(
        initial: Duration,
        minimum: Duration,
        maximum: Duration,
        granularity: Duration,
    ) -> TCPRetransmissionTimer {
        TCPRetransmissionTimer {
            smoothed: None,
            variation: Duration::ZERO,
            timeout: initial.clamp(minimum, maximum.max(minimum)),
            backoff: 0,
            minimum,
            maximum: maximum.max(minimum),
            granularity,
        }
    }

    /// Takes the sample `rtt` (RFC 6298 (2.2), (2.3)) and ends the backoff.
    pub fn sample(&mut self, rtt: Duration) {
        match self.smoothed {
            None => {
                self.smoothed = Some(rtt);
                self.variation = rtt / 2;
            }
            Some(smoothed) => {
                // RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R'|, then SRTT = 7/8 SRTT + 1/8 R'.
                let difference = smoothed.abs_diff(rtt);
                self.variation = (self.variation * 3 + difference) / 4;
                self.smoothed = Some((smoothed * 7 + rtt) / 8);
            }
        }
        let smoothed = self.smoothed.unwrap_or(rtt);
        let variation = (self.variation * 4).max(self.granularity);
        self.timeout = smoothed.saturating_add(variation).clamp(self.minimum, self.maximum);
        self.backoff = 0;
    }

    /// The timer expired: the RTO doubles, up to the maximum (RFC 6298 (5.5)).
    pub fn expire(&mut self) {
        self.backoff = self.backoff.saturating_add(1);
    }

    /// The RTO after a lost SYN, once data is sent: at least 3 seconds
    /// unless a sample was taken (RFC 6298 (5.7)).
    pub fn restore_after_syn_loss(&mut self) {
        if self.smoothed.is_none() {
            self.timeout = self.timeout.max(TCPRetransmissionTimer::SYN_LOSS_TIMEOUT).min(self.maximum);
        }
        self.backoff = 0;
    }

    /// The current RTO, backoff included.
    pub fn current(&self) -> Duration {
        let factor = 1u32.checked_shl(self.backoff.min(31)).unwrap_or(u32::MAX);
        self.timeout.saturating_mul(factor).min(self.maximum)
    }
}
