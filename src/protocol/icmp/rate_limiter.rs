use core::time::Duration;

use crate::runtime::Instant;

/// The parameters of an [`ICMPRateLimiter`]: a bucket of `burst` tokens,
/// one added every `interval`. The defaults are the example of RFC 4443
/// §2.4 (f) for a small device: bursts of 10, 10 a second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPRateLimitConfig {
    pub burst: u32,
    pub interval: Duration,
}

impl Default for ICMPRateLimitConfig {
    fn default() -> ICMPRateLimitConfig {
        ICMPRateLimitConfig { burst: 10, interval: Duration::from_millis(100) }
    }
}

/// The token bucket that limits the error messages a node originates (RFC
/// 4443 §2.4 (f), which requires it for ICMPv6; RFC 1812 §4.3.2.8 for ICMP):
/// each message takes a token; tokens come back at a fixed rate, up to the
/// burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ICMPRateLimiter {
    pub config: ICMPRateLimitConfig,
    pub tokens: u32,
    /// When the bucket last gained tokens.
    pub updated: Instant,
}

impl ICMPRateLimiter {
    /// A full bucket at `now`.
    pub fn new(config: ICMPRateLimitConfig, now: Instant) -> ICMPRateLimiter {
        ICMPRateLimiter { config, tokens: config.burst, updated: now }
    }

    /// Whether a message may be sent at `now`; takes its token if so.
    pub fn allow(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// Adds the tokens that came back by `now`.
    pub fn refill(&mut self, now: Instant) {
        let interval = self.config.interval.as_nanos().max(1);
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        let gained = elapsed / interval;
        if gained == 0 {
            return;
        }
        if gained >= (self.config.burst - self.tokens.min(self.config.burst)) as u128 {
            self.tokens = self.config.burst;
            self.updated = now;
        } else {
            self.tokens += gained as u32;
            let used = u64::try_from(gained * interval).unwrap_or(u64::MAX);
            self.updated = Instant::from_nanos(self.updated.as_nanos().saturating_add(used));
        }
    }
}
