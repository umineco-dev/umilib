use std::sync::OnceLock;
use std::time::Instant as StdInstant;

use crate::runtime::{Clock, Instant};

/// The system's monotonic clock (`std::time::Instant`), counted from the
/// first time any `MonotonicClock` is read in the process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonotonicClock;

impl MonotonicClock {
    pub const fn new() -> MonotonicClock {
        MonotonicClock
    }

    /// The origin of the clock's instants.
    pub fn origin() -> StdInstant {
        static ORIGIN: OnceLock<StdInstant> = OnceLock::new();
        *ORIGIN.get_or_init(StdInstant::now)
    }

    /// The runtime instant of a std instant (the origin if it is earlier).
    pub fn instant(at: StdInstant) -> Instant {
        let nanoseconds = at.saturating_duration_since(MonotonicClock::origin()).as_nanos();
        Instant::from_nanos(u64::try_from(nanoseconds).unwrap_or(u64::MAX))
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Instant {
        MonotonicClock::instant(StdInstant::now())
    }
}
