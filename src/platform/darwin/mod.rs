//! What Darwin (macOS, iOS) gives: the readiness poller on `kqueue`
//! ([`Poller`]) and the system's random bytes ([`Random`]). Compiled on
//! Darwin only.

mod poller;
mod random;
pub mod sys;

pub use poller::Poller;
pub use random::Random;
