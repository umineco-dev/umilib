use core::time::Duration;

use crate::hash::siphash::SipHash24;
use crate::protocol::ip::IPEndpoint;
use crate::runtime::Instant;
use crate::secret::Secret;

use super::TCPSequence;

/// The generator of initial sequence numbers of RFC 6528 (RFC 9293 §3.4.1):
/// ISN = M + F(local address, local port, remote address, remote port, key),
/// where M is a timer that ticks every 4 microseconds (MUST-8) and F is
/// SipHash-2-4 under a secret key, which cannot be computed from outside
/// (MUST-9). The key comes from a source of random bytes, such as
/// `crypto::random`, and should be drawn again from time to time.
pub struct TCPISNGenerator {
    pub key: Secret<[u8; 16]>,
}

impl TCPISNGenerator {
    /// The period of the timer M (RFC 9293 §3.4.1).
    pub const TICK: Duration = Duration::from_micros(4);

    pub fn new(key: [u8; 16]) -> TCPISNGenerator {
        TCPISNGenerator { key: Secret::new(key) }
    }

    /// The initial sequence number of a connection between `local` and `remote` opened at `now`.
    pub fn generate(&self, local: IPEndpoint, remote: IPEndpoint, now: Instant) -> TCPSequence {
        let ticks = (now.as_nanos() / TCPISNGenerator::TICK.as_nanos() as u64) as u32;
        let mut hash = SipHash24::new(self.key.expose());
        hash.update(local.address.octets());
        hash.update(&local.port.to_be_bytes());
        hash.update(remote.address.octets());
        hash.update(&remote.port.to_be_bytes());
        let output = hash.output();
        TCPSequence(ticks.wrapping_add(u32::from_le_bytes([output[0], output[1], output[2], output[3]])))
    }
}
