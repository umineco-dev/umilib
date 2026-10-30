//! The Dragonfly key exchange of RFC 7664 over elliptic curves: two peers
//! that share a password authenticate each other and agree on a key.
//!
//! RFC 7664 leaves the random function H, the key derivation function KDF
//! and the encodings to the protocol that uses it. [`Dragonfly`] fixes them
//! as follows, with a hash function `H`:
//! - H is `H`, and KDF-n(k, label) is the counter mode of SP 800-108 with
//!   HMAC-`H` keyed with k, a 32-bit counter and the fixed input
//!   label || 0x00 || \[n\]_32 (see [`Dragonfly::kdf`]);
//! - the password element is found by the hunting and pecking of section
//!   3.2.1, always with at least [`DragonflyConfig::iterations`] rounds, the
//!   residuosity tested in constant time;
//! - identities are ordered as byte strings; a scalar is big-endian of the
//!   bytes of the order and an element is the uncompressed SEC 1 point;
//! - kck and mk each have the bytes of p.
//!
//! [`DragonflyPeer`] runs one side: the commit exchange (section 3.3) and
//! the confirm exchange (section 3.4).

mod config;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod dragonfly;
mod peer;

pub use config::DragonflyConfig;
pub use dragonfly::Dragonfly;
pub use peer::{DragonflyCommit, DragonflyPeer};
