//! The Secure Remote Password protocol SRP-6a as RFC 5054 defines it for
//! TLS: a client that knows a password and a server that stores only a
//! verifier of it agree on a premaster secret.
//!
//! [`SRP`] computes the values of section 2 (the multiplier k, the private
//! key x and the verifier v) in an [`SRPGroup`] of appendix A with a hash
//! function `H` (SHA-1 in RFC 5054). [`SRPClient`] and [`SRPServer`] hold
//! the secret exponents a and b and compute the premaster secret of section
//! 2.6, after the checks of sections 2.5.3 and 2.5.4 (A % N ≠ 0, B % N ≠ 0)
//! and of SRP-6a (u ≠ 0). Integers are converted to bytes most significant
//! first: without leading zeros, or padded to the bytes of N by PAD().

mod client;
mod group;
mod groups;
mod server;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod srp;

pub use client::SRPClient;
pub use group::SRPGroup;
pub use groups::{SRP1024, SRP1536, SRP2048, SRP3072, SRP4096, SRP6144, SRP8192};
pub use server::SRPServer;
pub use srp::SRP;
