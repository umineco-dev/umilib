use super::Digest;
use crate::secret::Zeroize;

/// A [`Digest`] designed as a cryptographic hash function, which the
/// constructions of [`crate::crypto`] (HMAC, the DRBGs) require, so that a
/// checksum such as xxHash or a keyed hash such as SipHash cannot be used in
/// their place. Its state can be zeroized.
///
/// Designed is not the same as secure: collisions of MD4, MD5 and SHA-1 can
/// be computed, so use them only where a protocol requires them (HMAC-MD5 and
/// HMAC-SHA-1 are still sound as MACs).
pub trait CryptographicDigest: Digest + Zeroize {}
