use super::super::SASLMechanism;
use crate::hash::CryptographicDigest;

/// A hash function SCRAM is registered with (the IANA SASL registry):
/// SHA-1 (RFC 5802) and SHA-256 (RFC 7677).
pub trait SCRAMHash: CryptographicDigest + Default {
    /// The mechanism without channel binding, and its `-PLUS` variant.
    const MECHANISM: SASLMechanism;
    const PLUS_MECHANISM: SASLMechanism;
}

#[cfg(umilib_feature = "hash-sha-v1")]
impl SCRAMHash for crate::hash::sha::v1::SHA1 {
    const MECHANISM: SASLMechanism = SASLMechanism::SCRAMSHA1;
    const PLUS_MECHANISM: SASLMechanism = SASLMechanism::SCRAMSHA1PLUS;
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl SCRAMHash for crate::hash::sha::v2::SHA256 {
    const MECHANISM: SASLMechanism = SASLMechanism::SCRAMSHA256;
    const PLUS_MECHANISM: SASLMechanism = SASLMechanism::SCRAMSHA256PLUS;
}
