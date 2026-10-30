use alloc::vec::Vec;

use crate::auth::cert::key::{AlgorithmIdentifier, KeyLimits, SignatureAlgorithm};
use crate::codec::asn1::ASN1Time;

/// The inputs of the checks of a response (RFC 6960 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OCSPConfig {
    /// The time at which the status must be current and the certificate of
    /// a delegated responder valid. A fraction of a second is dropped, as
    /// the times of a response have none.
    pub time: ASN1Time,
    /// The nonce of the request, which the response must repeat (RFC 8954);
    /// `None` if the request had none.
    pub nonce: Option<Vec<u8>>,
    /// The largest keys of delegated responders accepted.
    pub key_limits: KeyLimits,
    /// Whether signatures that hash with SHA-1 are accepted.
    pub accept_sha1: bool,
    /// How long, in seconds, a status without `nextUpdate` is current after
    /// its `thisUpdate` (RFC 6960 §3.2, §4.2.2.1).
    pub lifetime_without_next_update: u64,
    /// The most signatures the search of a response's signer verifies.
    pub maximum_signatures: usize,
}

impl OCSPConfig {
    /// The default of `lifetime_without_next_update`: one day.
    pub const DEFAULT_LIFETIME: u64 = 24 * 60 * 60;
    /// The default of `maximum_signatures`: the CA's key and four candidate responders.
    pub const DEFAULT_MAXIMUM_SIGNATURES: usize = 9;

    /// The defaults at `time`: no nonce, the default key limits, SHA-1
    /// refused, a status without `nextUpdate` current for a day, and at most
    /// 9 signatures verified.
    pub fn new(time: ASN1Time) -> OCSPConfig {
        OCSPConfig {
            time,
            nonce: None,
            key_limits: KeyLimits::default(),
            accept_sha1: false,
            lifetime_without_next_update: OCSPConfig::DEFAULT_LIFETIME,
            maximum_signatures: OCSPConfig::DEFAULT_MAXIMUM_SIGNATURES,
        }
    }

    /// Whether a signature of `algorithm` is accepted: a known algorithm,
    /// and SHA-1 only with `accept_sha1`.
    pub fn accepts(&self, algorithm: &AlgorithmIdentifier<'_>) -> bool {
        SignatureAlgorithm::from_identifier(algorithm).is_ok_and(|algorithm| self.accept_sha1 || !algorithm.uses_sha1())
    }

    /// The time in whole seconds.
    pub fn second(&self) -> ASN1Time {
        ASN1Time { nanosecond: 0, ..self.time }
    }
}
