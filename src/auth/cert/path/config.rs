use alloc::vec::Vec;

use super::ServiceIdentity;
use crate::auth::cert::key::KeyLimits;
use crate::auth::cert::x509::{KeyUsage, NameConstraints};
use crate::codec::asn1::{ASN1Time, ObjectIdentifier};

/// Which requirements a path must meet beyond the algorithm of RFC 5280 §6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathProfile {
    /// The algorithm of RFC 5280 §6.1 (with the policy graph of RFC 9618)
    /// alone, as RFC 5280 recommends: certificates are not checked against
    /// the profile of RFC 5280 §4.
    Algorithm,
    /// The algorithm, and the requirements of the profile of RFC 5280 §4
    /// that a relying party can check: extensions marked critical or not as
    /// required, key identifiers present, names well formed, a key usage
    /// consistent with the basic constraints, and the trust anchor's own
    /// certificate valid and a CA.
    RFC5280,
    /// The profile of RFC 5280, and the rules the Web PKI adds (CA/Browser
    /// Forum Baseline Requirements): v3 certificates only, an extended key
    /// usage in the target without anyExtendedKeyUsage, the purpose asked
    /// for in the extended key usage of every certificate that has one
    /// (intermediates restrict their subordinates), a target that is not a
    /// CA, and RSA keys of at least 2048 bits whose size is a multiple of 8.
    WebPKI,
}

/// How certificates are checked against CRLs (RFC 5280 §6.3) and the other
/// revocation sources of the validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevocationConfig {
    /// Whether certificates are checked against the CRLs and sources given.
    pub check: bool,
    /// Whether a certificate no CRL nor source covers fails (`RevocationUnknown`);
    /// otherwise its status is left undetermined and the path is accepted.
    pub require: bool,
    /// Whether delta CRLs are applied to the complete CRLs they update (`use-deltas`, §6.3.1).
    pub use_deltas: bool,
    /// How long, in seconds, a CRL or a status without `nextUpdate` is
    /// current after its `thisUpdate`. Without `nextUpdate` newer
    /// information is available at any time (RFC 6960 §4.2.2.1), so such a
    /// status must be recent (RFC 6960 §3.2).
    pub lifetime_without_next_update: u64,
}

impl RevocationConfig {
    /// The default of `lifetime_without_next_update`: one day.
    pub const DEFAULT_LIFETIME: u64 = 24 * 60 * 60;
    /// No revocation checking.
    pub const NONE: RevocationConfig = RevocationConfig {
        check: false,
        require: false,
        use_deltas: false,
        lifetime_without_next_update: RevocationConfig::DEFAULT_LIFETIME,
    };
    /// Every certificate must be covered by a CRL or a source given; delta CRLs are applied.
    pub const REQUIRED: RevocationConfig = RevocationConfig {
        check: true,
        require: true,
        use_deltas: true,
        lifetime_without_next_update: RevocationConfig::DEFAULT_LIFETIME,
    };

    /// Whether a status issued at `this_update`, with `next_update` if
    /// any, is current at `time`: issued, and not past `next_update`, or
    /// without one not older than `lifetime_without_next_update`.
    pub fn is_current(&self, this_update: ASN1Time, next_update: Option<ASN1Time>, time: ASN1Time) -> bool {
        let expiry = match next_update {
            Some(next_update) => next_update.to_unix_seconds(),
            None => this_update.to_unix_seconds().saturating_add_unsigned(self.lifetime_without_next_update),
        };
        this_update <= time && time.to_unix_seconds() <= expiry
    }
}

/// The inputs of path validation (RFC 5280 §6.1.1) and the limits of path building.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathConfig {
    /// The time at which the path must be valid.
    pub time: ASN1Time,
    pub profile: PathProfile,
    /// `user-initial-policy-set`; `None` is any-policy.
    pub initial_policy_set: Option<Vec<ObjectIdentifier<'static>>>,
    pub initial_explicit_policy: bool,
    pub initial_policy_mapping_inhibit: bool,
    pub initial_any_policy_inhibit: bool,
    /// `initial-permitted-subtrees` and `initial-excluded-subtrees`, if any.
    pub initial_name_constraints: Option<NameConstraints<'static>>,
    /// The most intermediate certificates a path may have between the
    /// target and the trust anchor, not counting self-issued ones (which
    /// renew a CA's key, and which path length constraints do not count either).
    pub maximum_intermediates: usize,
    /// The most signatures path building verifies before it gives up.
    pub maximum_signatures: usize,
    /// The most comparisons of a name with a name constraint a path may
    /// take, which bounds the work of certificates with many names and
    /// constraints (quadratic otherwise).
    pub maximum_name_checks: usize,
    /// The largest keys accepted.
    pub key_limits: KeyLimits,
    /// Whether signatures that hash with SHA-1 are accepted.
    pub accept_sha1: bool,
    pub revocation: RevocationConfig,
    /// The key usages the target's key must allow, if its certificate has the extension.
    pub key_usage: Option<KeyUsage>,
    /// The purpose the target's extended key usage must allow, if it has the extension
    /// (with [`PathProfile::WebPKI`], it must have it).
    pub extended_key_usage: Option<ObjectIdentifier<'static>>,
    /// The identity the target must name (RFC 9525).
    pub identity: Option<ServiceIdentity>,
}

impl PathConfig {
    /// The defaults at `time`: the profile of RFC 5280, any policy with
    /// policy processing on and nothing inhibited, no name constraints, at
    /// most 8 intermediate certificates, 100 signatures and 2^20 name
    /// comparisons, SHA-1 refused,
    /// no revocation checking, and no usage, purpose or identity asked for.
    pub fn new(time: ASN1Time) -> PathConfig {
        PathConfig {
            time,
            profile: PathProfile::RFC5280,
            initial_policy_set: None,
            initial_explicit_policy: false,
            initial_policy_mapping_inhibit: false,
            initial_any_policy_inhibit: false,
            initial_name_constraints: None,
            maximum_intermediates: 8,
            maximum_signatures: 100,
            maximum_name_checks: 1 << 20,
            key_limits: KeyLimits::default(),
            accept_sha1: false,
            revocation: RevocationConfig::NONE,
            key_usage: None,
            extended_key_usage: None,
            identity: None,
        }
    }

    /// The validation of a TLS server at `time` named `identity`: the Web
    /// PKI profile and the purpose `id-kp-serverAuth`.
    pub fn web_pki_server(time: ASN1Time, identity: ServiceIdentity) -> PathConfig {
        PathConfig {
            profile: PathProfile::WebPKI,
            extended_key_usage: Some(crate::auth::cert::x509::ExtendedKeyUsage::SERVER_AUTH),
            identity: Some(identity),
            ..PathConfig::new(time)
        }
    }
}
