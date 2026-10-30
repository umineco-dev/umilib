use core::fmt;

use crate::auth::cert::key::KeyError;
use crate::auth::cert::x509::{CRLReason, X509Error};

/// Why a certification path is refused, for the certificate at `index` of
/// the path (0 for the target, increasing toward the trust anchor), or for
/// the trust anchor itself when the index is the length of the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathError {
    pub index: usize,
    pub reason: PathErrorReason,
}

/// What is wrong with the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathErrorReason {
    /// No path from the target to a trust anchor could be built.
    NoPath,
    /// The issuer's name does not match the name of the next certificate's subject (§6.1.3 (a)(4)).
    NameChaining,
    /// The signature does not verify under the issuer's key (§6.1.3 (a)(1)).
    Signature,
    /// The time is outside the validity period (§6.1.3 (a)(2)).
    Validity,
    /// The certificate is revoked (§6.1.3 (a)(3), §6.3).
    Revoked(CRLReason),
    /// No CRL nor revocation source covers the certificate, and revocation
    /// checking is required (§6.3.3).
    RevocationUnknown,
    /// A CRL in scope for the certificate that cannot be used: malformed,
    /// with a critical extension not processed, or without a valid signer.
    InvalidCRL,
    /// A revocation source answers for the certificate with a status that
    /// cannot be used: an OCSP response without a valid signer, for one.
    InvalidResponse,
    /// A name outside the permitted subtrees or within the excluded ones,
    /// or one the constraints cannot be applied to (§6.1.3 (b), (c)).
    NameConstraints,
    /// No valid policy (§6.1.3 (f), §6.1.5), or a mapping of anyPolicy (§6.1.4 (a)).
    Policy,
    /// An intermediate certificate that is not a CA (§6.1.4 (k)).
    NotCA,
    /// More intermediate certificates than a path length constraint allows (§6.1.4 (l)).
    PathLength,
    /// A key usage that does not allow the certificate's role (§6.1.4 (n), or the usage asked for).
    KeyUsage,
    /// An extended key usage that does not allow the purpose asked for.
    ExtendedKeyUsage,
    /// A critical extension this module does not process (§6.1.4 (o), §6.1.5 (f)).
    UnknownCriticalExtension,
    /// A signature algorithm or key the configuration does not accept.
    Algorithm,
    /// The key or the signature algorithm is refused.
    Key(KeyError),
    /// An extension does not decode, or the certificate breaks the profile asked for.
    Certificate(X509Error),
    /// The certificate breaks a requirement of the profile of the configuration.
    Profile,
    /// The target does not name the identity asked for.
    Identity,
    /// The path is longer than the configuration allows.
    Depth,
    /// Building paths took more work than the configuration allows.
    Work,
}

impl PathError {
    pub const fn new(index: usize, reason: PathErrorReason) -> PathError {
        PathError { index, reason }
    }
}

impl fmt::Display for PathErrorReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathErrorReason::NoPath => formatter.write_str("no path to a trust anchor"),
            PathErrorReason::NameChaining => formatter.write_str("the issuer name does not match"),
            PathErrorReason::Signature => formatter.write_str("the signature does not verify"),
            PathErrorReason::Validity => formatter.write_str("outside the validity period"),
            PathErrorReason::Revoked(reason) => write!(formatter, "revoked ({reason:?})"),
            PathErrorReason::RevocationUnknown => formatter.write_str("the revocation status is unknown"),
            PathErrorReason::InvalidCRL => formatter.write_str("a CRL in scope cannot be used"),
            PathErrorReason::InvalidResponse => formatter.write_str("a revocation status cannot be used"),
            PathErrorReason::NameConstraints => formatter.write_str("a name breaks the name constraints"),
            PathErrorReason::Policy => formatter.write_str("no valid certificate policy"),
            PathErrorReason::NotCA => formatter.write_str("an intermediate certificate is not a CA"),
            PathErrorReason::PathLength => formatter.write_str("the path length constraint is exceeded"),
            PathErrorReason::KeyUsage => formatter.write_str("the key usage does not allow the use"),
            PathErrorReason::ExtendedKeyUsage => {
                formatter.write_str("the extended key usage does not allow the purpose")
            }
            PathErrorReason::UnknownCriticalExtension => formatter.write_str("an unknown critical extension"),
            PathErrorReason::Algorithm => formatter.write_str("an algorithm or key the configuration refuses"),
            PathErrorReason::Key(error) => write!(formatter, "{error}"),
            PathErrorReason::Certificate(error) => write!(formatter, "{error}"),
            PathErrorReason::Profile => formatter.write_str("the certificate breaks the profile"),
            PathErrorReason::Identity => formatter.write_str("the certificate does not name the identity"),
            PathErrorReason::Depth => formatter.write_str("the path is too long"),
            PathErrorReason::Work => formatter.write_str("path building took too much work"),
        }
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "certificate {}: {}", self.index, self.reason)
    }
}

impl core::error::Error for PathError {}
