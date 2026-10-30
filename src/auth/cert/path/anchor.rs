use super::{PathError, PathErrorReason};
use crate::auth::cert::key::{KeyLimits, PublicKey};
use crate::auth::cert::x509::{Certificate, Name, NameConstraints, X509Error};

/// A trust anchor (RFC 5280 §6.1.1 (d)): the name and key of a trusted CA,
/// with the name constraints the relying party puts on it, and the
/// certificate it came from, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub name: Name<'static>,
    pub public_key: PublicKey,
    /// Constraints on the names of every path from the anchor (RFC 5280 §6.2).
    pub name_constraints: Option<NameConstraints<'static>>,
    /// The certificate of the anchor; with a profile beyond the algorithm,
    /// its validity, basic constraints, key usage and critical extensions
    /// are checked like those of a CA in the path.
    pub certificate: Option<Certificate<'static>>,
}

impl TrustAnchor {
    /// The anchor of a name and a key.
    pub const fn new(name: Name<'static>, public_key: PublicKey) -> TrustAnchor {
        TrustAnchor { name, public_key, name_constraints: None, certificate: None }
    }

    /// The anchor of a certificate (usually self-signed): its subject, its
    /// key (within `limits`) and its name constraints extension, which RFC
    /// 5280 §6.2 lets relying parties honour, and which this one does.
    pub fn from_certificate(certificate: Certificate<'static>, limits: &KeyLimits) -> Result<TrustAnchor, PathError> {
        let error = |reason| PathError::new(0, reason);
        let tbs = certificate.tbs_certificate();
        let public_key = PublicKey::from_info_with_limits(&tbs.subject_public_key_info, limits)
            .map_err(|key| error(PathErrorReason::Key(key)))?;
        let name_constraints = tbs
            .extensions
            .typed::<NameConstraints<'_>>()
            .map_err(|failure: X509Error| error(PathErrorReason::Certificate(failure)))?
            .map(NameConstraints::into_owned);
        let name = tbs.subject.clone().into_owned();
        Ok(TrustAnchor { name, public_key, name_constraints, certificate: Some(certificate) })
    }
}
