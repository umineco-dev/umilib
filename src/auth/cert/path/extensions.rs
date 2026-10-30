use super::PathErrorReason;
use crate::auth::cert::x509::{
    AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints, CRLDistributionPoints, Certificate,
    CertificatePolicies, ExtendedKeyUsage, ExtensionValue, FreshestCRL, InhibitAnyPolicy, IssuerAlternativeName,
    KeyUsage, NameConstraints, PolicyConstraints, PolicyMappings, SubjectAlternativeName, SubjectInformationAccess,
    SubjectKeyIdentifier,
};
use crate::codec::asn1::ObjectIdentifier;

/// The extensions of a certificate that path validation processes,
/// decoded once. Every one of them must decode, and a critical extension
/// of another type is refused (RFC 5280 §6.1.4 (o), §6.1.5 (f)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathExtensions<'c> {
    pub basic_constraints: Option<BasicConstraints>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<ExtendedKeyUsage<'c>>,
    pub certificate_policies: Option<CertificatePolicies<'c>>,
    pub policy_mappings: Option<PolicyMappings<'c>>,
    pub policy_constraints: Option<PolicyConstraints>,
    pub inhibit_any_policy: Option<InhibitAnyPolicy>,
    pub name_constraints: Option<NameConstraints<'c>>,
    pub subject_alternative_name: Option<SubjectAlternativeName<'c>>,
    pub authority_key_identifier: Option<AuthorityKeyIdentifier<'c>>,
    pub subject_key_identifier: Option<SubjectKeyIdentifier<'c>>,
}

impl<'c> PathExtensions<'c> {
    /// The extension types processed (or, for the access and distribution
    /// point extensions, recognized and harmless when critical).
    pub const RECOGNIZED: [ObjectIdentifier<'static>; 16] = [
        BasicConstraints::OID,
        KeyUsage::OID,
        ExtendedKeyUsage::OID,
        CertificatePolicies::OID,
        PolicyMappings::OID,
        PolicyConstraints::OID,
        InhibitAnyPolicy::OID,
        NameConstraints::OID,
        SubjectAlternativeName::OID,
        IssuerAlternativeName::OID,
        AuthorityKeyIdentifier::OID,
        SubjectKeyIdentifier::OID,
        CRLDistributionPoints::OID,
        FreshestCRL::OID,
        AuthorityInformationAccess::OID,
        SubjectInformationAccess::OID,
    ];

    /// Decodes the extensions of `certificate`; fails with the error of an
    /// extension that does not decode, or `UnknownCriticalExtension`.
    pub fn decode(certificate: &'c Certificate<'_>) -> Result<PathExtensions<'c>, PathErrorReason> {
        let extensions = &certificate.tbs_certificate().extensions;
        if extensions
            .entries
            .iter()
            .any(|extension| extension.critical && !PathExtensions::RECOGNIZED.contains(&extension.oid))
        {
            return Err(PathErrorReason::UnknownCriticalExtension);
        }
        let failed = PathErrorReason::Certificate;
        // The recognized extensions that are not kept must decode too.
        extensions.typed::<IssuerAlternativeName<'_>>().map_err(failed)?;
        extensions.typed::<CRLDistributionPoints<'_>>().map_err(failed)?;
        extensions.typed::<FreshestCRL<'_>>().map_err(failed)?;
        extensions.typed::<AuthorityInformationAccess<'_>>().map_err(failed)?;
        extensions.typed::<SubjectInformationAccess<'_>>().map_err(failed)?;
        Ok(PathExtensions {
            basic_constraints: extensions.typed().map_err(failed)?,
            key_usage: extensions.typed().map_err(failed)?,
            extended_key_usage: extensions.typed().map_err(failed)?,
            certificate_policies: extensions.typed().map_err(failed)?,
            policy_mappings: extensions.typed().map_err(failed)?,
            policy_constraints: extensions.typed().map_err(failed)?,
            inhibit_any_policy: extensions.typed().map_err(failed)?,
            name_constraints: extensions.typed().map_err(failed)?,
            subject_alternative_name: extensions.typed().map_err(failed)?,
            authority_key_identifier: extensions.typed().map_err(failed)?,
            subject_key_identifier: extensions.typed().map_err(failed)?,
        })
    }

    /// Whether the certificate asserts that it is a CA.
    pub fn is_ca(&self) -> bool {
        self.basic_constraints.is_some_and(|constraints| constraints.ca)
    }
}
