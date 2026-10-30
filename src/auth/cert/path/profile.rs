use super::{NameMatching, PathErrorReason, PathExtensions, PathProfile};
use crate::auth::cert::key::{KeyAlgorithm, PublicKey};
use crate::auth::cert::x509::{
    AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints, Certificate, ExtendedKeyUsage, Extension,
    ExtensionValue, FreshestCRL, GeneralName, InhibitAnyPolicy, KeyUsage, NameConstraints, PolicyConstraints,
    SubjectAlternativeName, SubjectInformationAccess, SubjectKeyIdentifier, Version,
};
use crate::codec::asn1::ObjectIdentifier;
use crate::crypto::rsa::RSAPublicKey;

/// The place of a certificate in a path, which the profile checks depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertificateRole {
    /// The certificate validated (certificate n of RFC 5280 §6.1).
    Target,
    /// A certificate between the target and the trust anchor.
    Intermediate,
    /// The certificate of the trust anchor.
    Anchor,
}

impl PathProfile {
    /// The key usages a key of `algorithm` may have and the ones it must
    /// have one of, when the extension is present: RFC 4055 §1.2 (RSASSA-PSS
    /// keys), RFC 8410 §5 (EdDSA, XDH), RFC 9881 §5 (ML-DSA), RFC 9909 §6
    /// (SLH-DSA), RFC 9935 §5 (ML-KEM). RSA and EC keys have no such rule.
    pub fn key_usages(algorithm: &KeyAlgorithm, ca: bool) -> (KeyUsage, KeyUsage) {
        let signing =
            KeyUsage::DIGITAL_SIGNATURE | KeyUsage::CONTENT_COMMITMENT | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN;
        match algorithm {
            KeyAlgorithm::RSAPSS(_) => (signing, signing),
            KeyAlgorithm::MLDSA(_) | KeyAlgorithm::SLHDSA(_) | KeyAlgorithm::HashSLHDSA(_) => (signing, signing),
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 if ca => (KeyUsage::ALL, signing),
            KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => {
                (KeyUsage::ALL, KeyUsage::DIGITAL_SIGNATURE | KeyUsage::CONTENT_COMMITMENT)
            }
            KeyAlgorithm::X25519 | KeyAlgorithm::X448 => {
                (KeyUsage::KEY_AGREEMENT | KeyUsage::ENCIPHER_ONLY | KeyUsage::DECIPHER_ONLY, KeyUsage::KEY_AGREEMENT)
            }
            KeyAlgorithm::MLKEM(_) => (KeyUsage::KEY_ENCIPHERMENT, KeyUsage::KEY_ENCIPHERMENT),
            KeyAlgorithm::RSA | KeyAlgorithm::EC(_) => (KeyUsage::ALL, KeyUsage::ALL),
        }
    }

    /// Whether the critical flag of `extension` is the one RFC 5280
    /// requires: authority and subject key identifiers, access, freshest
    /// CRL and subject directory attributes non-critical; name and policy
    /// constraints and inhibit anyPolicy critical; basic constraints
    /// critical in a CA certificate whose key signs certificates.
    pub fn has_required_criticality(extension: &Extension<'_>, signs_certificates: bool) -> bool {
        let oid = &extension.oid;
        let non_critical: [ObjectIdentifier<'static>; 6] = [
            AuthorityKeyIdentifier::OID,
            SubjectKeyIdentifier::OID,
            AuthorityInformationAccess::OID,
            SubjectInformationAccess::OID,
            FreshestCRL::OID,
            crate::auth::cert::x509::SubjectDirectoryAttributes::OID,
        ];
        let critical: [ObjectIdentifier<'static>; 3] =
            [NameConstraints::OID, PolicyConstraints::OID, InhibitAnyPolicy::OID];
        if non_critical.contains(oid) {
            return !extension.critical;
        }
        if critical.contains(oid) {
            return extension.critical;
        }
        if *oid == BasicConstraints::OID && signs_certificates {
            return extension.critical;
        }
        true
    }

    /// Whether the subject alternative names are well formed (RFC 5280
    /// §4.2.1.6): DNS names of the preferred name syntax (a wildcard first
    /// label allowed), mailboxes, URIs with a scheme, and none empty.
    pub fn has_well_formed_names(names: &SubjectAlternativeName<'_>) -> bool {
        names.names.iter().all(|name| match name {
            GeneralName::DNSName(name) => NameMatching::is_dns_name(name, true),
            GeneralName::RFC822Name(address) => NameMatching::mailbox(address).is_some(),
            GeneralName::URI(uri) => uri.split_once(':').is_some_and(|(scheme, _)| !scheme.is_empty()),
            _ => true,
        })
    }

    /// Checks `certificate` against the profile, beyond what reading it
    /// checked. `self_signed` is whether its signature verifies under its own key.
    pub fn check(
        self,
        certificate: &Certificate<'_>,
        extensions: &PathExtensions<'_>,
        key: &PublicKey,
        role: CertificateRole,
        self_signed: bool,
    ) -> Result<(), PathErrorReason> {
        if self == PathProfile::Algorithm {
            return Ok(());
        }
        let refused = Err(PathErrorReason::Profile);
        let tbs = certificate.tbs_certificate();
        let ca = extensions.is_ca();
        let usage = extensions.key_usage;
        let signs_certificates = usage.is_none_or(|usage| usage.contains(KeyUsage::KEY_CERT_SIGN));
        // §4.1.2.2, §4.1.2.4, §4.1.2.6: serial number, issuer and subject. A trust anchor is
        // trusted out of band (§6.2): the rules on how CAs issue its serial number do not apply.
        let anchor = role == CertificateRole::Anchor;
        if (!anchor && !tbs.serial_number.is_conforming()) || tbs.issuer.is_empty() || (ca && tbs.subject.is_empty()) {
            return refused;
        }
        // §4.2: the criticality each extension requires.
        if !tbs
            .extensions
            .entries
            .iter()
            .all(|extension| PathProfile::has_required_criticality(extension, ca && signs_certificates))
        {
            return refused;
        }
        // §4.2.1.1: an authority key identifier with a key identifier, but in self-signed
        // certificates and trust anchors, which end the path it helps to build.
        let identifier =
            extensions.authority_key_identifier.as_ref().and_then(|identifier| identifier.key_identifier.as_ref());
        if identifier.is_none() && !self_signed && !anchor {
            return refused;
        }
        // §4.2.1.2: a subject key identifier in CA certificates.
        if ca && extensions.subject_key_identifier.is_none() {
            return refused;
        }
        // §4.2.1.3, §4.2.1.9: keyCertSign only with cA, cA only with keyCertSign, pathLenConstraint only with both.
        let cert_sign = usage.is_some_and(|usage| usage.contains(KeyUsage::KEY_CERT_SIGN));
        if (cert_sign && !ca) || (ca && usage.is_some() && !cert_sign) {
            return refused;
        }
        let path_length = extensions.basic_constraints.is_some_and(|constraints| constraints.path_length.is_some());
        if path_length && (!ca || !signs_certificates) {
            return refused;
        }
        // The key usages the algorithm of the key allows.
        if let Some(usage) = usage {
            let (allowed, required) = PathProfile::key_usages(key.algorithm(), ca);
            if !allowed.contains(usage) || usage.bits & required.bits == 0 {
                return refused;
            }
        }
        // §4.2.1.10: name constraints only in CA certificates.
        if extensions.name_constraints.is_some() && !ca {
            return refused;
        }
        // §4.1.2.6, §4.2.1.6: an empty subject needs critical, well-formed alternative names.
        let alternative = tbs.extensions.get(&SubjectAlternativeName::OID);
        if tbs.subject.is_empty() && !alternative.is_some_and(|extension| extension.critical) {
            return refused;
        }
        if let Some(names) = &extensions.subject_alternative_name
            && !PathProfile::has_well_formed_names(names)
        {
            return refused;
        }
        if self == PathProfile::WebPKI {
            self.check_web_pki(certificate, extensions, key, role)?;
        }
        Ok(())
    }

    /// The rules the Web PKI adds (CA/Browser Forum Baseline Requirements).
    pub fn check_web_pki(
        self,
        certificate: &Certificate<'_>,
        extensions: &PathExtensions<'_>,
        key: &PublicKey,
        role: CertificateRole,
    ) -> Result<(), PathErrorReason> {
        let refused = Err(PathErrorReason::Profile);
        let tbs = certificate.tbs_certificate();
        // §7.1.1: v3 only.
        if tbs.version != Version::V3 {
            return refused;
        }
        // §6.1.5: RSA keys of at least 2048 bits, a multiple of 8.
        if let Ok(rsa) = key.typed::<RSAPublicKey>() {
            let bits = rsa.bits();
            if bits < 2048 || bits % 8 != 0 {
                return refused;
            }
        }
        match role {
            CertificateRole::Target => {
                // §7.1.2.7: a subscriber certificate is not a CA, has no critical extended key usage,
                // and has a non-critical subject alternative name with a subject. The common name is
                // not checked: RFC 9525 §6.3 does not use it for identity.
                if extensions.is_ca() {
                    return refused;
                }
                // §7.1.2.7.6, §7.1.2.7.10: an extended key usage, not critical, without anyExtendedKeyUsage.
                let usage = tbs.extensions.get(&ExtendedKeyUsage::OID);
                if usage.is_none_or(|extension| extension.critical) {
                    return refused;
                }
                if extensions.extended_key_usage.as_ref().is_some_and(|usage| usage.contains(&ExtendedKeyUsage::ANY)) {
                    return refused;
                }
                let alternative = tbs.extensions.get(&SubjectAlternativeName::OID);
                if !tbs.subject.is_empty() && alternative.is_some_and(|extension| extension.critical) {
                    return refused;
                }
            }
            CertificateRole::Anchor => {
                // §7.1.2.1: a root has no extended key usage, and an authority key identifier,
                // if any, is its own subject key identifier alone.
                if extensions.extended_key_usage.is_some() {
                    return refused;
                }
                if let Some(identifier) = &extensions.authority_key_identifier {
                    let own = extensions.subject_key_identifier.as_ref().map(|subject| &subject.key_identifier);
                    if identifier.authority_cert_issuer.is_some()
                        || identifier.key_identifier.is_none()
                        || identifier.key_identifier.as_ref() != own
                    {
                        return refused;
                    }
                }
            }
            CertificateRole::Intermediate => {}
        }
        Ok(())
    }
}
