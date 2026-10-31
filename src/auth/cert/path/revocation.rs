use alloc::vec::Vec;
use core::fmt;

use super::{PathBudget, PathConfig, PathErrorReason, PathProfile, PathValidator, TrustAnchor};
use crate::auth::cert::key::{PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{
    AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints, CRLDistributionPoints, CRLNumber, CRLReason,
    Certificate, CertificateIssuer, CertificateList, DeltaCRLIndicator, DistributionPoint, DistributionPointName,
    ExtensionValue, Extensions, FreshestCRL, GeneralName, HoldInstructionCode, InvalidityDate, IssuerAlternativeName,
    IssuingDistributionPoint, KeyUsage, Name, ReasonFlags, RelativeDistinguishedName, RevokedCertificate,
};
use crate::codec::asn1::ObjectIdentifier;

/// The revocation status of a certificate (RFC 5280 §6.3.2 (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevocationStatus {
    /// The CRLs that cover every reason do not list it.
    Unrevoked,
    Revoked(CRLReason),
    /// The CRLs given do not cover every reason.
    Undetermined,
}

/// A source of revocation status other than the CRLs of the validator,
/// such as OCSP responses (RFC 6960), which path validation consults for
/// each certificate when it checks revocation (RFC 5280 §6.3).
///
/// A source holds the data it answers from: it does no I/O.
pub trait RevocationSource: fmt::Debug {
    /// The status of `certificate`, issued by the holder of `issuer` and
    /// `issuer_key`, under `config` (its time, key limits and algorithms):
    /// `Undetermined` when the source says nothing current about it, an
    /// error when what it says about it cannot be used. Every signature the
    /// source verifies is spent from `budget`, the budget of the whole
    /// validation; `Work` when it runs out.
    fn status(
        &self,
        certificate: &Certificate<'_>,
        issuer: &Name<'_>,
        issuer_key: &PublicKey,
        config: &PathConfig,
        budget: &mut PathBudget,
    ) -> Result<RevocationStatus, PathErrorReason>;
}

impl RevocationStatus {
    /// The status of two sources together: revoked if either says so,
    /// unrevoked if either says so otherwise, and undetermined if neither knows.
    pub fn combine(self, other: RevocationStatus) -> RevocationStatus {
        match (self, other) {
            (RevocationStatus::Revoked(reason), _) | (_, RevocationStatus::Revoked(reason)) => {
                RevocationStatus::Revoked(reason)
            }
            (RevocationStatus::Unrevoked, _) | (_, RevocationStatus::Unrevoked) => RevocationStatus::Unrevoked,
            _ => RevocationStatus::Undetermined,
        }
    }
}

impl ReasonFlags {
    /// The reasons a CRL may cover: all but `unused` (RFC 5280 §6.3.2 (a)).
    pub const ALL_REASONS: ReasonFlags = ReasonFlags { bits: 0x1FE };
}

impl<'a, 'c> PathValidator<'a, 'c> {
    /// The CRL extensions processed; another critical one makes a CRL unusable.
    pub const CRL_EXTENSIONS: [ObjectIdentifier<'static>; 7] = [
        AuthorityKeyIdentifier::OID,
        IssuerAlternativeName::OID,
        CRLNumber::OID,
        DeltaCRLIndicator::OID,
        IssuingDistributionPoint::OID,
        FreshestCRL::OID,
        AuthorityInformationAccess::OID,
    ];
    /// The CRL entry extensions processed.
    pub const ENTRY_EXTENSIONS: [ObjectIdentifier<'static>; 4] =
        [CRLReason::OID, InvalidityDate::OID, CertificateIssuer::OID, HoldInstructionCode::OID];

    /// The full names of a distribution point name: a full name, or the
    /// name relative to `issuer` made full (RFC 5280 §4.2.1.13).
    pub fn full_names(name: &DistributionPointName<'_>, issuer: &Name<'_>) -> Vec<GeneralName<'static>> {
        match name {
            DistributionPointName::FullName(names) => names.iter().cloned().map(GeneralName::into_owned).collect(),
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                let mut rdns: Vec<RelativeDistinguishedName<'_>> = issuer.rdns().collect();
                rdns.push(rdn.clone());
                match Name::new(&rdns) {
                    Ok(name) => alloc::vec![GeneralName::DirectoryName(name)],
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// Whether two general names name the same thing: directory names by
    /// RFC 5280 §7.1, the others by their encoding.
    pub fn same_name(first: &GeneralName<'_>, second: &GeneralName<'_>) -> bool {
        match (first, second) {
            (GeneralName::DirectoryName(first), GeneralName::DirectoryName(second)) => first.matches(second),
            (first, second) => first == second,
        }
    }

    /// Whether `names` has a directory name matching `name`.
    pub fn names_directory(names: &[GeneralName<'_>], name: &Name<'_>) -> bool {
        names
            .iter()
            .any(|candidate| matches!(candidate, GeneralName::DirectoryName(candidate) if candidate.matches(name)))
    }

    /// The distribution points of `certificate` to process (RFC 5280 §6.3.3):
    /// those of its extension, then the one the certificate issuer is.
    pub fn distribution_points(
        certificate: &Certificate<'_>,
    ) -> Result<Vec<DistributionPoint<'static>>, PathErrorReason> {
        let tbs = certificate.tbs_certificate();
        let mut points: Vec<DistributionPoint<'static>> = tbs
            .extensions
            .typed::<CRLDistributionPoints<'_>>()
            .map_err(PathErrorReason::Certificate)?
            .map(|points| points.into_owned().points)
            .unwrap_or_default();
        let mut issuer_names = alloc::vec![GeneralName::DirectoryName(tbs.issuer.clone().into_owned())];
        if let Some(alternative) =
            tbs.extensions.typed::<IssuerAlternativeName<'_>>().map_err(PathErrorReason::Certificate)?
        {
            issuer_names.extend(alternative.into_owned().names);
        }
        points.push(DistributionPoint {
            name: Some(DistributionPointName::FullName(issuer_names)),
            reasons: None,
            crl_issuer: None,
        });
        Ok(points)
    }

    /// Whether `list` is current at the validation time: issued, and not
    /// past its `nextUpdate` (RFC 5280 §6.3.3 (a)), or, without one, not
    /// older than `lifetime_without_next_update` of the configuration.
    pub fn is_current(&self, list: &CertificateList<'_>) -> bool {
        let tbs = list.tbs_cert_list();
        let next_update = tbs.next_update.map(|next| next.time());
        self.config.revocation.is_current(tbs.this_update.time(), next_update, self.time())
    }

    /// Checks a CRL in scope for the profile and its extensions: a
    /// signature algorithm the configuration accepts, no critical extension
    /// not processed, every processed one decoding, and
    /// with a profile beyond the algorithm a non-critical CRL number, an
    /// authority key identifier and no serial number listed twice (for one issuer).
    pub fn check_crl(&self, list: &CertificateList<'_>) -> Result<(), PathErrorReason> {
        let invalid = Err(PathErrorReason::InvalidCRL);
        let accepted = SignatureAlgorithm::from_identifier(list.signature_algorithm())
            .is_ok_and(|algorithm| self.config.accept_sha1 || !algorithm.uses_sha1());
        if !accepted {
            return invalid;
        }
        let tbs = list.tbs_cert_list();
        let unknown = |extensions: &Extensions<'_>, known: &[ObjectIdentifier<'static>]| {
            extensions.entries.iter().any(|extension| extension.critical && !known.contains(&extension.oid))
        };
        if unknown(&tbs.extensions, &PathValidator::CRL_EXTENSIONS) {
            return invalid;
        }
        if tbs.revoked_certificates.iter().any(|entry| unknown(&entry.extensions, &PathValidator::ENTRY_EXTENSIONS)) {
            return invalid;
        }
        let decodes = tbs.extensions.typed::<AuthorityKeyIdentifier<'_>>().is_ok()
            && tbs.extensions.typed::<CRLNumber<'_>>().is_ok()
            && tbs.extensions.typed::<DeltaCRLIndicator<'_>>().is_ok()
            && tbs.extensions.typed::<IssuingDistributionPoint<'_>>().is_ok()
            && tbs.revoked_certificates.iter().all(|entry| {
                entry.extensions.typed::<CRLReason>().is_ok()
                    && entry.extensions.typed::<CertificateIssuer<'_>>().is_ok()
            });
        if !decodes {
            return invalid;
        }
        if self.config.profile == PathProfile::Algorithm {
            return Ok(());
        }
        let number = tbs.extensions.get(&CRLNumber::OID);
        if number.is_none_or(|extension| extension.critical)
            || tbs.extensions.get(&AuthorityKeyIdentifier::OID).is_none()
        {
            return invalid;
        }
        let mut serials: Vec<&[u8]> =
            tbs.revoked_certificates.iter().map(|entry| entry.serial_number.as_bytes()).collect();
        let indirect =
            tbs.revoked_certificates.iter().any(|entry| entry.extensions.get(&CertificateIssuer::OID).is_some());
        serials.sort_unstable();
        if !indirect && serials.windows(2).any(|pair| pair[0] == pair[1]) {
            return invalid;
        }
        Ok(())
    }

    /// The entry of `list` for the certificate of `serial` issued by
    /// `issuer`, following the certificate issuers of the entries of an
    /// indirect CRL (RFC 5280 §5.3.3; a CRL that is not indirect lists only
    /// certificates of its own issuer).
    pub fn entry<'l>(
        list: &'l CertificateList<'_>,
        serial: &[u8],
        issuer: &Name<'_>,
    ) -> Option<&'l RevokedCertificate<'l>> {
        let tbs = list.tbs_cert_list();
        let indirect = tbs
            .extensions
            .typed::<IssuingDistributionPoint<'_>>()
            .ok()
            .flatten()
            .is_some_and(|issuing| issuing.indirect_crl);
        let mut current: Vec<GeneralName<'_>> = alloc::vec![GeneralName::DirectoryName(tbs.issuer.clone())];
        for entry in &tbs.revoked_certificates {
            if indirect && let Ok(Some(names)) = entry.extensions.typed::<CertificateIssuer<'_>>() {
                current = names.names.into_iter().map(GeneralName::into_owned).collect();
            }
            if entry.serial_number.as_bytes() == serial && PathValidator::names_directory(&current, issuer) {
                return Some(entry);
            }
        }
        None
    }

    /// The reason of an entry: its reason code, or unspecified.
    pub fn reason(entry: &RevokedCertificate<'_>) -> CRLReason {
        entry.extensions.typed::<CRLReason>().ok().flatten().unwrap_or(CRLReason::Unspecified)
    }

    /// The key that signed `list`, validated (RFC 5280 §6.3.3 (f), (g)): the
    /// key of the certificate's issuer when it issued the CRL, or the key
    /// of a certificate of the CRL issuer whose path leads to the same
    /// anchor; its certificate, if any, allows cRLSign. `None` if none
    /// verifies. Every signature verified, also on the paths of CRL issuers,
    /// is spent from `budget`; `Work` when it runs out.
    ///
    /// A CRL issuer whose path is already being validated (in `signers`)
    /// is taken as valid here, and that outer validation decides: a CRL
    /// issuer may be covered by the CRL it issues (NIST PKITS 4.14.30).
    /// [`PathValidator::revocation_status`] reads every usable CRL, so such
    /// a CRL cannot hide another that revokes.
    #[allow(clippy::too_many_arguments)]
    pub fn crl_signer(
        &self,
        list: &CertificateList<'_>,
        direct: bool,
        issuer_key: &PublicKey,
        issuer_certificate: Option<&Certificate<'_>>,
        anchor: &TrustAnchor,
        signers: &mut Vec<Vec<u8>>,
        budget: &mut PathBudget,
    ) -> Result<Option<PublicKey>, PathErrorReason> {
        let signs_crls = |certificate: Option<&Certificate<'_>>| {
            certificate.is_none_or(|certificate| {
                let usage = certificate.tbs_certificate().extensions.typed::<KeyUsage>().ok().flatten();
                usage.is_none_or(|usage| usage.contains(KeyUsage::CRL_SIGN))
            })
        };
        let mut verifies = |key: &PublicKey| -> Result<bool, PathErrorReason> {
            budget.spend_signature()?;
            Ok(list.verify(key).is_ok())
        };
        if direct && signs_crls(issuer_certificate) && verifies(issuer_key)? {
            return Ok(Some(issuer_key.clone()));
        }
        let crl_issuer = &list.tbs_cert_list().issuer;
        if anchor.name.matches(crl_issuer) && signs_crls(anchor.certificate.as_ref()) && verifies(&anchor.public_key)? {
            return Ok(Some(anchor.public_key.clone()));
        }
        if signers.len() >= self.config.maximum_nested_signers {
            return Ok(None);
        }
        // The path of a CRL issuer is validated as that of a certificate
        // holder: the purposes and identity of the target do not apply, nor
        // the rules of the Web PKI on server certificates.
        let config = PathConfig {
            profile: self.config.profile.min(PathProfile::RFC5280),
            key_usage: None,
            extended_key_usage: None,
            identity: None,
            ..self.config.clone()
        };
        for candidate in
            self.intermediates.iter().filter(|candidate| candidate.tbs_certificate().subject.matches(crl_issuer))
        {
            if !signs_crls(Some(candidate)) {
                continue;
            }
            let Ok(key) = PublicKey::from_info_with_limits(
                &candidate.tbs_certificate().subject_public_key_info,
                &self.config.key_limits,
            ) else {
                continue;
            };
            budget.spend_signature()?;
            if list.verify(&key).is_err() {
                continue;
            }
            let encoding = candidate.tbs_encoding().to_vec();
            if signers.contains(&encoding) {
                return Ok(Some(key));
            }
            signers.push(encoding);
            let validator = PathValidator { config: &config, anchors: core::slice::from_ref(anchor), ..*self };
            let validated = validator.validate_with(candidate, signers, budget);
            signers.pop();
            match validated {
                Ok(_) => return Ok(Some(key)),
                Err(error) if error.reason == PathErrorReason::Work => return Err(PathErrorReason::Work),
                Err(_) => {}
            }
        }
        Ok(None)
    }

    /// The revocation status of `chain[position]` (RFC 5280 §6.3.3): its
    /// issuer has the key `issuer_key`, and its certificate is the next of
    /// the chain or the anchor's.
    ///
    /// Every current CRL in scope is read, not only until every reason is
    /// covered, and a revocation in any of them is the status: what the
    /// CRLs are given in, and a CRL that omits a revocation, cannot hide a
    /// CRL that lists it. A CRL in scope that cannot be used (malformed,
    /// with a critical extension not processed, or without a valid signer)
    /// is skipped, as is a delta CRL that cannot be used. The status of the
    /// CRLs is then combined with that of each source
    /// ([`RevocationStatus::combine`]); a source that cannot use what it
    /// has about the certificate is skipped too. A status left
    /// undetermined after something was skipped fails with the reason of
    /// the first thing skipped (`InvalidCRL`, `InvalidResponse`): the
    /// status exists but cannot be read.
    pub fn revocation_status(
        &self,
        chain: &[&Certificate<'_>],
        anchor: &TrustAnchor,
        position: usize,
        issuer_key: &PublicKey,
        signers: &mut Vec<Vec<u8>>,
        budget: &mut PathBudget,
    ) -> Result<RevocationStatus, PathErrorReason> {
        let certificate = chain[position];
        let issuer_certificate = chain.get(position + 1).copied().or(anchor.certificate.as_ref());
        let tbs = certificate.tbs_certificate();
        let ca = tbs
            .extensions
            .typed::<BasicConstraints>()
            .map_err(PathErrorReason::Certificate)?
            .is_some_and(|constraints| constraints.ca);
        let mut reasons = ReasonFlags::default();
        let mut status = RevocationStatus::Unrevoked;
        let mut skipped: Option<PathErrorReason> = None;
        let complete: Vec<&CertificateList<'_>> = self
            .crls
            .iter()
            .filter(|list| list.tbs_cert_list().extensions.get(&DeltaCRLIndicator::OID).is_none())
            .collect();
        let serial = tbs.serial_number.as_bytes();
        for point in PathValidator::distribution_points(certificate)? {
            for &list in &complete {
                if status != RevocationStatus::Unrevoked {
                    break;
                }
                let interim = match self.scope(list, &point, certificate, ca) {
                    Ok(Some(interim)) => interim,
                    Ok(None) => continue,
                    Err(reason) => {
                        skipped.get_or_insert(reason);
                        continue;
                    }
                };
                if !self.is_current(list) {
                    continue;
                }
                if let Err(reason) = self.check_crl(list) {
                    skipped.get_or_insert(reason);
                    continue;
                }
                let direct = point.crl_issuer.is_none();
                let Some(signer) =
                    self.crl_signer(list, direct, issuer_key, issuer_certificate, anchor, signers, budget)?
                else {
                    skipped.get_or_insert(PathErrorReason::InvalidCRL);
                    continue;
                };
                if self.config.revocation.use_deltas
                    && let Some(delta) = self.delta(list, &signer, budget)?
                    && let Some(entry) = PathValidator::entry(delta, serial, &tbs.issuer)
                {
                    status = RevocationStatus::Revoked(PathValidator::reason(entry));
                }
                if status == RevocationStatus::Unrevoked
                    && let Some(entry) = PathValidator::entry(list, serial, &tbs.issuer)
                {
                    status = RevocationStatus::Revoked(PathValidator::reason(entry));
                }
                if status == RevocationStatus::Revoked(CRLReason::RemoveFromCRL) {
                    status = RevocationStatus::Unrevoked;
                }
                reasons.bits |= interim.bits;
            }
        }
        let mut status = match status {
            RevocationStatus::Unrevoked if !reasons.contains(ReasonFlags::ALL_REASONS) => {
                RevocationStatus::Undetermined
            }
            status => status,
        };
        for source in self.sources {
            if let RevocationStatus::Revoked(_) = status {
                break;
            }
            match source.status(certificate, &tbs.issuer, issuer_key, self.config, budget) {
                Ok(answer) => status = status.combine(answer),
                Err(PathErrorReason::Work) => return Err(PathErrorReason::Work),
                Err(reason) => {
                    skipped.get_or_insert(reason);
                }
            }
        }
        match skipped {
            Some(reason) if status == RevocationStatus::Undetermined => Err(reason),
            _ => Ok(status),
        }
    }

    /// The reasons `list` covers for `certificate` through `point` (RFC 5280
    /// §6.3.3 (b), (d)), or `None` if the CRL is not in its scope.
    pub fn scope(
        &self,
        list: &CertificateList<'_>,
        point: &DistributionPoint<'_>,
        certificate: &Certificate<'_>,
        ca: bool,
    ) -> Result<Option<ReasonFlags>, PathErrorReason> {
        let tbs = certificate.tbs_certificate();
        let crl = list.tbs_cert_list();
        let issuing = crl.extensions.typed::<IssuingDistributionPoint<'_>>().map_err(|_| PathErrorReason::InvalidCRL);
        let issuing = match &point.crl_issuer {
            Some(crl_issuer) => {
                if !PathValidator::names_directory(crl_issuer, &crl.issuer) {
                    return Ok(None);
                }
                match issuing? {
                    Some(issuing) if issuing.indirect_crl => Some(issuing),
                    _ => return Ok(None),
                }
            }
            None => {
                if !crl.issuer.matches(&tbs.issuer) {
                    return Ok(None);
                }
                issuing?
            }
        };
        let Some(issuing) = issuing else {
            return Ok(Some(point.reasons.unwrap_or(ReasonFlags::ALL_REASONS)));
        };
        if let Some(name) = &issuing.name {
            let names = PathValidator::full_names(name, &crl.issuer);
            let wanted: Vec<GeneralName<'static>> = match (&point.name, &point.crl_issuer) {
                (Some(point_name), crl_issuer) => {
                    let base = crl_issuer
                        .as_ref()
                        .and_then(|issuers| {
                            issuers.iter().find_map(|issuer| match issuer {
                                GeneralName::DirectoryName(name) => Some(name.clone()),
                                _ => None,
                            })
                        })
                        .unwrap_or_else(|| tbs.issuer.clone());
                    PathValidator::full_names(point_name, &base)
                }
                (None, Some(crl_issuer)) => crl_issuer.iter().cloned().map(GeneralName::into_owned).collect(),
                (None, None) => Vec::new(),
            };
            if !names.iter().any(|name| wanted.iter().any(|other| PathValidator::same_name(name, other))) {
                return Ok(None);
            }
        }
        if (issuing.only_contains_user_certs && ca)
            || (issuing.only_contains_ca_certs && !ca)
            || issuing.only_contains_attribute_certs
        {
            return Ok(None);
        }
        let reasons = match (issuing.only_some_reasons, point.reasons) {
            (Some(only), Some(reasons)) => ReasonFlags { bits: only.bits & reasons.bits },
            (Some(only), None) => only,
            (None, Some(reasons)) => reasons,
            (None, None) => ReasonFlags::ALL_REASONS,
        };
        Ok(Some(ReasonFlags { bits: reasons.bits & ReasonFlags::ALL_REASONS.bits }))
    }

    /// The current delta CRL that updates the complete CRL `list` (RFC 5280
    /// §5.2.4, §6.3.3 (c), (h)): the same issuer, issuing distribution point
    /// and authority key identifier, a base no newer than `list`, usable,
    /// and signed by `signer` (each signature spent from `budget`); the
    /// newest of them. Delta CRLs that cannot be used are skipped.
    pub fn delta(
        &self,
        list: &CertificateList<'_>,
        signer: &PublicKey,
        budget: &mut PathBudget,
    ) -> Result<Option<&'a CertificateList<'c>>, PathErrorReason> {
        let complete = list.tbs_cert_list();
        let number =
            complete.extensions.typed::<CRLNumber<'_>>().ok().flatten().and_then(|number| number.as_u128().ok());
        let Some(number) = number else { return Ok(None) };
        let identifier = |list: &CertificateList<'_>| {
            let tbs = list.tbs_cert_list();
            tbs.extensions
                .typed::<AuthorityKeyIdentifier<'_>>()
                .ok()
                .flatten()
                .map(|identifier| identifier.key_identifier.map(|key| key.into_owned()))
        };
        let mut best: Option<(u128, &'a CertificateList<'c>)> = None;
        for delta in self.crls {
            let tbs = delta.tbs_cert_list();
            let Ok(Some(indicator)) = tbs.extensions.typed::<DeltaCRLIndicator<'_>>() else { continue };
            let same_scope = tbs.issuer.matches(&complete.issuer)
                && tbs.extensions.get(&IssuingDistributionPoint::OID).map(|extension| &extension.value)
                    == complete.extensions.get(&IssuingDistributionPoint::OID).map(|extension| &extension.value)
                && identifier(delta) == identifier(list);
            let base = indicator.as_u128().ok();
            let delta_number =
                tbs.extensions.typed::<CRLNumber<'_>>().ok().flatten().and_then(|number| number.as_u128().ok());
            let (Some(base), Some(delta_number)) = (base, delta_number) else { continue };
            if !same_scope || base > number || delta_number <= number || !self.is_current(delta) {
                continue;
            }
            if self.check_crl(delta).is_err() {
                continue;
            }
            budget.spend_signature()?;
            if delta.verify(signer).is_err() {
                continue;
            }
            if best.is_none_or(|(newest, _)| delta_number > newest) {
                best = Some((delta_number, delta));
            }
        }
        Ok(best.map(|(_, delta)| delta))
    }
}
