use alloc::vec::Vec;

use super::{
    CertificateRole, NameConstraintsState, PathConfig, PathError, PathErrorReason, PathExtensions, PathProfile,
    PolicyGraph, RevocationSource, RevocationStatus, TrustAnchor,
};
use crate::auth::cert::key::{PublicKey, SignatureAlgorithm};
use crate::auth::cert::x509::{
    AuthorityKeyIdentifier, Certificate, CertificateList, CertificatePolicies, ExtendedKeyUsage, KeyUsage,
    SubjectKeyIdentifier, Version,
};
use crate::codec::asn1::{ASN1Time, ObjectIdentifier};

/// A path that validated: the certificates from the target to the one the
/// trust anchor issued, the anchor, and the user-constrained policy set
/// (RFC 9618 §5.5), which contains anyPolicy when every policy is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPath<'p> {
    pub certificates: Vec<&'p Certificate<'p>>,
    pub anchor: &'p TrustAnchor,
    pub policies: Vec<ObjectIdentifier<'static>>,
}

/// The work left to a validation, so that hostile certificates and CRLs
/// cannot make it run without end (RFC 4158 §5): the signatures it may
/// verify and the names it may compare with name constraints, shared by
/// path building and by the validation of the paths of CRL issuers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathBudget {
    pub signatures: usize,
    pub name_checks: usize,
}

impl PathBudget {
    /// The budget of one validation under `config`.
    pub const fn new(config: &PathConfig) -> PathBudget {
        PathBudget { signatures: config.maximum_signatures, name_checks: config.maximum_name_checks }
    }

    /// Spends one signature; fails with `Work` when none is left.
    pub fn spend_signature(&mut self) -> Result<(), PathErrorReason> {
        self.signatures = self.signatures.checked_sub(1).ok_or(PathErrorReason::Work)?;
        Ok(())
    }
}

/// Builds and validates certification paths (RFC 5280 §6, RFC 4158): from
/// a target, through the intermediate certificates given, to one of the
/// trust anchors, checked against the configuration, the CRLs given and
/// the other revocation sources given.
#[derive(Clone, Copy, Debug)]
pub struct PathValidator<'a, 'c> {
    pub config: &'a PathConfig,
    pub anchors: &'a [TrustAnchor],
    pub intermediates: &'a [Certificate<'c>],
    pub crls: &'a [CertificateList<'c>],
    pub sources: &'a [&'a dyn RevocationSource],
}

impl<'a, 'c> PathValidator<'a, 'c> {
    /// A validator without revocation sources other than `crls`.
    pub const fn new(
        config: &'a PathConfig,
        anchors: &'a [TrustAnchor],
        intermediates: &'a [Certificate<'c>],
        crls: &'a [CertificateList<'c>],
    ) -> PathValidator<'a, 'c> {
        PathValidator { config, anchors, intermediates, crls, sources: &[] }
    }

    /// The validator with the revocation sources `sources`, consulted in
    /// order after the CRLs when revocation is checked.
    pub const fn with_sources(self, sources: &'a [&'a dyn RevocationSource]) -> PathValidator<'a, 'c> {
        PathValidator { sources, ..self }
    }

    /// The validation time, in whole seconds: a certificate's times have no
    /// fraction, so a fraction of the validation time is dropped (a time
    /// within the second of `notAfter` is still valid).
    pub fn time(&self) -> ASN1Time {
        ASN1Time { nanosecond: 0, ..self.config.time }
    }

    /// Builds a path from `target` to a trust anchor and validates it. The
    /// candidate issuers of each certificate are tried in order (those whose
    /// subject key identifier is the certificate's authority key identifier
    /// first), backtracking when a path fails; the error is that of the
    /// longest path tried.
    pub fn validate(&self, target: &'a Certificate<'c>) -> Result<ValidatedPath<'a>, PathError> {
        self.validate_with(target, &mut Vec::new(), &mut PathBudget::new(self.config))
    }

    /// [`PathValidator::validate`] within `budget`, while the paths of the
    /// CRL issuers `signers` (their signed bytes) are being validated (for
    /// the path of a CRL issuer).
    pub fn validate_with(
        &self,
        target: &'a Certificate<'c>,
        signers: &mut Vec<Vec<u8>>,
        budget: &mut PathBudget,
    ) -> Result<ValidatedPath<'a>, PathError> {
        let mut chain: Vec<&'a Certificate<'c>> = alloc::vec![target];
        let mut best = (PathError::new(0, PathErrorReason::NoPath), 0);
        match self.extend(&mut chain, budget, &mut best, signers) {
            Some(path) => Ok(path),
            None => Err(best.0),
        }
    }

    /// Keeps `error` if it comes from a path at least as long as the best error's.
    pub fn record(best: &mut (PathError, usize), error: PathError, length: usize) {
        if length >= best.1 || best.0.reason == PathErrorReason::NoPath {
            *best = (error, length);
        }
    }

    /// Whether `key` verifies the signature of `certificate`, spending one
    /// signature of `budget`; fails with `Work` when none is left.
    pub fn verifies(
        certificate: &Certificate<'_>,
        key: &PublicKey,
        budget: &mut PathBudget,
    ) -> Result<bool, PathErrorReason> {
        budget.spend_signature()?;
        Ok(certificate.verify(key).is_ok())
    }

    /// Extends `chain` toward a trust anchor, depth-first, and validates
    /// each complete path; `best` keeps the error of the longest path tried
    /// and its length.
    pub fn extend(
        &self,
        chain: &mut Vec<&'a Certificate<'c>>,
        budget: &mut PathBudget,
        best: &mut (PathError, usize),
        signers: &mut Vec<Vec<u8>>,
    ) -> Option<ValidatedPath<'a>> {
        let last = *chain.last()?;
        let issuer = &last.tbs_certificate().issuer;
        let index = chain.len() - 1;
        for anchor in self.anchors.iter().filter(|anchor| anchor.name.matches(issuer)) {
            match PathValidator::verifies(last, &anchor.public_key, budget) {
                Err(reason) => {
                    *best = (PathError::new(index, reason), usize::MAX);
                    return None;
                }
                Ok(false) => {
                    PathValidator::record(best, PathError::new(index, PathErrorReason::Signature), chain.len())
                }
                Ok(true) => match self.validate_path(chain, anchor, true, signers, budget) {
                    Ok(policies) => {
                        let certificates =
                            chain.iter().map(|&certificate| certificate as &'a Certificate<'a>).collect();
                        return Some(ValidatedPath { certificates, anchor, policies });
                    }
                    Err(error) if error.reason == PathErrorReason::Work => {
                        *best = (error, usize::MAX);
                        return None;
                    }
                    Err(error) => PathValidator::record(best, error, chain.len()),
                },
            }
        }
        let identifier = last
            .tbs_certificate()
            .extensions
            .typed::<AuthorityKeyIdentifier<'_>>()
            .ok()
            .flatten()
            .and_then(|identifier| identifier.key_identifier);
        let mut candidates: Vec<&'a Certificate<'c>> = self
            .intermediates
            .iter()
            .filter(|candidate| candidate.tbs_certificate().subject.matches(issuer))
            .filter(|candidate| !chain.iter().any(|seen| PathValidator::same_ca(seen, candidate)))
            .collect();
        // Candidates whose subject key identifier is the authority key identifier first.
        candidates.sort_by_key(|candidate| {
            let subject = candidate.tbs_certificate().extensions.typed::<SubjectKeyIdentifier<'_>>().ok().flatten();
            match (&identifier, subject) {
                (Some(identifier), Some(subject)) if *identifier == subject.key_identifier => 0,
                _ => 1,
            }
        });
        for candidate in candidates {
            let logical =
                PathValidator::logical_intermediates(chain) + usize::from(!PathValidator::self_issued(candidate));
            if logical > self.config.maximum_intermediates {
                PathValidator::record(best, PathError::new(index, PathErrorReason::Depth), chain.len());
                continue;
            }
            let info = &candidate.tbs_certificate().subject_public_key_info;
            let Ok(key) = PublicKey::from_info_with_limits(info, &self.config.key_limits) else { continue };
            match PathValidator::verifies(last, &key, budget) {
                Err(reason) => {
                    *best = (PathError::new(index, reason), usize::MAX);
                    return None;
                }
                Ok(false) => {
                    PathValidator::record(best, PathError::new(index, PathErrorReason::Signature), chain.len())
                }
                Ok(true) => {
                    chain.push(candidate);
                    let found = self.extend(chain, budget, best, signers);
                    chain.pop();
                    if found.is_some() || best.0.reason == PathErrorReason::Work {
                        return found;
                    }
                }
            }
        }
        None
    }

    /// Whether `certificate` is self-issued (RFC 5280 §6.1: its names match).
    pub fn self_issued(certificate: &Certificate<'_>) -> bool {
        let tbs = certificate.tbs_certificate();
        tbs.issuer.matches(&tbs.subject)
    }

    /// The intermediate certificates of `chain` (all but the target) that
    /// are not self-issued.
    pub fn logical_intermediates(chain: &[&Certificate<'_>]) -> usize {
        chain.iter().skip(1).filter(|certificate| !PathValidator::self_issued(certificate)).count()
    }

    /// Whether two certificates are the same CA for path building: the same
    /// subject and key, which a path must not repeat (RFC 4158 §2.4.2).
    pub fn same_ca(first: &Certificate<'_>, second: &Certificate<'_>) -> bool {
        let (first, second) = (first.tbs_certificate(), second.tbs_certificate());
        first.subject_public_key_info == second.subject_public_key_info && first.subject.matches(&second.subject)
    }

    /// Validates `chain`, the certificates from the target to the one
    /// `anchor` issued, by RFC 5280 §6.1 with the policy graph of RFC 9618,
    /// and the checks of the configuration. `verified` is whether the
    /// signatures were already verified (by path building). Returns the
    /// user-constrained policy set.
    pub fn validate_path(
        &self,
        chain: &[&Certificate<'_>],
        anchor: &TrustAnchor,
        verified: bool,
        signers: &mut Vec<Vec<u8>>,
        budget: &mut PathBudget,
    ) -> Result<Vec<ObjectIdentifier<'static>>, PathError> {
        let config = self.config;
        let n = chain.len();
        if n == 0 || PathValidator::logical_intermediates(chain) > config.maximum_intermediates {
            return Err(PathError::new(n.saturating_sub(1), PathErrorReason::Depth));
        }
        // §6.1.2: initialization.
        let initial = |inhibit: bool| if inhibit { 0 } else { n + 1 };
        let mut explicit_policy = initial(config.initial_explicit_policy);
        let mut inhibit_any_policy = initial(config.initial_any_policy_inhibit);
        let mut policy_mapping = initial(config.initial_policy_mapping_inhibit);
        let mut max_path_length = n;
        let mut graph = Some(PolicyGraph::new());
        let mut constraints = NameConstraintsState::new();
        if let Some(initial) = &config.initial_name_constraints {
            constraints.push(initial.clone());
        }
        if let Some(anchored) = &anchor.name_constraints {
            constraints.push(anchored.clone());
        }
        self.check_anchor(anchor, n, budget)?;
        let mut working_key = anchor.public_key.clone();
        let mut working_issuer = anchor.name.clone();
        for i in 1..=n {
            let certificate = chain[n - i];
            let index = n - i;
            let error = |reason| PathError::new(index, reason);
            let tbs = certificate.tbs_certificate();
            let extensions = PathExtensions::decode(certificate).map_err(error)?;
            let key = PublicKey::from_info_with_limits(&tbs.subject_public_key_info, &config.key_limits)
                .map_err(|failure| error(PathErrorReason::Key(failure)))?;
            let self_issued = tbs.issuer.matches(&tbs.subject);
            let last = i == n;
            // §6.1.3 (a): signature, validity, revocation, name chaining.
            let algorithm = SignatureAlgorithm::from_identifier(certificate.signature_algorithm())
                .map_err(|failure| error(PathErrorReason::Key(failure)))?;
            if algorithm.uses_sha1() && !config.accept_sha1 {
                return Err(error(PathErrorReason::Algorithm));
            }
            if !verified && !PathValidator::verifies(certificate, &working_key, budget).map_err(error)? {
                return Err(error(PathErrorReason::Signature));
            }
            if !tbs.validity.contains(self.time()) {
                return Err(error(PathErrorReason::Validity));
            }
            if !tbs.issuer.matches(&working_issuer) {
                return Err(error(PathErrorReason::NameChaining));
            }
            let self_signed = self_issued && PathValidator::verifies(certificate, &key, budget).map_err(error)?;
            let role = if last { CertificateRole::Target } else { CertificateRole::Intermediate };
            config.profile.check(certificate, &extensions, &key, role, self_signed).map_err(error)?;
            if config.revocation.check {
                let status =
                    self.revocation_status(chain, anchor, n - i, &working_key, signers, budget).map_err(error)?;
                match status {
                    RevocationStatus::Revoked(reason) => return Err(error(PathErrorReason::Revoked(reason))),
                    RevocationStatus::Undetermined if config.revocation.require => {
                        return Err(error(PathErrorReason::RevocationUnknown));
                    }
                    _ => {}
                }
            }
            // §6.1.3 (b), (c): name constraints, but for self-issued intermediates.
            if !self_issued || last {
                constraints.check(certificate, &mut budget.name_checks).map_err(error)?;
            }
            // §6.1.3 (d), (e), (f): policies.
            match (&mut graph, &extensions.certificate_policies) {
                (Some(current), Some(policies)) => {
                    current.process(policies, inhibit_any_policy > 0 || (!last && self_issued));
                    if current.is_empty() {
                        graph = None;
                    }
                }
                (Some(_), None) => graph = None,
                (None, _) => {}
            }
            if explicit_policy == 0 && graph.is_none() {
                return Err(error(PathErrorReason::Policy));
            }
            if last {
                // §6.1.5: wrap-up.
                explicit_policy = explicit_policy.saturating_sub(1);
                if extensions
                    .policy_constraints
                    .is_some_and(|constraints| constraints.require_explicit_policy == Some(0))
                {
                    explicit_policy = 0;
                }
                let policies = match &graph {
                    Some(current) => current.user_constrained_policies(config.initial_policy_set.as_deref()),
                    None => Vec::new(),
                };
                if explicit_policy == 0 && policies.is_empty() {
                    return Err(error(PathErrorReason::Policy));
                }
                self.check_target(certificate, &extensions).map_err(error)?;
                return Ok(policies);
            }
            // §6.1.4: preparation for certificate i+1.
            if let Some(mappings) = &extensions.policy_mappings {
                let any = CertificatePolicies::ANY_POLICY;
                if mappings
                    .mappings
                    .iter()
                    .any(|mapping| mapping.issuer_domain_policy == any || mapping.subject_domain_policy == any)
                {
                    return Err(error(PathErrorReason::Policy));
                }
                if let Some(current) = &mut graph {
                    current.map(mappings, policy_mapping > 0);
                    if current.is_empty() {
                        graph = None;
                    }
                }
            }
            working_issuer = tbs.subject.clone().into_owned();
            working_key = key;
            if let Some(name_constraints) = &extensions.name_constraints {
                constraints.push(name_constraints.clone().into_owned());
            }
            if !self_issued {
                explicit_policy = explicit_policy.saturating_sub(1);
                policy_mapping = policy_mapping.saturating_sub(1);
                inhibit_any_policy = inhibit_any_policy.saturating_sub(1);
            }
            if let Some(policy_constraints) = extensions.policy_constraints {
                if let Some(require) = policy_constraints.require_explicit_policy {
                    explicit_policy = explicit_policy.min(require as usize);
                }
                if let Some(inhibit) = policy_constraints.inhibit_policy_mapping {
                    policy_mapping = policy_mapping.min(inhibit as usize);
                }
            }
            if let Some(inhibit) = extensions.inhibit_any_policy {
                inhibit_any_policy = inhibit_any_policy.min(inhibit.skip_certs as usize);
            }
            // §6.1.4 (k): a v3 CA; v1 and v2 intermediates are refused, which RFC 5280 allows.
            if tbs.version != Version::V3 || !extensions.is_ca() {
                return Err(error(PathErrorReason::NotCA));
            }
            if !self_issued {
                if max_path_length == 0 {
                    return Err(error(PathErrorReason::PathLength));
                }
                max_path_length -= 1;
            }
            if let Some(length) = extensions.basic_constraints.and_then(|constraints| constraints.path_length) {
                max_path_length = max_path_length.min(length as usize);
            }
            if extensions.key_usage.is_some_and(|usage| !usage.contains(KeyUsage::KEY_CERT_SIGN)) {
                return Err(error(PathErrorReason::KeyUsage));
            }
            // The Web PKI: an intermediate's extended key usage restricts the purposes below it.
            if config.profile == PathProfile::WebPKI
                && let (Some(purpose), Some(usage)) = (&config.extended_key_usage, &extensions.extended_key_usage)
                && !usage.contains(purpose)
                && !usage.contains(&ExtendedKeyUsage::ANY)
            {
                return Err(error(PathErrorReason::ExtendedKeyUsage));
            }
        }
        Err(PathError::new(0, PathErrorReason::NoPath))
    }

    /// Checks the certificate of `anchor`, if it has one and the profile is
    /// beyond the algorithm: valid at the time, a CA whose key signs
    /// certificates, no critical extension not processed, and the profile.
    pub fn check_anchor(&self, anchor: &TrustAnchor, n: usize, budget: &mut PathBudget) -> Result<(), PathError> {
        let error = |reason| PathError::new(n, reason);
        let Some(certificate) = &anchor.certificate else { return Ok(()) };
        if self.config.profile == PathProfile::Algorithm {
            return Ok(());
        }
        let tbs = certificate.tbs_certificate();
        let extensions = PathExtensions::decode(certificate).map_err(error)?;
        if !tbs.validity.contains(self.time()) {
            return Err(error(PathErrorReason::Validity));
        }
        if !extensions.is_ca() {
            return Err(error(PathErrorReason::NotCA));
        }
        if extensions.key_usage.is_some_and(|usage| !usage.contains(KeyUsage::KEY_CERT_SIGN)) {
            return Err(error(PathErrorReason::KeyUsage));
        }
        let self_signed = tbs.issuer.matches(&tbs.subject)
            && PathValidator::verifies(certificate, &anchor.public_key, budget).map_err(error)?;
        self.config
            .profile
            .check(certificate, &extensions, &anchor.public_key, CertificateRole::Anchor, self_signed)
            .map_err(error)
    }

    /// The checks of the configuration on the target: key usage, extended
    /// key usage and identity.
    pub fn check_target(
        &self,
        target: &Certificate<'_>,
        extensions: &PathExtensions<'_>,
    ) -> Result<(), PathErrorReason> {
        let config = self.config;
        if let (Some(wanted), Some(usage)) = (config.key_usage, extensions.key_usage)
            && !usage.contains(wanted)
        {
            return Err(PathErrorReason::KeyUsage);
        }
        if let Some(purpose) = &config.extended_key_usage {
            match &extensions.extended_key_usage {
                Some(usage) => {
                    let any = usage.contains(&ExtendedKeyUsage::ANY) && config.profile != PathProfile::WebPKI;
                    if !usage.contains(purpose) && !any {
                        return Err(PathErrorReason::ExtendedKeyUsage);
                    }
                }
                None if config.profile == PathProfile::WebPKI => return Err(PathErrorReason::ExtendedKeyUsage),
                None => {}
            }
        }
        if let Some(identity) = &config.identity
            && !identity.matches(target).map_err(PathErrorReason::Certificate)?
        {
            return Err(PathErrorReason::Identity);
        }
        Ok(())
    }
}
