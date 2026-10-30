//! The C ABI of [`crate::auth::cert::path`].
//!
//! Configurations, trust anchors, lists of anchors, lists of revocation
//! sources and the outcomes of validations are handles; certificates,
//! names, lists of certificates and lists of CRLs are the handles of
//! [`crate::ffi::auth::cert::x509`], keys those of
//! [`crate::ffi::auth::cert::key`]. Times are seconds since
//! 1970-01-01T00:00:00Z, object identifiers dotted text (lists of them
//! separated by commas), profiles and identities the codes of
//! [`PathProfileKind`] and [`ServiceIdentityKind`].
//!
//! A validation always writes an outcome when its arguments are valid:
//! the path that validated, or the reason the best path tried was refused
//! (as a status, the same for every call), the index of the certificate it
//! concerns and, for a revoked one, the code of the reason.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::auth::cert::key::{KeyLimits, PublicKey};
use crate::auth::cert::path::{
    PathConfig, PathError, PathErrorReason, PathProfile, PathValidator, RevocationConfig, RevocationSource,
    ServiceIdentity, TrustAnchor,
};
use crate::auth::cert::x509::{Certificate, CertificateList, ExtensionValue, KeyUsage, Name, NameConstraints};
use crate::codec::asn1::ObjectIdentifier;
use crate::ffi::auth::cert::x509::X509Status;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`PathErrorReason`], one per variant (key and
/// certificate errors keep those of key and x509).
pub struct PathStatus;

impl PathStatus {
    pub const NO_PATH: Status = Status::new(c"auth.cert.path", c"NoPath", c"no path to a trust anchor could be built");
    pub const NAME_CHAINING: Status = Status::new(
        c"auth.cert.path",
        c"NameChaining",
        c"the issuer does not match the subject of the next certificate",
    );
    pub const SIGNATURE: Status =
        Status::new(c"auth.cert.path", c"Signature", c"the signature does not verify under the issuer's key");
    pub const VALIDITY: Status =
        Status::new(c"auth.cert.path", c"Validity", c"the time is outside the validity period");
    pub const REVOKED: Status = Status::new(c"auth.cert.path", c"Revoked", c"the certificate is revoked");
    pub const REVOCATION_UNKNOWN: Status =
        Status::new(c"auth.cert.path", c"RevocationUnknown", c"the revocation status is unknown");
    pub const INVALID_CRL: Status = Status::new(c"auth.cert.path", c"InvalidCRL", c"a CRL in scope cannot be used");
    pub const INVALID_RESPONSE: Status =
        Status::new(c"auth.cert.path", c"InvalidResponse", c"a revocation status cannot be used");
    pub const NAME_CONSTRAINTS: Status =
        Status::new(c"auth.cert.path", c"NameConstraints", c"a name breaks the name constraints");
    pub const POLICY: Status = Status::new(c"auth.cert.path", c"Policy", c"no valid policy");
    pub const NOT_CA: Status = Status::new(c"auth.cert.path", c"NotCA", c"an intermediate certificate is not a CA");
    pub const PATH_LENGTH: Status =
        Status::new(c"auth.cert.path", c"PathLength", c"more intermediates than a path length constraint allows");
    pub const KEY_USAGE: Status = Status::new(c"auth.cert.path", c"KeyUsage", c"the key usage does not allow the role");
    pub const EXTENDED_KEY_USAGE: Status =
        Status::new(c"auth.cert.path", c"ExtendedKeyUsage", c"the extended key usage does not allow the purpose");
    pub const UNKNOWN_CRITICAL_EXTENSION: Status =
        Status::new(c"auth.cert.path", c"UnknownCriticalExtension", c"an unknown critical extension");
    pub const ALGORITHM: Status =
        Status::new(c"auth.cert.path", c"Algorithm", c"a signature algorithm or key the configuration does not accept");
    pub const PROFILE: Status =
        Status::new(c"auth.cert.path", c"Profile", c"the certificate breaks the profile of the configuration");
    pub const IDENTITY: Status =
        Status::new(c"auth.cert.path", c"Identity", c"the target does not name the identity asked for");
    pub const DEPTH: Status =
        Status::new(c"auth.cert.path", c"Depth", c"the path is longer than the configuration allows");
    pub const WORK: Status =
        Status::new(c"auth.cert.path", c"Work", c"building paths took more work than the configuration allows");

    /// The object identifiers of the dotted texts of `text`, separated by commas (none for empty text).
    pub fn oids(text: &str) -> Result<Vec<ObjectIdentifier<'static>>, &'static Status> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        text.split(',').map(X509Status::oid).collect()
    }

    /// The text of `oids`, dotted and separated by commas.
    pub fn oids_text(oids: &[ObjectIdentifier<'_>]) -> String {
        let texts: Vec<String> = oids.iter().map(|oid| alloc::format!("{oid}")).collect();
        texts.join(",")
    }

    /// The name constraints of the DER value of `length` bytes at `data`, or `None` for no bytes.
    pub fn name_constraints(data: &[u8]) -> Result<Option<NameConstraints<'static>>, &'static Status> {
        if data.is_empty() {
            return Ok(None);
        }
        let constraints = NameConstraints::from_der(data).map_err(|error| error.to_status())?;
        Ok(Some(constraints.into_owned()))
    }
}

impl ToStatus for PathErrorReason {
    fn to_status(&self) -> &'static Status {
        match self {
            PathErrorReason::NoPath => &PathStatus::NO_PATH,
            PathErrorReason::NameChaining => &PathStatus::NAME_CHAINING,
            PathErrorReason::Signature => &PathStatus::SIGNATURE,
            PathErrorReason::Validity => &PathStatus::VALIDITY,
            PathErrorReason::Revoked(_) => &PathStatus::REVOKED,
            PathErrorReason::RevocationUnknown => &PathStatus::REVOCATION_UNKNOWN,
            PathErrorReason::InvalidCRL => &PathStatus::INVALID_CRL,
            PathErrorReason::InvalidResponse => &PathStatus::INVALID_RESPONSE,
            PathErrorReason::NameConstraints => &PathStatus::NAME_CONSTRAINTS,
            PathErrorReason::Policy => &PathStatus::POLICY,
            PathErrorReason::NotCA => &PathStatus::NOT_CA,
            PathErrorReason::PathLength => &PathStatus::PATH_LENGTH,
            PathErrorReason::KeyUsage => &PathStatus::KEY_USAGE,
            PathErrorReason::ExtendedKeyUsage => &PathStatus::EXTENDED_KEY_USAGE,
            PathErrorReason::UnknownCriticalExtension => &PathStatus::UNKNOWN_CRITICAL_EXTENSION,
            PathErrorReason::Algorithm => &PathStatus::ALGORITHM,
            PathErrorReason::Key(error) => error.to_status(),
            PathErrorReason::Certificate(error) => error.to_status(),
            PathErrorReason::Profile => &PathStatus::PROFILE,
            PathErrorReason::Identity => &PathStatus::IDENTITY,
            PathErrorReason::Depth => &PathStatus::DEPTH,
            PathErrorReason::Work => &PathStatus::WORK,
        }
    }
}

impl ToStatus for PathError {
    fn to_status(&self) -> &'static Status {
        self.reason.to_status()
    }
}

/// The [`PathProfile`] values of the C ABI.
pub struct PathProfileKind;

impl PathProfileKind {
    pub const ALGORITHM: u8 = 0;
    pub const RFC5280: u8 = 1;
    pub const WEB_PKI: u8 = 2;

    pub fn decode(kind: u8) -> Result<PathProfile, &'static Status> {
        match kind {
            PathProfileKind::ALGORITHM => Ok(PathProfile::Algorithm),
            PathProfileKind::RFC5280 => Ok(PathProfile::RFC5280),
            PathProfileKind::WEB_PKI => Ok(PathProfile::WebPKI),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The [`ServiceIdentity`] kinds of the C ABI, with [`ServiceIdentityKind::NONE`] for no identity.
pub struct ServiceIdentityKind;

impl ServiceIdentityKind {
    pub const NONE: u8 = 0;
    /// A DNS domain name in A-labels (text).
    pub const DNS: u8 = 1;
    /// An address of 4 or 16 octets.
    pub const IP_ADDRESS: u8 = 2;
    /// A mailbox (text).
    pub const EMAIL: u8 = 3;

    pub fn decode(kind: u8, data: &[u8]) -> Result<Option<ServiceIdentity>, &'static Status> {
        let text = || core::str::from_utf8(data).map(String::from).map_err(|_| &Status::INVALID_UTF8);
        match kind {
            ServiceIdentityKind::NONE => Ok(None),
            ServiceIdentityKind::DNS => Ok(Some(ServiceIdentity::DNS(text()?))),
            ServiceIdentityKind::IP_ADDRESS if matches!(data.len(), 4 | 16) => {
                Ok(Some(ServiceIdentity::IPAddress(data.to_vec())))
            }
            ServiceIdentityKind::EMAIL => Ok(Some(ServiceIdentity::Email(text()?))),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The revocation sources of a validation other than its CRLs (OCSP
/// responses, for one), consulted in order.
#[derive(Debug, Default)]
pub struct RevocationSources {
    pub sources: Vec<Box<dyn RevocationSource>>,
}

/// The outcome of a validation: copies of the certificates of the path
/// that validated, from the target, the index of its trust anchor and its
/// user-constrained policy set; or the error of the best path tried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathOutcome {
    pub certificates: Vec<Certificate<'static>>,
    pub anchor: usize,
    pub policies: Vec<ObjectIdentifier<'static>>,
    pub error: Option<PathError>,
}

impl PathOutcome {
    /// The reason code written for an error that is not a revocation.
    pub const NO_REASON: u8 = u8::MAX;
}

impl Value for PathConfig {
    const TYPE: Type = Type::Named("umilib_auth_cert_path_PathConfig");
}

impl Value for TrustAnchor {
    const TYPE: Type = Type::Named("umilib_auth_cert_path_TrustAnchor");
}

impl Value for Vec<TrustAnchor> {
    const TYPE: Type = Type::Named("umilib_auth_cert_path_TrustAnchors");
}

impl Value for RevocationSources {
    const TYPE: Type = Type::Named("umilib_auth_cert_path_RevocationSources");
}

impl Value for PathOutcome {
    const TYPE: Type = Type::Named("umilib_auth_cert_path_PathOutcome");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the defaults at `time` into `out`: the profile of RFC 5280, any policy, no name
    /// constraints, at most 8 intermediates, 100 signatures and 2^20 name comparisons, the default
    /// key limits, SHA-1 refused, no revocation checking, and no usage, purpose or identity.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_new(time: i64, out: *mut *mut PathConfig) -> *const Status {
        Status::from_result((|| {
            let time = crate::codec::asn1::ASN1Time::from_unix_seconds(time).map_err(|_| &X509Status::INVALID_TIME)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, PathConfig::new(time)) }
        })())
    }

    /// Sets the profile (a [`PathProfileKind`] code).
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_profile(config: *mut PathConfig, profile: u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.profile = PathProfileKind::decode(profile)?;
            Ok(())
        })())
    }

    /// Sets the user-initial-policy-set: any policy if `any`, otherwise the dotted object
    /// identifiers of `length` bytes at `policies`, separated by commas.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_initial_policy_set(config: *mut PathConfig, any: bool, policies: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let policies = PathStatus::oids(unsafe { Pointer::text(policies, length) }?)?;
            config.initial_policy_set = if any { None } else { Some(policies) };
            Ok(())
        })())
    }

    /// Sets initial-explicit-policy, initial-policy-mapping-inhibit and initial-any-policy-inhibit.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_initial_policy_flags(config: *mut PathConfig, explicit_policy: bool, policy_mapping_inhibit: bool, any_policy_inhibit: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.initial_explicit_policy = explicit_policy;
            config.initial_policy_mapping_inhibit = policy_mapping_inhibit;
            config.initial_any_policy_inhibit = any_policy_inhibit;
            Ok(())
        })())
    }

    /// Sets the initial name constraints, the DER `NameConstraints` value of `length` bytes at
    /// `data` (none for 0 bytes).
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_initial_name_constraints(config: *mut PathConfig, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.initial_name_constraints = PathStatus::name_constraints(unsafe { Pointer::slice(data, length) }?)?;
            Ok(())
        })())
    }

    /// Sets the most intermediate certificates (not counting self-issued ones), signatures and
    /// name comparisons.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_limits(config: *mut PathConfig, maximum_intermediates: usize, maximum_signatures: usize, maximum_name_checks: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.maximum_intermediates = maximum_intermediates;
            config.maximum_signatures = maximum_signatures;
            config.maximum_name_checks = maximum_name_checks;
            Ok(())
        })())
    }

    /// Sets the largest RSA modulus and exponent (in bits) accepted.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_key_limits(config: *mut PathConfig, maximum_rsa_bits: u32, maximum_rsa_exponent_bits: u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.key_limits = KeyLimits { maximum_rsa_bits, maximum_rsa_exponent_bits };
            Ok(())
        })())
    }

    /// Sets whether signatures that hash with SHA-1 are accepted.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_accept_sha1(config: *mut PathConfig, accept: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.accept_sha1 = accept;
            Ok(())
        })())
    }

    /// Sets whether revocation is checked, whether an unknown status fails, whether delta CRLs are
    /// applied, and how long (in seconds) a CRL or a status without `nextUpdate` is current.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_revocation(config: *mut PathConfig, check: bool, require: bool, use_deltas: bool, lifetime_without_next_update: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.revocation = RevocationConfig { check, require, use_deltas, lifetime_without_next_update };
            Ok(())
        })())
    }

    /// Sets the key usages (the bits of x509, bit 0 `digitalSignature` as `1 << 0`) the target's key
    /// must allow if `has_key_usage`; none otherwise.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_key_usage(config: *mut PathConfig, has_key_usage: bool, bits: u16) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.key_usage = if has_key_usage { Some(KeyUsage { bits }) } else { None };
            Ok(())
        })())
    }

    /// Sets the purpose, the dotted object identifier of `length` bytes at `purpose`, that the
    /// target's extended key usage must allow (none for 0 bytes).
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_extended_key_usage(config: *mut PathConfig, purpose: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let purpose = unsafe { Pointer::text(purpose, length) }?;
            config.extended_key_usage = if purpose.is_empty() { None } else { Some(X509Status::oid(purpose)?) };
            Ok(())
        })())
    }

    /// Sets the identity the target must name: the [`ServiceIdentityKind`] `kind` and the `length`
    /// bytes at `data` (none for `kind` 0).
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_set_identity(config: *mut PathConfig, kind: u8, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.identity = ServiceIdentityKind::decode(kind, unsafe { Pointer::slice(data, length) }?)?;
            Ok(())
        })())
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_config_free(config: *mut PathConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Writes the anchor of the name `name` and the key `public_key`, with the name constraints of
    /// the DER `NameConstraints` value of `length` bytes at `name_constraints` (none for 0 bytes), into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchor_new(name: *const Name<'static>, public_key: *const PublicKey, name_constraints: *const u8, length: usize, out: *mut *mut TrustAnchor) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable bytes and a writable pointer.
            let name = unsafe { Pointer::reference(name) }?;
            let public_key = unsafe { Pointer::reference(public_key) }?;
            let constraints = PathStatus::name_constraints(unsafe { Pointer::slice(name_constraints, length) }?)?;
            let anchor = TrustAnchor { name_constraints: constraints, ..TrustAnchor::new(name.clone(), public_key.clone()) };
            unsafe { Pointer::write_handle(out, anchor) }
        })())
    }

    /// Writes the anchor of a copy of `certificate` (its subject, its key within the limits of
    /// `maximum_rsa_bits` and `maximum_rsa_exponent_bits`, and its name constraints) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchor_from_certificate(certificate: *const Certificate<'static>, maximum_rsa_bits: u32, maximum_rsa_exponent_bits: u32, out: *mut *mut TrustAnchor) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let certificate = unsafe { Pointer::reference(certificate) }?;
            let limits = KeyLimits { maximum_rsa_bits, maximum_rsa_exponent_bits };
            let anchor = TrustAnchor::from_certificate(certificate.clone(), &limits).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, anchor) }
        })())
    }

    /// Writes the name of the anchor into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchor_name(anchor: *const TrustAnchor, out: *mut *mut Name<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let anchor = unsafe { Pointer::reference(anchor) }?;
            unsafe { Pointer::write_handle(out, anchor.name.clone()) }
        })())
    }

    /// Writes the key of the anchor into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchor_public_key(anchor: *const TrustAnchor, out: *mut *mut PublicKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let anchor = unsafe { Pointer::reference(anchor) }?;
            unsafe { Pointer::write_handle(out, anchor.public_key.clone()) }
        })())
    }

    /// Releases an anchor. Does nothing if `anchor` is null.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchor_free(anchor: *mut TrustAnchor) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(anchor) }
    }

    /// Writes an empty list of anchors into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchors_new(out: *mut *mut Vec<TrustAnchor>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<TrustAnchor>::new()) })
    }

    /// Appends a copy of `anchor` to the list.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchors_push(anchors: *mut Vec<TrustAnchor>, anchor: *const TrustAnchor) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let anchors = unsafe { Pointer::reference_mut(anchors) }?;
            let anchor = unsafe { Pointer::reference(anchor) }?;
            anchors.push(anchor.clone());
            Ok(())
        })())
    }

    /// Writes the number of anchors of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchors_count(anchors: *const Vec<TrustAnchor>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let anchors = unsafe { Pointer::reference(anchors) }?;
            unsafe { Pointer::write(out, anchors.len()) }
        })())
    }

    /// Releases a list of anchors. Does nothing if `anchors` is null.
    pub unsafe extern "C" fn umilib_auth_cert_path_trust_anchors_free(anchors: *mut Vec<TrustAnchor>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(anchors) }
    }

    /// Writes an empty list of revocation sources into `out`; the modules of the sources add to it.
    pub unsafe extern "C" fn umilib_auth_cert_path_revocation_sources_new(out: *mut *mut RevocationSources) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, RevocationSources::default()) })
    }

    /// Writes the number of sources of the list into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_revocation_sources_count(sources: *const RevocationSources, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let sources = unsafe { Pointer::reference(sources) }?;
            unsafe { Pointer::write(out, sources.sources.len()) }
        })())
    }

    /// Releases a list of revocation sources. Does nothing if `sources` is null.
    pub unsafe extern "C" fn umilib_auth_cert_path_revocation_sources_free(sources: *mut RevocationSources) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(sources) }
    }

    /// Builds a path from `target` through `intermediates` to one of `anchors` and validates it
    /// under `config`, with the CRLs `crls` and the revocation sources `sources` (null for none),
    /// and writes the outcome into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_validator_validate(config: *const PathConfig, anchors: *const Vec<TrustAnchor>, intermediates: *const Vec<Certificate<'static>>, crls: *const Vec<CertificateList<'static>>, sources: *const RevocationSources, target: *const Certificate<'static>, out: *mut *mut PathOutcome) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles (or a null list of sources) and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let anchors = unsafe { Pointer::reference(anchors) }?;
            let intermediates = unsafe { Pointer::reference(intermediates) }?;
            let crls = unsafe { Pointer::reference(crls) }?;
            let target = unsafe { Pointer::reference(target) }?;
            let sources: Vec<&dyn RevocationSource> = if sources.is_null() {
                Vec::new()
            } else {
                unsafe { Pointer::reference(sources) }?.sources.iter().map(|source| source.as_ref()).collect()
            };
            let validator = PathValidator::new(config, anchors, intermediates, crls).with_sources(&sources);
            let outcome = match validator.validate(target) {
                Ok(path) => PathOutcome {
                    certificates: path.certificates.iter().map(|&certificate| certificate.clone().into_owned()).collect(),
                    anchor: anchors.iter().position(|anchor| core::ptr::eq(anchor, path.anchor)).unwrap_or_default(),
                    policies: path.policies,
                    error: None,
                },
                Err(error) => PathOutcome { certificates: Vec::new(), anchor: 0, policies: Vec::new(), error: Some(error) },
            };
            unsafe { Pointer::write_handle(out, outcome) }
        })())
    }

    /// Writes whether the path validated into `out_valid` and, if it did not, the status of the
    /// reason into `out_reason`, the index of the certificate it concerns (0 for the target) into
    /// `out_index` and, for a revoked certificate, the code of the reason into `out_revocation_reason`
    /// (null, 0 and 255 otherwise).
    pub unsafe extern "C" fn umilib_auth_cert_path_path_outcome_error(outcome: *const PathOutcome, out_valid: *mut bool, out_reason: *mut *const Status, out_index: *mut usize, out_revocation_reason: *mut u8) -> *const Status {
        Status::from_result((|| {
            if out_valid.is_null() || out_reason.is_null() || out_index.is_null() || out_revocation_reason.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a valid handle and writable pointers.
            let outcome = unsafe { Pointer::reference(outcome) }?;
            let reason: *const Status = outcome.error.map_or(core::ptr::null(), |error| error.to_status());
            let revocation = match outcome.error.map(|error| error.reason) {
                Some(PathErrorReason::Revoked(reason)) => reason as u8,
                _ => PathOutcome::NO_REASON,
            };
            unsafe { Pointer::write(out_valid, outcome.error.is_none()) }?;
            unsafe { Pointer::write(out_reason, reason) }?;
            unsafe { Pointer::write(out_index, outcome.error.map_or(0, |error| error.index)) }?;
            unsafe { Pointer::write(out_revocation_reason, revocation) }
        })())
    }

    /// Writes copies of the certificates of the path, from the target (none if it did not
    /// validate), into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_outcome_certificates(outcome: *const PathOutcome, out: *mut *mut Vec<Certificate<'static>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let outcome = unsafe { Pointer::reference(outcome) }?;
            unsafe { Pointer::write_handle(out, outcome.certificates.clone()) }
        })())
    }

    /// Writes the index, in the list of anchors validated against, of the anchor of the path into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_outcome_anchor(outcome: *const PathOutcome, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let outcome = unsafe { Pointer::reference(outcome) }?;
            unsafe { Pointer::write(out, outcome.anchor) }
        })())
    }

    /// Writes the user-constrained policy set of the path (dotted, separated by commas; it has
    /// anyPolicy when every policy is valid) into `out`.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_outcome_policies(outcome: *const PathOutcome, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let outcome = unsafe { Pointer::reference(outcome) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(PathStatus::oids_text(&outcome.policies).into_bytes())) }
        })())
    }

    /// Releases an outcome. Does nothing if `outcome` is null.
    pub unsafe extern "C" fn umilib_auth_cert_path_path_outcome_free(outcome: *mut PathOutcome) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(outcome) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "path",
    definitions: &[
        Definition::Opaque {
            name: "umilib_auth_cert_path_PathConfig",
            documentation: " The inputs of path validation and the limits of path building.",
        },
        Definition::Opaque { name: "umilib_auth_cert_path_TrustAnchor", documentation: " A trust anchor." },
        Definition::Opaque { name: "umilib_auth_cert_path_TrustAnchors", documentation: " A list of trust anchors." },
        Definition::Opaque {
            name: "umilib_auth_cert_path_RevocationSources",
            documentation: " The revocation sources of a validation other than its CRLs.",
        },
        Definition::Opaque {
            name: "umilib_auth_cert_path_PathOutcome",
            documentation: " The outcome of a validation: the path, or the error.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
