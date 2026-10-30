use alloc::vec::Vec;

use crate::auth::cert::key::{PrivateKey, PublicKey};
use crate::auth::cert::path::{PathConfig, PathErrorReason, PathValidator, ServiceIdentity, TrustAnchor};
use crate::auth::cert::x509::{Certificate, ExtendedKeyUsage};
use crate::codec::asn1::ASN1Time;

use super::{TLSAlertDescription, TLSAuthentication, TLSError, TLSNamedGroup, TLSSignatureScheme, TLSVersion};

/// What decides whether a peer's certificate chain is accepted: the
/// check of RFC 9846 §4.5.1.3. [`TLSPathVerifier`] validates paths to trust
/// anchors (RFC 5280, RFC 9525); an application can bring its own, such as
/// pinning.
pub trait TLSCertificateVerifier: Send + Sync {
    /// Checks `chain` (DER, the end-entity certificate first) at `time`
    /// (seconds since 1970), for `identity` if the peer must have one, with
    /// the stapled OCSP response `ocsp` if any. Fails with the alert to send.
    fn verify(
        &self,
        chain: &[Vec<u8>],
        identity: Option<&ServiceIdentity>,
        ocsp: Option<&[u8]>,
        time: i64,
    ) -> Result<(), TLSAlertDescription>;
}

/// Path validation to trust anchors (RFC 5280 §6) with the identity of RFC
/// 9525: the default [`TLSCertificateVerifier`]. `config` is the template of
/// every validation: its time and identity are those of the connection.
pub struct TLSPathVerifier {
    pub anchors: Vec<TrustAnchor>,
    pub config: PathConfig,
}

impl TLSPathVerifier {
    /// The verification of servers: the Web PKI profile, `id-kp-serverAuth`.
    pub fn servers(anchors: Vec<TrustAnchor>) -> TLSPathVerifier {
        let time = ASN1Time::from_unix_seconds(0).expect("the epoch is a time");
        let mut config = PathConfig::web_pki_server(time, ServiceIdentity::DNS(alloc::string::String::new()));
        config.identity = None;
        TLSPathVerifier { anchors, config }
    }

    /// The verification of clients: the profile of RFC 5280, `id-kp-clientAuth`.
    pub fn clients(anchors: Vec<TrustAnchor>) -> TLSPathVerifier {
        let time = ASN1Time::from_unix_seconds(0).expect("the epoch is a time");
        let config = PathConfig { extended_key_usage: Some(ExtendedKeyUsage::CLIENT_AUTH), ..PathConfig::new(time) };
        TLSPathVerifier { anchors, config }
    }

    /// The alert of a failed validation (RFC 9846 §6.2).
    pub fn alert(reason: PathErrorReason) -> TLSAlertDescription {
        match reason {
            PathErrorReason::NoPath | PathErrorReason::NameChaining => TLSAlertDescription::UNKNOWN_CA,
            PathErrorReason::Validity => TLSAlertDescription::CERTIFICATE_EXPIRED,
            PathErrorReason::Revoked(_) => TLSAlertDescription::CERTIFICATE_REVOKED,
            PathErrorReason::Algorithm | PathErrorReason::Key(_) => TLSAlertDescription::UNSUPPORTED_CERTIFICATE,
            PathErrorReason::RevocationUnknown | PathErrorReason::InvalidResponse => {
                TLSAlertDescription::CERTIFICATE_UNKNOWN
            }
            _ => TLSAlertDescription::BAD_CERTIFICATE,
        }
    }
}

/// Validates the path; a stapled OCSP response, when `auth-cert-ocsp` is
/// compiled in, is a revocation source of it (RFC 6066 §8, RFC 9846
/// §4.5.1.1): a response that says the certificate is revoked fails with
/// `certificate_revoked`, one that cannot be read or used with
/// `bad_certificate_status_response`, and one that says nothing current
/// about it leaves its status to the configuration's revocation checking.
/// Without `auth-cert-ocsp` the response is not read.
impl TLSCertificateVerifier for TLSPathVerifier {
    fn verify(
        &self,
        chain: &[Vec<u8>],
        identity: Option<&ServiceIdentity>,
        ocsp: Option<&[u8]>,
        time: i64,
    ) -> Result<(), TLSAlertDescription> {
        let (target, intermediates) = chain.split_first().ok_or(TLSAlertDescription::CERTIFICATE_REQUIRED)?;
        let target = Certificate::from_der(target).map_err(|_| TLSAlertDescription::BAD_CERTIFICATE)?;
        let intermediates: Vec<Certificate<'_>> = intermediates
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<_, _>>()
            .map_err(|_| TLSAlertDescription::BAD_CERTIFICATE)?;
        let time = ASN1Time::from_unix_seconds(time).map_err(|_| TLSAlertDescription::INTERNAL_ERROR)?;
        let config = PathConfig { time, identity: identity.cloned(), ..self.config.clone() };
        #[cfg(umilib_feature = "auth-cert-ocsp")]
        if let Some(ocsp) = ocsp {
            use crate::auth::cert::ocsp::OCSPResponse;
            use crate::auth::cert::path::{PathErrorReason, RevocationSource};
            let bad = TLSAlertDescription::BAD_CERTIFICATE_STATUS_RESPONSE;
            let response = OCSPResponse::from_der(ocsp).map_err(|_| bad)?;
            let mut config = config;
            config.revocation.check = true;
            let sources: [&dyn RevocationSource; 1] = [&response];
            let validator = PathValidator::new(&config, &self.anchors, &intermediates, &[]).with_sources(&sources);
            return validator.validate(&target).map(|_| ()).map_err(|error| match error.reason {
                PathErrorReason::InvalidResponse => bad,
                reason => TLSPathVerifier::alert(reason),
            });
        }
        #[cfg(not(umilib_feature = "auth-cert-ocsp"))]
        let _ = ocsp;
        let validator = PathValidator::new(&config, &self.anchors, &intermediates, &[]);
        validator.validate(&target).map(|_| ()).map_err(|error| TLSPathVerifier::alert(error.reason))
    }
}

/// A certificate chain and the private key of its first certificate: what
/// a server (or a client asked for one) presents (RFC 9846 §4.5.1).
pub struct TLSCertifiedKey {
    /// DER certificates, the end-entity certificate first.
    pub chain: Vec<Vec<u8>>,
    pub key: PrivateKey,
    /// The OCSP response to staple, if any (RFC 9846 §4.5.1.1).
    pub ocsp: Option<Vec<u8>>,
}

impl TLSCertifiedKey {
    /// Whether the end-entity certificate names `identity`.
    pub fn names(&self, identity: &ServiceIdentity) -> bool {
        self.chain
            .first()
            .and_then(|der| Certificate::from_der(der).ok())
            .is_some_and(|certificate| identity.matches(&certificate).unwrap_or(false))
    }

    /// The first scheme of `offered` that this end also `allowed` and that
    /// this key can sign with in `version`, in the order of `offered` (the
    /// peer's preference).
    pub fn scheme(
        &self,
        offered: &[TLSSignatureScheme],
        allowed: &[TLSSignatureScheme],
        version: TLSVersion,
    ) -> Option<TLSSignatureScheme> {
        offered
            .iter()
            .copied()
            .find(|scheme| allowed.contains(scheme) && scheme.signs_with(self.key.algorithm(), version))
    }
}

impl TLSSignatureScheme {
    /// The signature algorithm of the scheme (RFC 9846 §4.3.3): RSASSA-PSS
    /// with MGF1 of the same hash and a salt of the hash's length.
    pub fn algorithm(self) -> Option<crate::auth::cert::key::SignatureAlgorithm> {
        use crate::auth::cert::key::{HashAlgorithm, PSSParameters, SignatureAlgorithm};
        Some(match self {
            TLSSignatureScheme::RSA_PKCS1_SHA256 => SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256),
            TLSSignatureScheme::RSA_PKCS1_SHA384 => SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA384),
            TLSSignatureScheme::RSA_PKCS1_SHA512 => SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA512),
            TLSSignatureScheme::ECDSA_SECP256R1_SHA256 => SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256),
            TLSSignatureScheme::ECDSA_SECP384R1_SHA384 => SignatureAlgorithm::ECDSA(HashAlgorithm::SHA384),
            TLSSignatureScheme::ECDSA_SECP521R1_SHA512 => SignatureAlgorithm::ECDSA(HashAlgorithm::SHA512),
            TLSSignatureScheme::RSA_PSS_RSAE_SHA256 | TLSSignatureScheme::RSA_PSS_PSS_SHA256 => {
                SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA256))
            }
            TLSSignatureScheme::RSA_PSS_RSAE_SHA384 | TLSSignatureScheme::RSA_PSS_PSS_SHA384 => {
                SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA384))
            }
            TLSSignatureScheme::RSA_PSS_RSAE_SHA512 | TLSSignatureScheme::RSA_PSS_PSS_SHA512 => {
                SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA512))
            }
            TLSSignatureScheme::ED25519 => SignatureAlgorithm::Ed25519,
            TLSSignatureScheme::ED448 => SignatureAlgorithm::Ed448,
            _ => return None,
        })
    }

    /// Whether a key of `key` can make signatures of the scheme in the
    /// handshakes of `version` (RFC 9846 §4.3.3): `rsa_pss_rsae` needs an
    /// rsaEncryption key and `rsa_pss_pss` an RSASSA-PSS key; in TLS 1.3 an
    /// ECDSA scheme names its curve, in TLS 1.2 only its hash.
    pub fn signs_with(self, key: &crate::auth::cert::key::KeyAlgorithm, version: TLSVersion) -> bool {
        use crate::auth::cert::key::{KeyAlgorithm, NamedCurve};
        if !self.signs_handshakes_of(version) {
            return false;
        }
        match (self, key) {
            (
                TLSSignatureScheme::RSA_PKCS1_SHA256
                | TLSSignatureScheme::RSA_PKCS1_SHA384
                | TLSSignatureScheme::RSA_PKCS1_SHA512
                | TLSSignatureScheme::RSA_PSS_RSAE_SHA256
                | TLSSignatureScheme::RSA_PSS_RSAE_SHA384
                | TLSSignatureScheme::RSA_PSS_RSAE_SHA512,
                KeyAlgorithm::RSA,
            ) => true,
            (
                TLSSignatureScheme::RSA_PSS_PSS_SHA256
                | TLSSignatureScheme::RSA_PSS_PSS_SHA384
                | TLSSignatureScheme::RSA_PSS_PSS_SHA512,
                KeyAlgorithm::RSAPSS(parameters),
            ) => {
                let Some(crate::auth::cert::key::SignatureAlgorithm::RSAPSS(own)) = self.algorithm() else {
                    return false;
                };
                parameters.is_none_or(|parameters| parameters.hash == own.hash)
            }
            (TLSSignatureScheme::ECDSA_SECP256R1_SHA256, KeyAlgorithm::EC(curve)) if version == TLSVersion::TLS1_3 => {
                *curve == NamedCurve::P256
            }
            (TLSSignatureScheme::ECDSA_SECP384R1_SHA384, KeyAlgorithm::EC(curve)) if version == TLSVersion::TLS1_3 => {
                *curve == NamedCurve::P384
            }
            (TLSSignatureScheme::ECDSA_SECP521R1_SHA512, KeyAlgorithm::EC(curve)) if version == TLSVersion::TLS1_3 => {
                *curve == NamedCurve::P521
            }
            (
                TLSSignatureScheme::ECDSA_SECP256R1_SHA256
                | TLSSignatureScheme::ECDSA_SECP384R1_SHA384
                | TLSSignatureScheme::ECDSA_SECP521R1_SHA512,
                KeyAlgorithm::EC(curve),
            ) => matches!(curve, NamedCurve::P256 | NamedCurve::P384 | NamedCurve::P521),
            (TLSSignatureScheme::ED25519, KeyAlgorithm::Ed25519) | (TLSSignatureScheme::ED448, KeyAlgorithm::Ed448) => {
                true
            }
            _ => false,
        }
    }

    /// Verifies the peer's signature of `message` with its key `key` in the
    /// handshake of `version`. Fails with `illegal_parameter` for a scheme
    /// the key cannot use, and `decrypt_error` for a signature that does
    /// not verify (RFC 9846 §4.5.2).
    pub fn verify(
        self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
        version: TLSVersion,
    ) -> Result<(), TLSError> {
        let algorithm =
            self.algorithm().filter(|_| self.signs_with(key.algorithm(), version)).ok_or(TLSError::illegal())?;
        key.verify(&algorithm, message, signature).map_err(|_| TLSError::Protocol(TLSAlertDescription::DECRYPT_ERROR))
    }

    /// Signs `message` with `key`; fails with `internal_error` if the key
    /// cannot sign with the scheme.
    pub fn sign<R: crate::crypto::random::Random>(
        self,
        key: &PrivateKey,
        message: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, TLSError> {
        let internal = TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let algorithm = self.algorithm().ok_or(internal)?;
        key.sign(&algorithm, message, random).map_err(|_| internal)
    }
}

impl TLSAuthentication {
    /// Whether a certificate's key of `key` can authenticate a TLS 1.2
    /// suite of this kind: RSA keys for ECDHE_RSA, ECDSA and EdDSA keys for
    /// ECDHE_ECDSA (RFC 8422 §2, §3).
    pub fn accepts(self, key: &crate::auth::cert::key::KeyAlgorithm) -> bool {
        use crate::auth::cert::key::{KeyAlgorithm, NamedCurve};
        match self {
            TLSAuthentication::RSA => matches!(key, KeyAlgorithm::RSA | KeyAlgorithm::RSAPSS(_)),
            TLSAuthentication::ECDSA => matches!(
                key,
                KeyAlgorithm::EC(NamedCurve::P256 | NamedCurve::P384 | NamedCurve::P521)
                    | KeyAlgorithm::Ed25519
                    | KeyAlgorithm::Ed448
            ),
        }
    }
}

impl TLSNamedGroup {
    /// The group of an elliptic curve of certificates, which a TLS 1.2
    /// client's `supported_groups` must list for an ECDSA certificate on
    /// it (RFC 8422 §5.1.1).
    pub fn of_curve(curve: crate::auth::cert::key::NamedCurve) -> Option<TLSNamedGroup> {
        use crate::auth::cert::key::NamedCurve;
        match curve {
            NamedCurve::P256 => Some(TLSNamedGroup::SECP256R1),
            NamedCurve::P384 => Some(TLSNamedGroup::SECP384R1),
            NamedCurve::P521 => Some(TLSNamedGroup::SECP521R1),
            _ => None,
        }
    }
}
