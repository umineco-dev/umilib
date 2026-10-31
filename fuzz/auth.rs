//! Fuzz targets of `umilib::auth`.

use umilib::platform::fuzz::FuzzTarget;

/// HOTP against the algorithm of RFC 4226 §5.3 written out with HMAC, and
/// every password verifies at its counter.
#[cfg(all(umilib_feature = "auth-totp", umilib_feature = "hash-sha-v1"))]
pub const OTPS: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-otps", |data| {
        use umilib::auth::totp::{HOTP, OTPError};
        use umilib::crypto::hmac::HMAC;
        use umilib::hash::sha::v1::SHA1;
        let Some((&control, rest)) = data.split_first() else { return };
        let digits = u32::from(control % 12);
        let (counter, key) = if rest.len() >= 8 {
            (u64::from_le_bytes(rest[..8].try_into().expect("eight bytes")), &rest[8..])
        } else {
            (0, rest)
        };
        let hotp = match HOTP::<SHA1>::new(key, digits) {
            Ok(hotp) => hotp,
            Err(OTPError::KeyTooShort) => return assert!(key.len() < 16),
            Err(OTPError::Digits) => return assert!(!(6..=10).contains(&digits)),
            Err(error) => panic!("{error:?}"),
        };
        let code = hotp.generate(counter).expect("the digits were checked");
        let digest = HMAC::<SHA1>::mac(key, &counter.to_be_bytes());
        let offset = (digest[19] & 0x0F) as usize;
        let binary =
            u32::from_be_bytes([digest[offset] & 0x7F, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
        assert_eq!(u64::from(code.value()), u64::from(binary) % 10u64.pow(digits));
        let text = code.to_string();
        assert_eq!(text.len(), digits as usize);
        assert_eq!(hotp.verify(text.as_bytes(), counter, 0), Some(counter));
        // A window that contains the counter finds it, or an earlier counter of the same password.
        let found = hotp.verify(text.as_bytes(), counter.saturating_sub(2), 2).expect("the counter is in the window");
        assert!(found <= counter && hotp.generate(found) == Ok(code));
    });

/// Algorithm identifiers, public keys, PKCS #8 keys and encrypted keys
/// decode without panicking, and what decodes encodes to what decodes to
/// the same.
#[cfg(umilib_feature = "auth-cert-key")]
pub const KEYS: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-cert-keys", |data| {
        use umilib::auth::cert::key::{
            AlgorithmIdentifier, EncryptedPrivateKeyInfo, KeyAlgorithm, PBES2Config, PrivateKey, PublicKey,
            SignatureAlgorithm,
        };
        // An identifier at the start of the input, and the rest as a signature: verifying it with
        // keys of every family returns, whatever the parameters (a salt length of RSASSA-PSS that
        // does not fit, for one) and the signature.
        let mut reader = umilib::codec::asn1::der::DERReader::new(data);
        if let Ok(identifier) = AlgorithmIdentifier::decode(&mut reader)
            && let Ok(algorithm) = SignatureAlgorithm::from_identifier(&identifier)
        {
            let signature = &data[reader.position()..];
            for key in OpenSSLKeys::public_keys() {
                let _ = key.verify(&algorithm, b"message", signature);
            }
        }
        if let Ok(identifier) = AlgorithmIdentifier::from_der(data) {
            if let Ok(algorithm) = SignatureAlgorithm::from_identifier(&identifier) {
                let again = algorithm.identifier().expect("an algorithm read has an identifier");
                assert_eq!(SignatureAlgorithm::from_identifier(&again), Ok(algorithm));
            }
            if let Ok(algorithm) = KeyAlgorithm::from_identifier(&identifier) {
                let again = algorithm.identifier().expect("an algorithm read has an identifier");
                assert_eq!(KeyAlgorithm::from_identifier(&again), Ok(algorithm));
            }
        }
        if let Ok(key) = PublicKey::from_der(data) {
            let der = key.to_der().expect("a key read encodes");
            assert_eq!(PublicKey::from_der(&der), Ok(key));
        }
        if let Ok(key) = PrivateKey::from_pkcs8_der(data) {
            let der = key.to_pkcs8_der().expect("a key read encodes");
            let again = PrivateKey::from_pkcs8_der(der.expose()).expect("a key written reads");
            assert_eq!(again.public_key().ok(), key.public_key().ok());
        }
        if let Ok(info) = EncryptedPrivateKeyInfo::from_der(data) {
            assert_eq!(info.to_der().expect("an encrypted key read encodes"), data);
            // Few iterations, so that a hostile input costs little.
            let config = PBES2Config { maximum_iterations: 64, ..PBES2Config::default() };
            let _ = info.decrypt(b"password", &config);
        }
    });

/// Checks that a value of the extension type `$type` read from `$data`
/// writes, if its fields meet the rules of writing, an encoding that reads
/// to the same value.
#[cfg(umilib_feature = "auth-cert-x509")]
macro_rules! check_extension_value {
    ($data:expr, $($type:ty),* $(,)?) => {
        $(
            if let Ok(value) = <$type as umilib::auth::cert::x509::ExtensionValue>::from_der($data)
                && let Ok(der) = umilib::auth::cert::x509::ExtensionValue::to_der(&value)
            {
                let again = <$type as umilib::auth::cert::x509::ExtensionValue>::from_der(&der).expect("a value written reads");
                assert_eq!(again, value, stringify!($type));
            }
        )*
    };
}

/// Every extension type of `umilib::auth::cert::x509` read from `data`.
#[cfg(umilib_feature = "auth-cert-x509")]
pub struct ExtensionValues;

#[cfg(umilib_feature = "auth-cert-x509")]
impl ExtensionValues {
    pub fn check(data: &[u8]) {
        use umilib::auth::cert::x509::*;
        check_extension_value!(
            data,
            AuthorityKeyIdentifier,
            SubjectKeyIdentifier,
            KeyUsage,
            ExtendedKeyUsage,
            PrivateKeyUsagePeriod,
            CertificatePolicies,
            PolicyMappings,
            SubjectAlternativeName,
            IssuerAlternativeName,
            SubjectDirectoryAttributes,
            BasicConstraints,
            NameConstraints,
            PolicyConstraints,
            InhibitAnyPolicy,
            CRLDistributionPoints,
            FreshestCRL,
            AuthorityInformationAccess,
            SubjectInformationAccess,
            CRLNumber,
            DeltaCRLIndicator,
            IssuingDistributionPoint,
            CRLReason,
            InvalidityDate,
            HoldInstructionCode,
            CertificateIssuer,
        );
        if let Ok(value) = PolicyQualifierInfo::decode(&mut umilib::codec::asn1::der::DERReader::new(data)) {
            let _ = value.cps_uri();
            let _ = value.notice();
        }
    }
}

/// Certificates, CRLs, names and extension values decode without
/// panicking; a certificate or CRL read writes back to its bytes, and its
/// signed fields write an encoding that reads to the same fields.
#[cfg(umilib_feature = "auth-cert-x509")]
pub const CERTIFICATES: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-cert-x509", |data| {
        use umilib::auth::cert::x509::{Certificate, CertificateList, Name, TBSCertList, TBSCertificate};
        ExtensionValues::check(data);
        if let Ok(name) = Name::from_der(data) {
            assert_eq!(name.as_der(), data);
            let _ = name.to_rfc4514();
            assert!(name.rdns().count() <= data.len() && name.attributes().count() <= data.len());
        }
        if let Ok(certificate) = Certificate::from_der(data) {
            assert_eq!(certificate.to_der().expect("a certificate read encodes"), data);
            let tbs = certificate.tbs_certificate();
            let der = tbs.to_der().expect("fields read encode");
            assert_eq!(&TBSCertificate::from_der(&der).expect("fields written read"), tbs);
            let _ = tbs.subject.to_rfc4514();
            let _ = tbs.check();
            tbs.extensions.entries.iter().for_each(|extension| ExtensionValues::check(&extension.value));
            for key in OpenSSLKeys::public_keys() {
                let _ = certificate.verify(key);
            }
            let _ = certificate.public_key();
        }
        if let Ok(list) = CertificateList::from_der(data) {
            assert_eq!(list.to_der().expect("a CRL read encodes"), data);
            let tbs = list.tbs_cert_list();
            let der = tbs.to_der().expect("fields read encode");
            assert_eq!(&TBSCertList::from_der(&der).expect("fields written read"), tbs);
            for entry in &tbs.revoked_certificates {
                assert!(list.find(&entry.serial_number).is_some());
                entry.extensions.entries.iter().for_each(|extension| ExtensionValues::check(&extension.value));
            }
            for key in OpenSSLKeys::public_keys() {
                let _ = list.verify(key);
            }
        }
    });

/// Certification requests decode without panicking, write back to their
/// bytes, and their requested extensions and signature are checked.
#[cfg(umilib_feature = "auth-cert-csr")]
pub const REQUESTS: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-cert-csr", |data| {
        use umilib::auth::cert::csr::{CertificationRequest, CertificationRequestInfo};
        if let Ok(request) = CertificationRequest::from_der(data) {
            assert_eq!(request.to_der().expect("a request read encodes"), data);
            let der = request.info().to_der().expect("information read encodes");
            assert_eq!(&CertificationRequestInfo::from_der(&der).expect("information written reads"), request.info());
            if let Ok(extensions) = request.info().extensions() {
                extensions.entries.iter().for_each(|extension| ExtensionValues::check(&extension.value));
            }
            let _ = request.verify();
        }
    });

/// OCSP requests, responses and certificate identifiers decode without
/// panicking and write back to their bytes; the checks of a response
/// return, and as a revocation source it says something only about the
/// certificates it names.
#[cfg(umilib_feature = "auth-cert-ocsp")]
pub const STATUSES: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-cert-ocsp", |data| {
        use umilib::auth::cert::ocsp::{BasicOCSPResponse, CertID, OCSPConfig, OCSPRequest, OCSPResponse};
        use umilib::auth::cert::x509::Certificate;
        if let Ok(cert_id) = CertID::from_der(data) {
            assert_eq!(cert_id.to_der().expect("an identifier read encodes"), data);
            assert!(
                cert_id.matches(&cert_id)
                    || umilib::auth::cert::key::HashAlgorithm::from_identifier(&cert_id.hash_algorithm).is_err()
            );
        }
        if let Ok(request) = OCSPRequest::from_der(data) {
            assert_eq!(request.to_der().expect("a request read encodes"), data);
            let _ = request.tbs_request().nonce();
            for key in OpenSSLKeys::public_keys() {
                let _ = request.verify(key);
            }
        }
        let issuer = OCSPFixtures::root();
        let issuer_key = issuer.public_key().expect("the fixture has a key");
        let check = |basic: &BasicOCSPResponse<'_>| {
            let config = OCSPConfig::new(OCSPFixtures::time());
            for single in &basic.tbs_response_data().responses {
                let _ = basic.verify(&single.cert_id, &issuer.tbs_certificate().subject, &issuer_key, &config);
            }
            #[cfg(umilib_feature = "auth-cert-path")]
            {
                use umilib::auth::cert::path::{PathBudget, PathConfig, RevocationSource, RevocationStatus};
                let config = PathConfig::new(OCSPFixtures::time());
                let target = OCSPFixtures::good();
                let mut budget = PathBudget::new(&config);
                let subject = &issuer.tbs_certificate().subject;
                let status = basic.status(&target, subject, &issuer_key, &config, &mut budget);
                let named = basic
                    .tbs_response_data()
                    .responses
                    .iter()
                    .any(|single| single.cert_id.identifies(&target, issuer_key.key()));
                assert!(
                    named || status == Ok(RevocationStatus::Undetermined),
                    "a response says nothing of a certificate it does not name"
                );
            }
        };
        if let Ok(response) = OCSPResponse::from_der(data) {
            assert_eq!(response.to_der().expect("a response read encodes"), data);
            if let Ok(basic) = response.basic() {
                check(basic);
            }
        }
        if let Ok(basic) = BasicOCSPResponse::from_der(data) {
            assert_eq!(basic.to_der().expect("a basic response read encodes"), data);
            let _: Option<&Certificate<'_>> = basic.certificates().first();
            check(&basic);
        }
    });

/// The certificates of the OCSP fixtures that OpenSSL made, and a time at which their responses are current.
#[cfg(umilib_feature = "auth-cert-ocsp")]
pub struct OCSPFixtures;

#[cfg(umilib_feature = "auth-cert-ocsp")]
impl OCSPFixtures {
    pub fn root() -> umilib::auth::cert::x509::Certificate<'static> {
        umilib::auth::cert::x509::Certificate::from_der(include_bytes!(
            "../tests/vectors/auth/cert/ocsp/openssl/root.der"
        ))
        .expect("the fixture is a certificate")
    }

    pub fn good() -> umilib::auth::cert::x509::Certificate<'static> {
        umilib::auth::cert::x509::Certificate::from_der(include_bytes!(
            "../tests/vectors/auth/cert/ocsp/openssl/good.der"
        ))
        .expect("the fixture is a certificate")
    }

    /// 2027-01-01.
    pub fn time() -> umilib::codec::asn1::ASN1Time {
        umilib::codec::asn1::ASN1Time::new(2027, 1, 1, 0, 0, 0, 0).expect("a valid time")
    }
}

/// Path validation of the certificates and CRLs read one after another
/// from the input (the first certificate the trust anchor, the last the
/// target) under every profile returns, within its budget, a path that
/// chains from the target to the anchor or an error of a certificate of the
/// input. An input that starts with 0 drives a policy graph instead, which
/// stays linear in the policies; one that starts with 1 compares a name
/// with a name constraint.
#[cfg(umilib_feature = "auth-cert-path")]
pub const PATHS: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-cert-path", |data| match data.split_first() {
        Some((0, rest)) => PathInputs::policies(rest),
        Some((1, rest)) => PathInputs::names(rest),
        _ => PathInputs::chain(data),
    });

/// The parts of the target `auth-cert-path`.
#[cfg(umilib_feature = "auth-cert-path")]
pub struct PathInputs;

#[cfg(umilib_feature = "auth-cert-path")]
impl PathInputs {
    /// Certificates and CRLs validated under every profile, with and without revocation checking.
    pub fn chain(data: &[u8]) {
        use umilib::auth::cert::key::KeyLimits;
        use umilib::auth::cert::path::{PathConfig, PathProfile, PathValidator, RevocationConfig, TrustAnchor};
        use umilib::auth::cert::x509::{Certificate, CertificateList};
        let mut reader = umilib::codec::asn1::der::DERReader::new(data);
        let (mut certificates, mut lists) = (Vec::new(), Vec::new());
        while !reader.is_empty() && certificates.len() + lists.len() < 8 {
            let start = reader.position();
            if reader.read_element().is_err() {
                break;
            }
            let bytes = &data[start..reader.position()];
            if let Ok(certificate) = Certificate::from_der(bytes) {
                certificates.push(certificate);
            } else if let Ok(list) = CertificateList::from_der(bytes) {
                lists.push(list);
            }
        }
        let Some(target) = certificates.last() else { return };
        let Ok(anchor) = TrustAnchor::from_certificate(certificates[0].clone().into_owned(), &KeyLimits::default())
        else {
            return;
        };
        let anchors = [anchor];
        // The certificates between the anchor's and the target (none when they are one or two).
        let intermediates = certificates.get(1..certificates.len().saturating_sub(1)).unwrap_or_default();
        let time = target.tbs_certificate().validity.not_before.time();
        for profile in [PathProfile::Algorithm, PathProfile::RFC5280, PathProfile::WebPKI] {
            for revocation in [RevocationConfig::NONE, RevocationConfig::REQUIRED] {
                let config = PathConfig { profile, revocation, maximum_signatures: 32, ..PathConfig::new(time) };
                match PathValidator::new(&config, &anchors, intermediates, &lists).validate(target) {
                    Ok(path) => {
                        assert!(core::ptr::eq(path.certificates[0], target));
                        for pair in path.certificates.windows(2) {
                            assert!(pair[0].tbs_certificate().issuer.matches(&pair[1].tbs_certificate().subject));
                        }
                        let last = path.certificates.last().expect("a path has its target");
                        assert!(last.tbs_certificate().issuer.matches(&path.anchor.name));
                    }
                    Err(error) => assert!(error.index <= certificates.len(), "{error:?}"),
                }
            }
        }
    }

    /// A policy graph of up to 16 certificates, each of up to 8 policies
    /// among 8 and anyPolicy and of up to 8 mappings: at each depth, a node
    /// per policy of the certificate or mapped from it, so never more than 17.
    pub fn policies(data: &[u8]) {
        use umilib::auth::cert::path::PolicyGraph;
        use umilib::auth::cert::x509::{CertificatePolicies, PolicyInformation, PolicyMapping, PolicyMappings};
        use umilib::codec::asn1::ObjectIdentifier;
        let oid = |byte: u8| match byte % 9 {
            0 => CertificatePolicies::ANY_POLICY,
            n => ObjectIdentifier::parse(&format!("1.2.3.{n}")).expect("a valid identifier"),
        };
        let mut graph = PolicyGraph::new();
        for chunk in data.chunks(17).take(16) {
            let (&control, rest) = chunk.split_first().expect("chunks are not empty");
            let (policy_bytes, mapping_bytes) = rest.split_at(rest.len().min(8));
            let mut identifiers: Vec<ObjectIdentifier<'static>> = policy_bytes.iter().map(|&byte| oid(byte)).collect();
            identifiers.sort_unstable();
            identifiers.dedup();
            let policies = CertificatePolicies {
                policies: identifiers
                    .into_iter()
                    .map(|identifier| PolicyInformation { identifier, qualifiers: Vec::new() })
                    .collect(),
            };
            graph.process(&policies, control & 1 != 0);
            let mappings = PolicyMappings {
                mappings: mapping_bytes
                    .chunks(2)
                    .filter(|pair| pair.len() == 2 && pair[0] % 9 != 0 && pair[1] % 9 != 0)
                    .map(|pair| PolicyMapping {
                        issuer_domain_policy: oid(pair[0]),
                        subject_domain_policy: oid(pair[1]),
                    })
                    .collect(),
            };
            graph.map(&mappings, control & 2 != 0);
            assert!(graph.levels.last().expect("a graph has a level").len() <= 17);
            if graph.is_empty() {
                return;
            }
        }
        let initial = [oid(1), oid(2)];
        let constrained = graph.user_constrained_policies(Some(&initial));
        assert!(constrained.iter().all(|policy| initial.contains(policy)));
    }

    /// A name and a constraint, the two lines of the input as text (or its
    /// halves as addresses): their comparisons return, and a valid DNS name
    /// is within itself.
    pub fn names(data: &[u8]) {
        use umilib::auth::cert::path::NameMatching;
        let half = data.len() / 2;
        let _ = NameMatching::ip_within(&data[..half], &data[half..]);
        let Ok(text) = core::str::from_utf8(data) else { return };
        let (name, constraint) = text.split_once('\n').unwrap_or((text, ""));
        let _ = NameMatching::dns_meets(name, constraint);
        let _ = NameMatching::dns_matches(name, constraint);
        let _ = NameMatching::email_within(name, constraint);
        let _ = NameMatching::uri_within(name, constraint);
        let _ = NameMatching::uri_host(name);
        if NameMatching::is_dns_name(name, false) && NameMatching::is_dns_constraint(name) {
            assert!(NameMatching::dns_within(name, name), "{name:?}");
        }
    }
}

/// Public keys of every family of signatures, made by OpenSSL (the fixtures of the key tests).
#[cfg(umilib_feature = "auth-cert-key")]
pub struct OpenSSLKeys;

#[cfg(umilib_feature = "auth-cert-key")]
impl OpenSSLKeys {
    pub fn public_keys() -> &'static [umilib::auth::cert::key::PublicKey] {
        use std::sync::OnceLock;
        use umilib::auth::cert::key::PublicKey;
        static KEYS: OnceLock<Vec<PublicKey>> = OnceLock::new();
        KEYS.get_or_init(|| {
            [
                include_str!("../tests/vectors/auth/cert/key/openssl/rsa.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/rsa-pss.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/p256.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/ed25519.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/ed448.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/mldsa65.pub"),
                include_str!("../tests/vectors/auth/cert/key/openssl/slhdsa-sha2-128f.pub"),
            ]
            .iter()
            .map(|pem| PublicKey::from_pem(pem).expect("the fixtures are keys"))
            .collect()
        })
    }
}

/// The messages of SASL decode without panicking and what decodes writes
/// back to its bytes; the SCRAM client and server run on the input without
/// panicking (with an iteration count of 1 to 16, to bound the work).
#[cfg(all(
    umilib_feature = "auth-sasl-anonymous",
    umilib_feature = "auth-sasl-external",
    umilib_feature = "auth-sasl-oauthbearer",
    umilib_feature = "auth-sasl-plain",
    umilib_feature = "auth-sasl-scram"
))]
pub const SASL: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-sasl", |data| {
        use umilib::auth::sasl::GS2Header;
        use umilib::auth::sasl::anonymous::ANONYMOUSMessage;
        use umilib::auth::sasl::external::EXTERNALMessage;
        use umilib::auth::sasl::oauthbearer::{OAUTHBEARERErrorResult, OAUTHBEARERMessage};
        use umilib::auth::sasl::plain::PLAINMessage;
        use umilib::auth::sasl::scram::{
            SCRAMClient, SCRAMClientFinal, SCRAMClientFirst, SCRAMConfig, SCRAMCredentials, SCRAMSecret, SCRAMServer,
            SCRAMServerFinal, SCRAMServerFirst,
        };
        use umilib::hash::sha::v2::SHA256;
        use umilib::secret::Secret;
        let Some((&selector, rest)) = data.split_first() else { return };
        match selector % 6 {
            0 => {
                if let Ok(message) = PLAINMessage::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes").expose(), rest);
                    let _ = message.verify_password("pencil");
                    let _ = message.prepared_authcid();
                }
            }
            1 => {
                if let Ok(message) = EXTERNALMessage::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                }
                if let Ok(message) = ANONYMOUSMessage::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                }
            }
            2 => {
                if let Ok(text) = core::str::from_utf8(rest)
                    && let Ok((header, tail)) = GS2Header::decode(text)
                {
                    assert_eq!(header.encode().expect("a header read writes"), &text[..text.len() - tail.len()]);
                }
            }
            3 => {
                if let Ok(message) = SCRAMClientFirst::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                }
                if let Ok(message) = SCRAMClientFinal::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                }
                // The server on the input as both client messages.
                let mut server = SCRAMServer::<SHA256>::new(selector & 0x80 != 0);
                server.add_channel_binding("tls-exporter", b"channel");
                if server.receive_client_first(rest).is_ok() {
                    let credentials = SCRAMCredentials::<SHA256>::new("pencil", b"salt", 1).expect("credentials");
                    server.server_first(&credentials, "server").expect("a nonce of printable characters");
                    let _ = server.receive_client_final(rest);
                }
            }
            4 => {
                if let Ok(message) = SCRAMServerFirst::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                }
                let _ = SCRAMServerFinal::decode(rest);
                // The client on the input as both server messages.
                let secret = SCRAMSecret::Password(Secret::new(String::from("pencil")));
                let mut client = SCRAMClient::<SHA256>::new("user", secret, "nonce");
                client.config = SCRAMConfig { minimum_iterations: 1, maximum_iterations: 16 };
                client.client_first().expect("a client-first-message");
                if client.receive_server_first(rest).is_ok() {
                    let _ = client.receive_server_final(rest);
                }
            }
            _ => {
                if let Ok(message) = OAUTHBEARERMessage::decode(rest) {
                    assert_eq!(message.encode().expect("a message read writes"), rest);
                    let _ = (message.bearer_token(), message.port());
                }
                if let Ok(result) = OAUTHBEARERErrorResult::decode(rest) {
                    assert_eq!(
                        OAUTHBEARERErrorResult::decode(&result.encode()).expect("a result written reads"),
                        result
                    );
                }
            }
        }
    });

/// The messages of OAuth read without panicking, and what reads writes back to what reads the
/// same: parameters, requests and responses, documents, scopes, challenges and presented tokens.
#[cfg(umilib_feature = "auth-oauth")]
pub const OAUTH_MESSAGES: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-oauth-messages", |data| {
        use umilib::auth::oauth::{
            DPoPProof, OAuthAuthorizationRequest, OAuthAuthorizationResponse, OAuthChallenge,
            OAuthDeviceAuthorizationResponse, OAuthErrorResponse, OAuthIntrospectionResponse, OAuthMetadata,
            OAuthMetadataKind, OAuthParameters, OAuthPresentedToken, OAuthPushedAuthorizationResponse, OAuthScope,
            OAuthTokenRequest, OAuthTokenResponse,
        };
        if let Ok(parameters) = OAuthParameters::parse(data) {
            assert_eq!(OAuthParameters::parse(parameters.encode().as_bytes()).as_ref(), Ok(&parameters));
            if let Ok(request) = OAuthAuthorizationRequest::from_parameters(&parameters) {
                assert_eq!(OAuthAuthorizationRequest::from_parameters(&request.to_parameters()).as_ref(), Ok(&request));
            }
            if let Ok(response) = OAuthAuthorizationResponse::from_parameters(&parameters) {
                assert_eq!(
                    OAuthAuthorizationResponse::from_parameters(&response.to_parameters()).as_ref(),
                    Ok(&response)
                );
            }
            if let Some(Ok(error)) = OAuthErrorResponse::from_parameters(&parameters) {
                let mut written = OAuthParameters::new();
                error.to_parameters(&mut written);
                assert_eq!(OAuthErrorResponse::from_parameters(&written), Some(Ok(error)));
            }
            if let Ok(request) = OAuthTokenRequest::from_parameters(&parameters) {
                let written = request.to_parameters();
                let again = OAuthTokenRequest::from_parameters(&written).expect("a written token request reads");
                assert_eq!(again.to_parameters(), written);
            }
        }
        for status in [200, 201, 400] {
            if let Ok(response) = OAuthTokenResponse::decode(status, data) {
                assert_eq!(OAuthTokenResponse::decode(200, response.encode().as_bytes()).as_ref(), Ok(&response));
            }
            if let Ok(response) = OAuthIntrospectionResponse::decode(status, data) {
                let again = OAuthIntrospectionResponse::decode(200, response.encode().as_bytes())
                    .expect("a written response reads");
                assert_eq!(again.encode(), response.encode());
            }
            if let Ok(response) = OAuthDeviceAuthorizationResponse::decode(status, data) {
                assert_eq!(
                    OAuthDeviceAuthorizationResponse::decode(200, response.encode().as_bytes()).as_ref(),
                    Ok(&response)
                );
            }
            if let Ok(response) = OAuthPushedAuthorizationResponse::decode(status, data) {
                assert_eq!(
                    OAuthPushedAuthorizationResponse::decode(201, response.encode().as_bytes()).as_ref(),
                    Ok(&response)
                );
            }
        }
        for kind in [OAuthMetadataKind::Server, OAuthMetadataKind::Resource] {
            if let Ok(metadata) = OAuthMetadata::decode(kind, data) {
                assert_eq!(OAuthMetadata::decode(kind, metadata.encode().as_bytes()).as_ref(), Ok(&metadata));
                if let Ok(identifier) = metadata.identifier() {
                    let _ = OAuthMetadata::location(kind, identifier);
                }
            }
        }
        let Ok(text) = core::str::from_utf8(data) else {
            return;
        };
        if let Ok(scope) = OAuthScope::parse(text) {
            assert_eq!(OAuthScope::parse(&scope.to_string()).as_ref(), Ok(&scope));
        }
        if let Ok(challenges) = OAuthChallenge::parse(text) {
            for challenge in &challenges {
                if challenge.parameters.iter().all(|(name, _)| !name.is_empty()) {
                    assert_eq!(
                        OAuthChallenge::parse(&challenge.encode().unwrap()).as_deref(),
                        Ok(core::slice::from_ref(challenge)),
                        "{text}"
                    );
                }
            }
        }
        if let Ok(Some(token)) = OAuthPresentedToken::from_authorization(text) {
            assert_eq!(OAuthPresentedToken::from_authorization(&token.authorization()), Ok(Some(token)));
        }
        if let Ok(target) = DPoPProof::target(text) {
            assert_eq!(DPoPProof::target(&target).as_ref(), Ok(&target));
        }
    });

/// An authorization server answers any request at any endpoint without panicking, always with a
/// status of its endpoint, and a resource server takes or refuses any request.
#[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
pub const OAUTH_SERVER: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("auth-oauth-server", |data| {
        use umilib::auth::oauth::{
            DPoPConfig, OAuthClientMethod, OAuthClientRegistration, OAuthEndpointRequest, OAuthGrant,
            OAuthIntrospectionResponse, OAuthParameters, OAuthResourceConfig, OAuthResourceServer, OAuthScope,
            OAuthServer, OAuthServerConfig, OAuthTokenValidation,
        };
        use umilib::crypto::random::HMACDRBG;
        use umilib::hash::sha::v2::SHA256;
        let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"umilib oauth fuzz").expect("a seeded generator");
        let mut server = OAuthServer::new(OAuthServerConfig::new("https://as.example"));
        let scope = OAuthScope::parse("read write").expect("a scope");
        server
            .register(OAuthClientRegistration::public("app", &["https://app.example/cb"], scope.clone()))
            .expect("a registration");
        let grants = [
            OAuthGrant::AUTHORIZATION_CODE,
            OAuthGrant::CLIENT_CREDENTIALS,
            OAuthGrant::REFRESH_TOKEN,
            OAuthGrant::DEVICE_CODE,
        ];
        let mut web = OAuthClientRegistration::confidential("web", OAuthClientMethod::SecretPost, "s", &grants, scope);
        web.introspection = true;
        server.register(web).expect("a registration");
        // Requests separated by 0xFF: a byte choosing the endpoint and the fields, then the body.
        for (index, part) in data.split(|byte| *byte == 0xFF).enumerate().take(16) {
            let Some((&choice, body)) = part.split_first() else {
                continue;
            };
            let now = index as i64;
            let text = String::from_utf8_lossy(body).into_owned();
            let request = OAuthEndpointRequest {
                method: if choice & 0x10 == 0 { "POST".into() } else { "GET".into() },
                uri: "https://as.example/token".into(),
                authorization: (choice & 0x20 != 0).then(|| text.clone()),
                dpop: (choice & 0x40 != 0).then(|| text.clone()),
                content_type: (choice & 0x80 == 0).then(|| "application/x-www-form-urlencoded".into()),
                body: body.to_vec(),
            };
            let response = match choice & 0x07 {
                0 => server.token(&request, now, &mut random),
                1 => server.introspect(&request, now),
                2 => server.revoke(&request, now),
                3 => server.push(&request, now, &mut random),
                4 => server.device_authorize(&request, now, &mut random),
                5 => {
                    if let Ok(parameters) = OAuthParameters::parse(body)
                        && let Ok(authorization) = server.authorize(&parameters, now)
                    {
                        let _ = server.deny(&authorization);
                    }
                    continue;
                }
                _ => {
                    let mut resource = OAuthResourceServer::new(OAuthResourceConfig {
                        resource: "https://api.example".into(),
                        realm: None,
                        resource_metadata: None,
                        validation: OAuthTokenValidation::Introspection,
                        require_dpop: choice & 0x08 != 0,
                        dpop: DPoPConfig::default(),
                        leeway: 0,
                    })
                    .expect("a resource server");
                    if let Ok(introspection) = OAuthIntrospectionResponse::decode(200, body) {
                        let _ = resource.accept_introspection(&request, &introspection, now);
                    }
                    let _ = resource.presented(&request);
                    continue;
                }
            };
            assert!([200, 201, 400, 401, 500, 503].contains(&response.status), "{}", response.status);
        }
    });

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(all(umilib_feature = "auth-totp", umilib_feature = "hash-sha-v1"))]
    &OTPS,
    #[cfg(umilib_feature = "auth-cert-key")]
    &KEYS,
    #[cfg(umilib_feature = "auth-cert-x509")]
    &CERTIFICATES,
    #[cfg(umilib_feature = "auth-cert-csr")]
    &REQUESTS,
    #[cfg(umilib_feature = "auth-cert-ocsp")]
    &STATUSES,
    #[cfg(umilib_feature = "auth-cert-path")]
    &PATHS,
    #[cfg(umilib_feature = "auth-oauth")]
    &OAUTH_MESSAGES,
    #[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
    &OAUTH_SERVER,
    #[cfg(all(
        umilib_feature = "auth-sasl-anonymous",
        umilib_feature = "auth-sasl-external",
        umilib_feature = "auth-sasl-oauthbearer",
        umilib_feature = "auth-sasl-plain",
        umilib_feature = "auth-sasl-scram"
    ))]
    &SASL,
];
