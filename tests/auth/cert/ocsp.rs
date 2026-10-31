//! OCSP against RFC 6960 and RFC 8954: requests and responses that OpenSSL
//! made, responses made here, refusals, and responses as a revocation
//! source of path validation.

use std::borrow::Cow;

use umilib::auth::cert::key::{HashAlgorithm, PrivateKey, PublicKey, SignatureAlgorithm};
use umilib::auth::cert::ocsp::{
    BasicOCSPResponse, CertID, CertStatus, OCSPConfig, OCSPError, OCSPNonce, OCSPRequest, OCSPResponse,
    OCSPResponseStatus, Request, ResponderID, ResponseData, SingleResponse, TBSRequest,
};
use umilib::auth::cert::x509::{
    CRLReason, Certificate, ExtendedKeyUsage, Extension, ExtensionValue, Extensions, GeneralName, InvalidityDate,
    KeyUsage, Name, SubjectKeyIdentifier,
};
use umilib::codec::asn1::ASN1Time;

use super::{DER, Fixtures, random};

fn certificate(name: &str) -> Certificate<'static> {
    Certificate::from_der(&Fixtures::OCSP.bytes(&format!("{name}.der")))
        .unwrap_or_else(|error| panic!("{name}: {error:?}"))
        .into_owned()
}

fn private_key(name: &str) -> PrivateKey {
    PrivateKey::from_pem(&Fixtures::OCSP.text(&format!("{name}.key"))).unwrap()
}

fn public_key(name: &str) -> PublicKey {
    certificate(name).public_key().unwrap()
}

fn subject(name: &str) -> Name<'static> {
    certificate(name).tbs_certificate().subject.clone().into_owned()
}

fn response(name: &str) -> OCSPResponse<'static> {
    OCSPResponse::from_der(&Fixtures::OCSP.bytes(&format!("response-{name}.der")))
        .unwrap_or_else(|error| panic!("{name}: {error:?}"))
        .into_owned()
}

fn request(name: &str) -> OCSPRequest<'static> {
    OCSPRequest::from_der(&Fixtures::OCSP.bytes(&format!("request-{name}.der")))
        .unwrap_or_else(|error| panic!("{name}: {error:?}"))
        .into_owned()
}

fn time(year: u16, month: u8, day: u8) -> ASN1Time {
    ASN1Time::new(year, month, day, 0, 0, 0, 0).unwrap()
}

/// The identifier of the certificate `name`, which the root issued.
fn cert_id(name: &str, hash: HashAlgorithm) -> CertID<'static> {
    CertID::new(&certificate(name), public_key("root").key(), hash)
}

/// The fixtures were made on 2026-10-25; their responses are current until 2036-10-22.
const NOW: (u16, u8, u8) = (2027, 1, 1);

fn now() -> OCSPConfig {
    OCSPConfig::new(time(NOW.0, NOW.1, NOW.2))
}

#[test]
fn requests_of_openssl() {
    for name in ["nonce", "multiple", "signed"] {
        let bytes = Fixtures::OCSP.bytes(&format!("request-{name}.der"));
        assert_eq!(OCSPRequest::from_der(&bytes).unwrap().to_der().unwrap(), bytes, "{name}");
    }
    let root_key = public_key("root");
    // One certificate, named by SHA-1 hashes (RFC 6960 §4.1.1), with a nonce of 16 octets.
    let nonce = request("nonce");
    let tbs = nonce.tbs_request();
    assert_eq!(tbs.requests.len(), 1);
    assert!(tbs.requests[0].cert_id.matches(&cert_id("good", HashAlgorithm::SHA1)));
    assert!(tbs.requests[0].cert_id.identifies(&certificate("good"), root_key.key()));
    assert!(!tbs.requests[0].cert_id.identifies(&certificate("revoked"), root_key.key()));
    assert_eq!(tbs.nonce().unwrap().unwrap().nonce.len(), 16);
    assert!(nonce.signature().is_none());
    assert_eq!(nonce.verify(&root_key), Err(OCSPError::Signer));
    // Three certificates by SHA-256, without a nonce.
    let multiple = request("multiple");
    let tbs = multiple.tbs_request();
    assert_eq!(tbs.nonce().unwrap(), None);
    for (request, name) in tbs.requests.iter().zip(["good", "revoked", "unknown"]) {
        assert!(request.cert_id.matches(&cert_id(name, HashAlgorithm::SHA256)), "{name}");
    }
    // A signed request names its requestor and carries its certificate (RFC 6960 §4.1.2).
    let signed = request("signed");
    assert_eq!(signed.tbs_request().requestor_name, Some(GeneralName::DirectoryName(subject("good"))));
    let signature = signed.signature().unwrap();
    assert_eq!(signature.certificates.as_deref(), Some(&[certificate("good")][..]));
    signed.verify(&public_key("good")).unwrap();
    assert!(signed.verify(&root_key).is_err());
}

#[test]
fn responses_of_openssl() {
    for name in ["direct", "delegated", "key-id", "no-next-update", "unauthorized", "other"] {
        let bytes = Fixtures::OCSP.bytes(&format!("response-{name}.der"));
        let response = OCSPResponse::from_der(&bytes).unwrap();
        assert_eq!(response.status, OCSPResponseStatus::Successful, "{name}");
        assert_eq!(response.to_der().unwrap(), bytes, "{name}");
    }
    let delegated = response("delegated");
    let basic = delegated.basic().unwrap();
    let data = basic.tbs_response_data();
    assert_eq!(data.responder_id, ResponderID::ByName(subject("responder")));
    assert_eq!(basic.certificates(), [certificate("responder")]);
    assert_eq!(data.responses.len(), 3);
    for (response, name) in data.responses.iter().zip(["good", "revoked", "unknown"]) {
        assert!(response.cert_id.matches(&cert_id(name, HashAlgorithm::SHA256)), "{name}");
        assert!(response.next_update.is_some_and(|next| next > response.this_update), "{name}");
    }
    assert_eq!(data.responses[0].status, CertStatus::Good);
    assert!(matches!(data.responses[1].status, CertStatus::Revoked { reason: Some(CRLReason::KeyCompromise), .. }));
    assert_eq!(data.responses[2].status, CertStatus::Unknown);
    // The invalidity date of the revoked certificate, a single extension (RFC 6960 §4.4.7).
    let invalidity = data.responses[1].extensions.typed::<InvalidityDate>().unwrap().unwrap();
    assert_eq!(invalidity.time, time(2026, 2, 1));
    // byKey is the SHA-1 hash of the responder's subjectPublicKey (RFC 6960 §4.2.1), here also its key identifier.
    let key_id = response("key-id");
    let responder = &key_id.basic().unwrap().tbs_response_data().responder_id;
    assert_eq!(*responder, ResponderID::by_key(public_key("responder").key()));
    let responder_certificate = certificate("responder");
    let identifier = responder_certificate.tbs_certificate().extensions.typed::<SubjectKeyIdentifier>().unwrap();
    assert_eq!(*responder, ResponderID::ByKey(Cow::Owned(identifier.unwrap().key_identifier.to_vec())));
    assert!(
        response("no-next-update")
            .basic()
            .unwrap()
            .tbs_response_data()
            .responses
            .iter()
            .all(|r| r.next_update.is_none())
    );
}

#[test]
fn responses_are_checked_as_rfc_6960_section_3_2_requires() {
    let (root, root_key) = (subject("root"), public_key("root"));
    let status = |fixture: &str, name: &str, hash: HashAlgorithm, config: &OCSPConfig| {
        let response = response(fixture);
        response.basic()?.verify(&cert_id(name, hash), &root, &root_key, config).map(|single| single.status)
    };
    // Signed by the CA itself, repeating the nonce of the request (RFC 8954).
    let nonce = request("nonce").tbs_request().nonce().unwrap().unwrap().nonce.into_owned();
    let with_nonce = OCSPConfig { nonce: Some(nonce.clone()), ..now() };
    assert_eq!(status("direct", "good", HashAlgorithm::SHA1, &with_nonce), Ok(CertStatus::Good));
    assert_eq!(status("direct", "good", HashAlgorithm::SHA1, &now()), Ok(CertStatus::Good));
    let other_nonce = OCSPConfig { nonce: Some(vec![0; 16]), ..now() };
    assert_eq!(status("direct", "good", HashAlgorithm::SHA1, &other_nonce), Err(OCSPError::Nonce));
    assert_eq!(status("delegated", "good", HashAlgorithm::SHA256, &with_nonce), Err(OCSPError::Nonce));
    // Signed by a responder the CA authorized, named by name or by key (§4.2.2.2).
    for response in ["delegated", "key-id"] {
        assert_eq!(status(response, "good", HashAlgorithm::SHA256, &now()), Ok(CertStatus::Good));
        assert!(matches!(
            status(response, "revoked", HashAlgorithm::SHA256, &now()),
            Ok(CertStatus::Revoked { reason: Some(CRLReason::KeyCompromise), .. })
        ));
        assert_eq!(status(response, "unknown", HashAlgorithm::SHA256, &now()), Ok(CertStatus::Unknown));
    }
    // A certificate the response does not name, or names with another hash, has no status there.
    assert_eq!(status("direct", "revoked", HashAlgorithm::SHA1, &now()), Err(OCSPError::NotFound));
    assert_eq!(status("delegated", "good", HashAlgorithm::SHA1, &now()), Err(OCSPError::NotFound));
    // A signer without id-kp-OCSPSigning, and a responder of another CA (of the same name), are not authorized.
    assert_eq!(status("unauthorized", "good", HashAlgorithm::SHA256, &now()), Err(OCSPError::Signer));
    assert_eq!(status("other", "good", HashAlgorithm::SHA256, &now()), Err(OCSPError::Signer));
    // Nor is the response signed for another CA's certificates.
    let other_key = public_key("other-root");
    let direct = response("direct");
    let verified = direct.basic().unwrap().verify(&cert_id("good", HashAlgorithm::SHA1), &root, &other_key, &now());
    assert_eq!(verified.map(|single| single.status), Err(OCSPError::Signer));
    // A status before its thisUpdate or after its nextUpdate is not current (§4.2.2.1).
    let at = |year, month, day| OCSPConfig::new(time(year, month, day));
    assert_eq!(status("direct", "good", HashAlgorithm::SHA1, &at(2026, 10, 1)), Err(OCSPError::Time));
    assert_eq!(status("direct", "good", HashAlgorithm::SHA1, &at(2036, 12, 1)), Err(OCSPError::Time));
    // The certificate of a delegated responder must be valid at the time (it expires on 2036-01-01).
    assert_eq!(status("delegated", "good", HashAlgorithm::SHA256, &at(2036, 6, 1)), Err(OCSPError::Signer));
    // Without nextUpdate, newer information is available at any time (§4.2.2.1), so the status must be
    // recent (§3.2): current for the configured lifetime after thisUpdate (2026-10-25T21:33:14Z), a day by default.
    assert_eq!(status("no-next-update", "good", HashAlgorithm::SHA256, &at(2026, 10, 26)), Ok(CertStatus::Good));
    assert_eq!(status("no-next-update", "good", HashAlgorithm::SHA256, &at(2026, 10, 28)), Err(OCSPError::Time));
    assert_eq!(status("no-next-update", "good", HashAlgorithm::SHA256, &at(2100, 1, 1)), Err(OCSPError::Time));
    let year = OCSPConfig { lifetime_without_next_update: 366 * 86400, ..at(2026, 12, 1) };
    assert_eq!(status("no-next-update", "good", HashAlgorithm::SHA256, &year), Ok(CertStatus::Good));
    // The search of the signer verifies at most `maximum_signatures` signatures (two for a delegated
    // responder); running out is not a finding about the signer.
    let few = OCSPConfig { maximum_signatures: 1, ..now() };
    assert_eq!(status("delegated", "good", HashAlgorithm::SHA256, &few), Err(OCSPError::Work));
    let enough = OCSPConfig { maximum_signatures: 2, ..now() };
    assert_eq!(status("delegated", "good", HashAlgorithm::SHA256, &enough), Ok(CertStatus::Good));
}

#[test]
fn responses_made_here_follow_rfc_6960() {
    let (root, root_key) = (subject("root"), public_key("root"));
    let responder = certificate("responder");
    let nonce = OCSPNonce::random(&mut random()).unwrap();
    assert_eq!(nonce.nonce.len(), 32);
    let mut extensions = Extensions::new();
    extensions.push(Extension::new(&nonce, false).unwrap()).unwrap();
    let revoked = CertStatus::Revoked { time: time(2026, 12, 1), reason: Some(CRLReason::Superseded) };
    let single = |name: &str, status| SingleResponse {
        cert_id: cert_id(name, HashAlgorithm::SHA256),
        status,
        this_update: time(2026, 12, 31),
        next_update: Some(time(2027, 1, 7)),
        extensions: Extensions::new(),
    };
    let data = ResponseData {
        responder_id: ResponderID::by_key(responder.public_key().unwrap().key()),
        produced_at: time(2026, 12, 31),
        responses: vec![single("good", CertStatus::Good), single("revoked", revoked)],
        extensions,
    };
    let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
    let basic = data.sign(&private_key("responder"), &algorithm, Some(vec![responder.clone()]), &mut random()).unwrap();
    let response = OCSPResponse { status: OCSPResponseStatus::Successful, response: Some(basic) };
    let bytes = response.to_der().unwrap();
    let read = OCSPResponse::from_der(&bytes).unwrap();
    assert_eq!(read, response);
    assert_eq!(read.to_der().unwrap(), bytes);
    let basic = read.basic().unwrap();
    assert_eq!(*basic.tbs_response_data(), data);
    let config = OCSPConfig { nonce: Some(nonce.nonce.to_vec()), ..now() };
    let verify = |name: &str| basic.verify(&cert_id(name, HashAlgorithm::SHA256), &root, &root_key, &config);
    assert_eq!(verify("good").unwrap().status, CertStatus::Good);
    assert_eq!(verify("revoked").unwrap().status, revoked);
    assert_eq!(verify("unknown").map(|single| single.status), Err(OCSPError::NotFound));
    // Without the responder's certificate, nothing shows the CA authorized its key.
    let bare = data.sign(&private_key("responder"), &algorithm, None, &mut random()).unwrap();
    let verified = bare.verify(&cert_id("good", HashAlgorithm::SHA256), &root, &root_key, &config);
    assert_eq!(verified.map(|single| single.status), Err(OCSPError::Signer));
    // A responder identifier that does not name the signer.
    let misnamed = ResponseData { responder_id: ResponderID::ByName(root.clone()), ..data.clone() };
    let misnamed =
        misnamed.sign(&private_key("responder"), &algorithm, Some(vec![responder.clone()]), &mut random()).unwrap();
    let verified = misnamed.verify(&cert_id("good", HashAlgorithm::SHA256), &root, &root_key, &config);
    assert_eq!(verified.map(|single| single.status), Err(OCSPError::Signer));
    // SHA-1 signatures are refused unless the configuration accepts them.
    let sha1 = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA1);
    let direct = ResponseData { responder_id: ResponderID::ByName(root.clone()), ..data.clone() };
    let direct = direct.sign(&private_key("root"), &sha1, None, &mut random()).unwrap();
    let id = cert_id("good", HashAlgorithm::SHA256);
    assert_eq!(direct.verify(&id, &root, &root_key, &config).map(|single| single.status), Err(OCSPError::Algorithm));
    let accepting = OCSPConfig { accept_sha1: true, ..config.clone() };
    assert_eq!(direct.verify(&id, &root, &root_key, &accepting).unwrap().status, CertStatus::Good);
    // An empty list of certificates is written back as it was read.
    let empty = data.sign(&private_key("responder"), &algorithm, Some(Vec::new()), &mut random()).unwrap();
    let bytes = empty.to_der().unwrap();
    assert_eq!(BasicOCSPResponse::from_der(&bytes).unwrap().to_der().unwrap(), bytes);
    assert_ne!(bytes, bare.to_der().unwrap());
}

#[test]
fn delegated_responders_follow_rfc_5280() {
    let (root, root_key) = (subject("root"), public_key("root"));
    let responder = certificate("responder");
    // The responder's certificate with `change` made to its extensions, issued by the root again.
    let reissued = |change: &dyn Fn(&mut Extensions<'static>)| {
        let mut tbs = responder.tbs_certificate().clone().into_owned();
        change(&mut tbs.extensions);
        tbs.sign(&private_key("root"), &mut random()).unwrap()
    };
    let status_with = |certificate: Certificate<'static>| {
        let data = ResponseData {
            responder_id: ResponderID::ByName(subject("responder")),
            produced_at: time(2026, 12, 31),
            responses: vec![SingleResponse {
                cert_id: cert_id("good", HashAlgorithm::SHA256),
                status: CertStatus::Good,
                this_update: time(2026, 12, 31),
                next_update: None,
                extensions: Extensions::new(),
            }],
            extensions: Extensions::new(),
        };
        let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
        let basic = data.sign(&private_key("responder"), &algorithm, Some(vec![certificate]), &mut random()).unwrap();
        let verified = basic.verify(&cert_id("good", HashAlgorithm::SHA256), &root, &root_key, &now());
        verified.map(|single| single.status)
    };
    assert_eq!(status_with(reissued(&|_| {})), Ok(CertStatus::Good));
    // RFC 5280 §4.2: a critical extension that is not processed makes the certificate unusable.
    let unknown = |extensions: &mut Extensions<'static>| {
        let oid = umilib::codec::asn1::ObjectIdentifier::parse("1.3.6.1.4.1.55555.7").unwrap().into_owned();
        extensions.push(Extension { oid, critical: true, value: Cow::Borrowed(&[0x05, 0x00]) }).unwrap();
    };
    assert_eq!(status_with(reissued(&unknown)), Err(OCSPError::Signer));
    // RFC 5280 §4.2.1.3: a key usage without digitalSignature does not allow signing responses.
    let encipherment = |extensions: &mut Extensions<'static>| {
        extensions.entries.retain(|extension| extension.oid != KeyUsage::OID);
        extensions.push(Extension::new(&KeyUsage { bits: 1 << 2 }, true).unwrap()).unwrap();
    };
    assert_eq!(status_with(reissued(&encipherment)), Err(OCSPError::Signer));
    // Without the extended key usage id-kp-OCSPSigning, the CA did not authorize the key (RFC 6960 §4.2.2.2).
    let no_purpose = |extensions: &mut Extensions<'static>| {
        extensions.entries.retain(|extension| extension.oid != ExtendedKeyUsage::OID);
    };
    assert_eq!(status_with(reissued(&no_purpose)), Err(OCSPError::Signer));
    // id-pkix-ocsp-nocheck is recognized, even critical.
    let nocheck = |extensions: &mut Extensions<'static>| {
        extensions
            .entries
            .iter_mut()
            .filter(|extension| extension.oid == BasicOCSPResponse::NO_CHECK)
            .for_each(|extension| extension.critical = true);
    };
    assert_eq!(status_with(reissued(&nocheck)), Ok(CertStatus::Good));
}

#[test]
fn requests_made_here_follow_rfc_6960() {
    let nonce = OCSPNonce::random(&mut random()).unwrap();
    let mut extensions = Extensions::new();
    extensions.push(Extension::new(&nonce, false).unwrap()).unwrap();
    let tbs = TBSRequest {
        requestor_name: None,
        requests: ["good", "revoked"]
            .into_iter()
            .map(|name| Request { cert_id: cert_id(name, HashAlgorithm::SHA256), extensions: Extensions::new() })
            .collect(),
        extensions,
    };
    let unsigned = OCSPRequest::new(tbs.clone()).unwrap();
    let bytes = unsigned.to_der().unwrap();
    assert_eq!(OCSPRequest::from_der(&bytes).unwrap(), unsigned);
    assert_eq!(unsigned.tbs_request().nonce().unwrap().unwrap(), nonce);
    let named = TBSRequest { requestor_name: Some(GeneralName::DirectoryName(subject("good"))), ..tbs };
    let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
    let signed =
        OCSPRequest::sign(named, &private_key("good"), &algorithm, Some(vec![certificate("good")]), &mut random())
            .unwrap();
    let bytes = signed.to_der().unwrap();
    let read = OCSPRequest::from_der(&bytes).unwrap();
    assert_eq!(read, signed);
    read.verify(&public_key("good")).unwrap();
}

#[test]
fn malformed_messages_are_refused() {
    let basic_oid = DER::oid("1.3.6.1.5.5.7.48.1.1");
    let enumerated = |value: u8| DER::element(0x0A, &[value]);
    let bytes_of =
        |oid: &[u8], content: &[u8]| DER::element(0xA0, &DER::sequence(&[oid, &DER::element(0x04, content)]));
    let basic = Fixtures::OCSP.bytes("response-direct.der");
    let basic = OCSPResponse::from_der(&basic).unwrap().basic().unwrap().to_der().unwrap();
    // A status that is not successful carries no response bytes (RFC 6960 §4.2.1).
    for status in OCSPResponseStatus::ALL.into_iter().filter(|status| *status != OCSPResponseStatus::Successful) {
        let bytes = DER::sequence(&[&enumerated(status as u8)]);
        let response = OCSPResponse::from_der(&bytes).unwrap();
        assert_eq!(response, OCSPResponse { status, response: None });
        assert_eq!(response.to_der().unwrap(), bytes);
        assert_eq!(response.basic().map(|_| ()), Err(OCSPError::Status(status)));
        let with_bytes = DER::sequence(&[&enumerated(status as u8), &bytes_of(&basic_oid, &basic)]);
        assert_eq!(OCSPResponse::from_der(&with_bytes).map(|_| ()), Err(OCSPError::ResponseType));
    }
    // 4 is not used, and 7 is not defined.
    for code in [4, 7] {
        let bytes = DER::sequence(&[&enumerated(code)]);
        assert!(matches!(OCSPResponse::from_der(&bytes), Err(OCSPError::X509(_))), "{code}");
    }
    // A successful status needs a basic response.
    let successful = DER::sequence(&[&enumerated(0)]);
    assert_eq!(OCSPResponse::from_der(&successful).map(|_| ()), Err(OCSPError::ResponseType));
    let other_type = DER::sequence(&[&enumerated(0), &bytes_of(&DER::oid("1.3.6.1.5.5.7.48.1.99"), &basic)]);
    assert_eq!(OCSPResponse::from_der(&other_type).map(|_| ()), Err(OCSPError::ResponseType));
    let good = DER::sequence(&[&enumerated(0), &bytes_of(&basic_oid, &basic)]);
    assert!(OCSPResponse::from_der(&good).is_ok());
    assert!(OCSPResponse { status: OCSPResponseStatus::Successful, response: None }.to_der().is_err());
    // A version other than v1 (RFC 6960 §4.1.1, §4.2.1).
    let response = response("direct");
    let data = response.basic().unwrap().tbs_response_data().to_der().unwrap();
    let version = |value: u8| DER::element(0xA0, &DER::integer(value));
    // The content of the fixture's ResponseData, after its tag and length.
    let header = if data[1] < 0x80 { 2 } else { 2 + (data[1] & 0x7F) as usize };
    let with_version = |value: u8| DER::sequence(&[&version(value), &data[header..]]);
    for (value, expected) in [(1, Err(OCSPError::Version)), (0, Ok(()))] {
        let bytes = with_version(value);
        let mut reader = umilib::codec::asn1::der::DERReader::new(&bytes);
        assert_eq!(ResponseData::decode(&mut reader).map(|_| ()), expected, "{value}");
    }
    // A nonce of 0 or of more than 32 octets (RFC 8954 §2.1).
    for length in [0, 33] {
        let nonce = OCSPNonce { nonce: Cow::Owned(vec![1; length]) };
        assert!(Extension::new(&nonce, false).is_err(), "{length}");
        let value = Cow::Owned(DER::element(0x04, &vec![1; length]));
        let extension = Extension { oid: OCSPNonce::OID, critical: false, value };
        assert!(extension.typed::<OCSPNonce>().is_err(), "{length}");
    }
    // An unknown critical extension makes the response unusable (RFC 6960 §4.4).
    let (root, root_key) = (subject("root"), public_key("root"));
    let mut extensions = Extensions::new();
    let oid = umilib::codec::asn1::ObjectIdentifier::parse("1.3.6.1.4.1.55555.9").unwrap().into_owned();
    extensions.push(Extension { oid, critical: true, value: Cow::Borrowed(&[0x05, 0x00]) }).unwrap();
    let data = ResponseData {
        responder_id: ResponderID::ByName(root.clone()),
        produced_at: time(2026, 12, 31),
        responses: vec![SingleResponse {
            cert_id: cert_id("good", HashAlgorithm::SHA256),
            status: CertStatus::Good,
            this_update: time(2026, 12, 31),
            next_update: None,
            extensions: Extensions::new(),
        }],
        extensions,
    };
    let signed = data
        .sign(&private_key("root"), &SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256), None, &mut random())
        .unwrap();
    let verified = signed.verify(&cert_id("good", HashAlgorithm::SHA256), &root, &root_key, &now());
    assert_eq!(verified.map(|single| single.status), Err(OCSPError::UnknownCriticalExtension));
}

#[cfg(umilib_feature = "auth-cert-path")]
#[test]
fn responses_are_revocation_sources_of_path_validation() {
    use umilib::auth::cert::path::{
        PathConfig, PathErrorReason, PathValidator, RevocationConfig, RevocationSource, RevocationStatus, TrustAnchor,
    };
    let anchors = [TrustAnchor::from_certificate(certificate("root"), &Default::default()).unwrap()];
    let config = PathConfig { revocation: RevocationConfig::REQUIRED, ..PathConfig::new(time(NOW.0, NOW.1, NOW.2)) };
    let validate = |name: &str, sources: &[&dyn RevocationSource]| {
        let target = certificate(name);
        PathValidator::new(&config, &anchors, &[], &[])
            .with_sources(sources)
            .validate(&target)
            .map(|_| ())
            .map_err(|error| error.reason)
    };
    let delegated = response("delegated");
    assert_eq!(validate("good", &[&delegated]), Ok(()));
    assert_eq!(validate("revoked", &[&delegated]), Err(PathErrorReason::Revoked(CRLReason::KeyCompromise)));
    assert_eq!(validate("unknown", &[&delegated]), Err(PathErrorReason::RevocationUnknown));
    assert_eq!(validate("good", &[]), Err(PathErrorReason::RevocationUnknown));
    // A response that names the certificate but cannot be used fails the path.
    assert_eq!(validate("good", &[&response("unauthorized")]), Err(PathErrorReason::InvalidResponse));
    // A response that does not name it says nothing; another source may.
    let direct = response("direct");
    assert_eq!(validate("revoked", &[&direct]), Err(PathErrorReason::RevocationUnknown));
    assert_eq!(validate("good", &[&direct]), Ok(()));
    // Revoked wins over unrevoked, whatever the order of the sources.
    let root = subject("root");
    let forged = ResponseData {
        responder_id: ResponderID::ByName(root),
        produced_at: time(2026, 12, 31),
        responses: vec![SingleResponse {
            cert_id: cert_id("revoked", HashAlgorithm::SHA256),
            status: CertStatus::Good,
            this_update: time(2026, 12, 31),
            next_update: None,
            extensions: Extensions::new(),
        }],
        extensions: Extensions::new(),
    };
    let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
    let forged = forged.sign(&private_key("root"), &algorithm, None, &mut random()).unwrap();
    assert_eq!(validate("revoked", &[&forged]), Ok(()));
    let revoked = Err(PathErrorReason::Revoked(CRLReason::KeyCompromise));
    assert_eq!(validate("revoked", &[&forged, &delegated]), revoked);
    assert_eq!(validate("revoked", &[&delegated, &forged]), revoked);
    // The signatures of the responses are spent from the budget of the validation (two for each
    // response of the delegated responder: its certificate's and the response's), so sources cannot
    // multiply the work a configuration allows.
    let budget = |sources: &[&dyn RevocationSource], signatures: usize| {
        let config = PathConfig { maximum_signatures: signatures, ..config.clone() };
        let target = certificate("good");
        PathValidator::new(&config, &anchors, &[], &[])
            .with_sources(sources)
            .validate(&target)
            .map(|_| ())
            .map_err(|error| error.reason)
    };
    let unchecked = PathConfig { revocation: RevocationConfig::NONE, ..config.clone() };
    let certificates = (0..=config.maximum_signatures)
        .find(|&signatures| {
            let config = PathConfig { maximum_signatures: signatures, ..unchecked.clone() };
            PathValidator::new(&config, &anchors, &[], &[]).validate(&certificate("good")).is_ok()
        })
        .expect("the path validates without revocation");
    assert_eq!(budget(&[&delegated], certificates + 2), Ok(()));
    assert_eq!(budget(&[&delegated], certificates + 1), Err(PathErrorReason::Work));
    let three: [&dyn RevocationSource; 3] = [&delegated, &delegated, &delegated];
    assert_eq!(budget(&three, certificates + 6), Ok(()));
    assert_eq!(budget(&three, certificates + 5), Err(PathErrorReason::Work));
    // A response that is not successful says nothing.
    let try_later = OCSPResponse { status: OCSPResponseStatus::TryLater, response: None };
    assert_eq!(validate("good", &[&try_later]), Err(PathErrorReason::RevocationUnknown));
    // The statuses combine as RFC 5280 §6.3 asks of the sources of a status.
    use RevocationStatus::{Revoked, Undetermined, Unrevoked};
    let compromised = Revoked(CRLReason::KeyCompromise);
    assert_eq!(Unrevoked.combine(compromised), compromised);
    assert_eq!(compromised.combine(Undetermined), compromised);
    assert_eq!(Undetermined.combine(Unrevoked), Unrevoked);
    assert_eq!(Undetermined.combine(Undetermined), Undetermined);
}
