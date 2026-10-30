//! Certification requests against RFC 2986 and RFC 2985, and requests
//! that OpenSSL made.

use std::borrow::Cow;

use umilib::auth::cert::csr::{CertificationRequest, CertificationRequestInfo};
use umilib::auth::cert::key::{HashAlgorithm, KeyError, PrivateKey, SignatureAlgorithm};
use umilib::auth::cert::x509::{
    Attribute, AttributeTypeAndValue, Extension, Extensions, GeneralName, KeyUsage, Name, NameAttribute,
    SubjectAlternativeName, X509Error,
};
use umilib::codec::asn1::der::DERReader;

use super::{DER, Fixtures, random};

fn request(name: &str) -> CertificationRequest<'static> {
    CertificationRequest::from_der(&Fixtures::X509.bytes(&format!("{name}.csr")))
        .unwrap_or_else(|error| panic!("{name}: {error:?}"))
        .into_owned()
}

fn private_key(name: &str) -> PrivateKey {
    PrivateKey::from_pem(&Fixtures::X509.text(&format!("{name}.key"))).unwrap()
}

/// The text of the single value of the attribute `oid` of `info`.
fn attribute_text(info: &CertificationRequestInfo<'_>, oid: &umilib::codec::asn1::ObjectIdentifier<'_>) -> String {
    let attribute = info.attributes.iter().find(|attribute| attribute.oid == *oid).unwrap();
    assert_eq!(attribute.values.len(), 1);
    AttributeTypeAndValue::new(attribute.oid.clone(), attribute.values[0].clone()).unwrap().text().unwrap().into_owned()
}

#[test]
fn requests_of_openssl() {
    let subject = Name::from_attributes(&[
        (NameAttribute::Country, "JP"),
        (NameAttribute::Organization, "umilib"),
        (NameAttribute::CommonName, "csr.example.com"),
    ])
    .unwrap();
    for (name, algorithm) in [
        ("leaf", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256)),
        ("rsa", SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256)),
        ("ed25519", SignatureAlgorithm::Ed25519),
        ("mldsa65", SignatureAlgorithm::MLDSA(umilib::auth::cert::key::MLDSAParameterSet::MLDSA65)),
    ] {
        let request = request(name);
        request.verify().unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(SignatureAlgorithm::from_identifier(request.signature_algorithm()).unwrap(), algorithm, "{name}");
        assert_eq!(request.public_key().unwrap(), private_key(name).public_key().unwrap(), "{name}");
        let info = request.info();
        assert_eq!(info.subject, subject, "{name}");
        // RFC 2985 §5.4: challengePassword and unstructuredName, and the requested extensions.
        assert_eq!(attribute_text(info, &CertificationRequestInfo::CHALLENGE_PASSWORD), "password1234");
        let unstructured = umilib::codec::asn1::ObjectIdentifier::parse("1.2.840.113549.1.9.2").unwrap();
        assert_eq!(attribute_text(info, &unstructured), "Unstructured Name");
        let extensions = info.extensions().unwrap();
        assert_eq!(
            extensions.typed::<SubjectAlternativeName>().unwrap().unwrap().names,
            [GeneralName::DNSName(Cow::Borrowed("csr.example.com"))]
        );
        assert!(extensions.get(&<KeyUsage as umilib::auth::cert::x509::ExtensionValue>::OID).unwrap().critical);
        assert_eq!(extensions.typed::<KeyUsage>().unwrap(), Some(KeyUsage::DIGITAL_SIGNATURE));
        // Written back to the same bytes.
        let bytes = Fixtures::X509.bytes(&format!("{name}.csr"));
        assert_eq!(request.to_der().unwrap(), bytes, "{name}");
        assert_eq!(info.to_der().unwrap(), request.info_encoding(), "{name}");
        assert_eq!(CertificationRequest::from_pem(&request.to_pem().unwrap()).unwrap(), request);
    }
    // A request without attributes has an empty [0] SET (RFC 2986 §4.1).
    let bare = request("bare");
    bare.verify().unwrap();
    assert!(bare.info().attributes.is_empty());
    assert!(bare.info().extensions().unwrap().is_empty());
    assert_eq!(bare.to_der().unwrap(), Fixtures::X509.bytes("bare.csr"));
    // A changed byte of the signature (the last field) still reads but does not verify.
    let mut tampered = Fixtures::X509.bytes("bare.csr");
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let tampered = CertificationRequest::from_der(&tampered).unwrap();
    assert!(tampered.verify().is_err());
}

#[test]
fn built_requests_are_signed_and_read_back() {
    let key = private_key("leaf");
    let mut extensions = Extensions::new();
    let names = SubjectAlternativeName { names: vec![GeneralName::DNSName(Cow::Borrowed("built.example.com"))] };
    extensions.push(Extension::new(&names, false).unwrap()).unwrap();
    let info = CertificationRequestInfo {
        subject: Name::from_attributes(&[(NameAttribute::CommonName, "built.example.com")]).unwrap(),
        subject_public_key_info: key.public_key().unwrap().info().unwrap().into_owned(),
        attributes: vec![CertificationRequestInfo::extension_request(&extensions).unwrap()],
    };
    let algorithm = SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256);
    let request = info.sign(&key, &algorithm, &mut random()).unwrap();
    request.verify().unwrap();
    let bytes = request.to_der().unwrap();
    let read = CertificationRequest::from_der(&bytes).unwrap();
    assert_eq!(read, request);
    assert_eq!(read.info().extensions().unwrap(), extensions);
    // The signature proves possession of the subject's key: another key is refused.
    assert_eq!(
        info.sign(&private_key("root"), &algorithm, &mut random()).unwrap_err(),
        X509Error::Key(KeyError::Mismatch)
    );
    // One extensionRequest of one value (RFC 2985 §5.4.2).
    let twice = CertificationRequestInfo {
        attributes: vec![info.attributes[0].clone(), info.attributes[0].clone()],
        ..info.clone()
    };
    assert_eq!(twice.sign(&key, &algorithm, &mut random()).unwrap_err(), X509Error::InvalidAttribute);
    let two_values = Attribute { values: vec![info.attributes[0].values[0].clone(); 2], ..info.attributes[0].clone() };
    assert_eq!(
        CertificationRequestInfo { attributes: vec![two_values], ..info.clone() }.extensions().unwrap_err(),
        X509Error::InvalidAttribute
    );
    // An attribute has at least one value (RFC 2986 §4.1).
    let empty = Attribute { values: Vec::new(), ..info.attributes[0].clone() };
    assert_eq!(
        CertificationRequestInfo { attributes: vec![empty], ..info.clone() }.to_der().unwrap_err(),
        X509Error::InvalidAttribute
    );
}

#[test]
fn requests_are_read_as_rfc_2986_defines_them() {
    let key = private_key("ed25519");
    let info = CertificationRequestInfo {
        subject: Name::from_attributes(&[(NameAttribute::CommonName, "x")]).unwrap(),
        subject_public_key_info: key.public_key().unwrap().info().unwrap().into_owned(),
        attributes: Vec::new(),
    };
    let encoding = info.to_der().unwrap();
    let mut reader = DERReader::new(&encoding);
    let mut fields = reader.read_sequence().unwrap();
    assert_eq!(fields.read_integer().unwrap().as_bytes(), [0], "version v1 (0)");
    let subject = fields.read_element().unwrap().encoding;
    let public_key = fields.read_element().unwrap().encoding;
    // The version is 0; the attributes are required, as [0] IMPLICIT SET OF in DER order.
    let request = |version: u8, attributes: &[&[u8]]| {
        let mut fields: Vec<&[u8]> = vec![];
        let version = DER::integer(version);
        fields.push(&version);
        fields.push(subject);
        fields.push(public_key);
        fields.extend_from_slice(attributes);
        CertificationRequestInfo::from_der(&DER::sequence(&fields)).map(|info| info.attributes.len())
    };
    assert_eq!(request(0, &[&[0xA0, 0x00]]), Ok(0));
    assert_eq!(request(1, &[&[0xA0, 0x00]]), Err(X509Error::Version));
    assert!(request(0, &[]).is_err());
    let attribute = |value: &[u8]| {
        DER::sequence(&[&DER::oid("1.2.840.113549.1.9.2"), &DER::element(0x31, &DER::element(0x0C, value))])
    };
    let (a, b) = (attribute(b"a"), attribute(b"b"));
    assert_eq!(request(0, &[&DER::element(0xA0, &[a.as_slice(), b.as_slice()].concat())]), Ok(2));
    assert!(request(0, &[&DER::element(0xA0, &[b.as_slice(), a.as_slice()].concat())]).is_err());
    let no_value = DER::sequence(&[&DER::oid("1.2.840.113549.1.9.2"), &DER::element(0x31, &[])]);
    assert_eq!(request(0, &[&DER::element(0xA0, &no_value)]), Err(X509Error::InvalidAttribute));
    // RFC 7468 §7: the label NEW CERTIFICATE REQUEST is accepted.
    let request = info.sign(&key, &SignatureAlgorithm::Ed25519, &mut random()).unwrap();
    let legacy = request.to_pem().unwrap().replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST");
    assert_eq!(CertificationRequest::from_pem(&legacy).unwrap(), request);
    let other = request.to_pem().unwrap().replace("CERTIFICATE REQUEST", "CERTIFICATE");
    assert_eq!(CertificationRequest::from_pem(&other).unwrap_err(), X509Error::PEMLabel);
}
