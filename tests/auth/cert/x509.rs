//! Certificates, CRLs and their parts against RFC 5280, RFC 4514, the
//! example certificates of RFC 8410, RFC 9881, RFC 9909 and RFC 9935, and
//! certificates and CRLs that OpenSSL made.

use std::borrow::Cow;

use umilib::auth::cert::key::{
    HashAlgorithm, KeyAlgorithm, MLDSAParameterSet, MLKEMParameterSet, NamedCurve, PSSParameters, PrivateKey,
    PublicKey, SLHDSAParameterSet, SignatureAlgorithm,
};
use umilib::auth::cert::x509::{
    AccessDescription, AttributeTypeAndValue, AuthorityInformationAccess, AuthorityKeyIdentifier, BasicConstraints,
    CRLDistributionPoints, CRLNumber, CRLReason, Certificate, CertificateIssuer, CertificateList, CertificatePolicies,
    DistributionPoint, DistributionPointName, ExtendedKeyUsage, Extension, ExtensionValue, Extensions, FreshestCRL,
    GeneralName, GeneralSubtree, HoldInstructionCode, InhibitAnyPolicy, InvalidityDate, IssuerAlternativeName,
    IssuingDistributionPoint, KeyUsage, Name, NameAttribute, NameConstraints, OtherName, PolicyConstraints,
    PolicyMapping, PolicyMappings, PolicyQualifierInfo, ReasonFlags, RelativeDistinguishedName, RevokedCertificate,
    SerialNumber, SubjectAlternativeName, SubjectInformationAccess, SubjectKeyIdentifier, TBSCertList, TBSCertificate,
    Time, Validity, Version, X509Error,
};
use umilib::codec::asn1::der::{DERReader, DERWriter};
use umilib::codec::asn1::{ASN1Error, ASN1Time, ObjectIdentifier};

use super::{DER, Fixtures, RFCExamples, random};

const RFC8410: &str = include_str!("../../vectors/auth/cert/key/rfc8410.txt");
const RFC9881: &str = include_str!("../../vectors/auth/cert/key/rfc9881.txt");
const RFC9909: &str = include_str!("../../vectors/auth/cert/key/rfc9909.txt");
const RFC9935: &str = include_str!("../../vectors/auth/cert/key/rfc9935.txt");

fn arcs(text: &str) -> ObjectIdentifier<'static> {
    ObjectIdentifier::parse(text).unwrap()
}

fn time(year: u16, month: u8, day: u8) -> ASN1Time {
    ASN1Time::new(year, month, day, 0, 0, 0, 0).unwrap()
}

fn certificate(name: &str) -> Certificate<'static> {
    Certificate::from_der(&Fixtures::X509.bytes(&format!("{name}.der")))
        .unwrap_or_else(|error| panic!("{name}: {error:?}"))
        .into_owned()
}

fn private_key(name: &str) -> PrivateKey {
    PrivateKey::from_pem(&Fixtures::X509.text(&format!("{name}.key"))).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The DER encoding of a value written by `write`.
fn der(write: impl FnOnce(&mut DERWriter)) -> Vec<u8> {
    let mut writer = DERWriter::new();
    write(&mut writer);
    writer.into_bytes()
}

#[test]
fn identifiers_are_those_of_rfc_5280() {
    // RFC 5280 appendix A.2 and RFC 4519 §2.
    let extensions = [
        (AuthorityKeyIdentifier::OID, "2.5.29.35"),
        (SubjectKeyIdentifier::OID, "2.5.29.14"),
        (KeyUsage::OID, "2.5.29.15"),
        (CertificatePolicies::OID, "2.5.29.32"),
        (PolicyMappings::OID, "2.5.29.33"),
        (SubjectAlternativeName::OID, "2.5.29.17"),
        (IssuerAlternativeName::OID, "2.5.29.18"),
        (BasicConstraints::OID, "2.5.29.19"),
        (NameConstraints::OID, "2.5.29.30"),
        (PolicyConstraints::OID, "2.5.29.36"),
        (ExtendedKeyUsage::OID, "2.5.29.37"),
        (CRLDistributionPoints::OID, "2.5.29.31"),
        (InhibitAnyPolicy::OID, "2.5.29.54"),
        (FreshestCRL::OID, "2.5.29.46"),
        (AuthorityInformationAccess::OID, "1.3.6.1.5.5.7.1.1"),
        (SubjectInformationAccess::OID, "1.3.6.1.5.5.7.1.11"),
        (CRLNumber::OID, "2.5.29.20"),
        (IssuingDistributionPoint::OID, "2.5.29.28"),
        (umilib::auth::cert::x509::DeltaCRLIndicator::OID, "2.5.29.27"),
        (CRLReason::OID, "2.5.29.21"),
        (CertificateIssuer::OID, "2.5.29.29"),
        (HoldInstructionCode::OID, "2.5.29.23"),
        (InvalidityDate::OID, "2.5.29.24"),
        (umilib::auth::cert::x509::SubjectDirectoryAttributes::OID, "2.5.29.9"),
        (umilib::auth::cert::x509::PrivateKeyUsagePeriod::OID, "2.5.29.16"),
        (CertificatePolicies::ANY_POLICY, "2.5.29.32.0"),
        (ExtendedKeyUsage::ANY, "2.5.29.37.0"),
        (ExtendedKeyUsage::SERVER_AUTH, "1.3.6.1.5.5.7.3.1"),
        (ExtendedKeyUsage::CLIENT_AUTH, "1.3.6.1.5.5.7.3.2"),
        (ExtendedKeyUsage::CODE_SIGNING, "1.3.6.1.5.5.7.3.3"),
        (ExtendedKeyUsage::EMAIL_PROTECTION, "1.3.6.1.5.5.7.3.4"),
        (ExtendedKeyUsage::TIME_STAMPING, "1.3.6.1.5.5.7.3.8"),
        (ExtendedKeyUsage::OCSP_SIGNING, "1.3.6.1.5.5.7.3.9"),
        (AccessDescription::OCSP, "1.3.6.1.5.5.7.48.1"),
        (AccessDescription::CA_ISSUERS, "1.3.6.1.5.5.7.48.2"),
        (AccessDescription::TIME_STAMPING, "1.3.6.1.5.5.7.48.3"),
        (AccessDescription::CA_REPOSITORY, "1.3.6.1.5.5.7.48.5"),
        (PolicyQualifierInfo::CPS, "1.3.6.1.5.5.7.2.1"),
        (PolicyQualifierInfo::USER_NOTICE, "1.3.6.1.5.5.7.2.2"),
        (HoldInstructionCode::NONE, "1.2.840.10040.2.1"),
        (HoldInstructionCode::CALL_ISSUER, "1.2.840.10040.2.2"),
        (HoldInstructionCode::REJECT, "1.2.840.10040.2.3"),
    ];
    for (oid, text) in extensions {
        assert_eq!(oid, arcs(text), "{text}");
    }
    let attributes = [
        (NameAttribute::CommonName, "2.5.4.3"),
        (NameAttribute::Surname, "2.5.4.4"),
        (NameAttribute::SerialNumber, "2.5.4.5"),
        (NameAttribute::Country, "2.5.4.6"),
        (NameAttribute::Locality, "2.5.4.7"),
        (NameAttribute::StateOrProvince, "2.5.4.8"),
        (NameAttribute::Street, "2.5.4.9"),
        (NameAttribute::Organization, "2.5.4.10"),
        (NameAttribute::OrganizationalUnit, "2.5.4.11"),
        (NameAttribute::Title, "2.5.4.12"),
        (NameAttribute::BusinessCategory, "2.5.4.15"),
        (NameAttribute::PostalCode, "2.5.4.17"),
        (NameAttribute::Name, "2.5.4.41"),
        (NameAttribute::GivenName, "2.5.4.42"),
        (NameAttribute::Initials, "2.5.4.43"),
        (NameAttribute::GenerationQualifier, "2.5.4.44"),
        (NameAttribute::DNQualifier, "2.5.4.46"),
        (NameAttribute::Pseudonym, "2.5.4.65"),
        (NameAttribute::OrganizationIdentifier, "2.5.4.97"),
        (NameAttribute::DomainComponent, "0.9.2342.19200300.100.1.25"),
        (NameAttribute::UserID, "0.9.2342.19200300.100.1.1"),
        (NameAttribute::EmailAddress, "1.2.840.113549.1.9.1"),
    ];
    assert_eq!(attributes.len(), NameAttribute::ALL.len());
    for (attribute, text) in attributes {
        assert_eq!(attribute.oid(), arcs(text), "{text}");
        assert_eq!(NameAttribute::from_oid(&arcs(text)), Some(attribute));
    }
}

#[test]
fn names_have_the_string_representation_of_rfc_4514() {
    // RFC 4514 §4, the examples: the most significant relative name last.
    let uid = Name::from_attributes(&[
        (NameAttribute::DomainComponent, "net"),
        (NameAttribute::DomainComponent, "example"),
        (NameAttribute::UserID, "jsmith"),
    ])
    .unwrap();
    assert_eq!(uid.to_rfc4514(), "UID=jsmith,DC=example,DC=net");
    let multivalued = Name::new(&[
        RelativeDistinguishedName::new(&[
            AttributeTypeAndValue::from_text(NameAttribute::DomainComponent, "net").unwrap()
        ])
        .unwrap(),
        RelativeDistinguishedName::new(&[
            AttributeTypeAndValue::from_text(NameAttribute::OrganizationalUnit, "Sales").unwrap(),
            AttributeTypeAndValue::from_text(NameAttribute::CommonName, "J.  Smith").unwrap(),
        ])
        .unwrap(),
    ])
    .unwrap();
    // The attributes of a relative name are in the order of their encodings (X.690 §11.6).
    assert_eq!(multivalued.to_rfc4514(), "OU=Sales+CN=J.  Smith,DC=net");
    let escaped = Name::from_attributes(&[(NameAttribute::CommonName, "James \"Jim\" Smith, III")]).unwrap();
    assert_eq!(escaped.to_rfc4514(), "CN=James \\\"Jim\\\" Smith\\, III");
    let unicode = Name::from_attributes(&[(NameAttribute::CommonName, "Lučić")]).unwrap();
    assert_eq!(unicode.to_rfc4514(), "CN=Lučić");
    // A type without a short name: the dotted identifier and the hexadecimal encoding of the value (§2.4).
    let hexadecimal = Name::new(&[RelativeDistinguishedName::new(&[AttributeTypeAndValue::new(
        arcs("1.3.6.1.4.1.1466.0"),
        Cow::Owned(vec![0x04, 0x02, 0x48, 0x69]),
    )
    .unwrap()])
    .unwrap()])
    .unwrap();
    assert_eq!(hexadecimal.to_rfc4514(), "1.3.6.1.4.1.1466.0=#04024869");
    // §2.4: a space or '#' first, a space last, and the characters "+,;<>\ are escaped, NUL as \00.
    let special = Name::from_attributes(&[(NameAttribute::CommonName, "#a+b;c<d>e\\f\0 ")]).unwrap();
    assert_eq!(special.to_rfc4514(), "CN=\\#a\\+b\\;c\\<d\\>e\\\\f\\00\\ ");
    let space = Name::from_attributes(&[(NameAttribute::CommonName, " x")]).unwrap();
    assert_eq!(space.to_rfc4514(), "CN=\\ x");
    assert_eq!(Name::empty().to_rfc4514(), "");
}

#[test]
fn name_attributes_have_the_syntax_and_size_of_their_type() {
    // RFC 5280 appendix A.1: countryName is a PrintableString of 2 characters.
    let country = AttributeTypeAndValue::from_text(NameAttribute::Country, "JP").unwrap();
    assert_eq!(country.value.as_ref(), &[0x13, 0x02, b'J', b'P']);
    assert_eq!(AttributeTypeAndValue::from_text(NameAttribute::Country, "JPN").unwrap_err(), X509Error::InvalidName);
    assert_eq!(AttributeTypeAndValue::from_text(NameAttribute::Country, "J@").unwrap_err(), X509Error::InvalidName);
    // ub-common-name is 64 characters, counted as characters, not octets.
    assert!(AttributeTypeAndValue::from_text(NameAttribute::CommonName, &"あ".repeat(64)).is_ok());
    assert_eq!(
        AttributeTypeAndValue::from_text(NameAttribute::CommonName, &"a".repeat(65)).unwrap_err(),
        X509Error::InvalidName
    );
    assert_eq!(AttributeTypeAndValue::from_text(NameAttribute::CommonName, "").unwrap_err(), X509Error::InvalidName);
    // DirectoryString as UTF8String, domainComponent and emailAddress as IA5String.
    let common = AttributeTypeAndValue::from_text(NameAttribute::CommonName, "例").unwrap();
    assert_eq!(common.value[0], 0x0C);
    assert_eq!(common.text().unwrap(), "例");
    let component = AttributeTypeAndValue::from_text(NameAttribute::DomainComponent, "com").unwrap();
    assert_eq!(component.value[0], 0x16);
    assert_eq!(
        AttributeTypeAndValue::from_text(NameAttribute::EmailAddress, "ü@example.com").unwrap_err(),
        X509Error::InvalidName
    );
    // The text of each string type of DirectoryString.
    let bmp =
        AttributeTypeAndValue::new(arcs("2.5.4.3"), Cow::Owned(vec![0x1E, 0x04, 0x00, 0x41, 0x30, 0x42])).unwrap();
    assert_eq!(bmp.text().unwrap(), "Aあ");
    let universal =
        AttributeTypeAndValue::new(arcs("2.5.4.3"), Cow::Owned(vec![0x1C, 0x04, 0x00, 0x01, 0xF6, 0x00])).unwrap();
    assert_eq!(universal.text().unwrap(), "😀");
    let teletex = AttributeTypeAndValue::new(arcs("2.5.4.3"), Cow::Owned(vec![0x14, 0x02, b'A', 0xE9])).unwrap();
    assert_eq!(teletex.text().unwrap(), "Aé");
    let integer = AttributeTypeAndValue::new(arcs("2.5.4.3"), Cow::Owned(vec![0x02, 0x01, 0x05])).unwrap();
    assert_eq!(integer.text().unwrap_err(), X509Error::InvalidName);
    // A value is one element.
    assert!(AttributeTypeAndValue::new(arcs("2.5.4.3"), Cow::Owned(vec![0x0C, 0x01, b'a', 0x00])).is_err());
}

#[test]
fn names_are_read_as_rfc_5280_defines_them() {
    let atav = |text: &[u8]| DER::sequence(&[&DER::oid("2.5.4.3"), &DER::element(0x0C, text)]);
    // A relative name is a non-empty SET OF in DER order.
    let empty_rdn = DER::sequence(&[&DER::element(0x31, &[])]);
    assert_eq!(Name::from_der(&empty_rdn).unwrap_err(), X509Error::InvalidName);
    let (a, b) = (atav(b"a"), atav(b"b"));
    let sorted = DER::sequence(&[&DER::element(0x31, &[a.as_slice(), b.as_slice()].concat())]);
    let name = Name::from_der(&sorted).unwrap();
    assert_eq!(name.rdns().count(), 1);
    assert_eq!(name.attributes().count(), 2);
    let unsorted = DER::sequence(&[&DER::element(0x31, &[b.as_slice(), a.as_slice()].concat())]);
    assert!(matches!(Name::from_der(&unsorted), Err(X509Error::Encoding(ASN1Error::NonCanonical { .. }))));
    // An attribute is a type and exactly one value.
    let two_values = DER::sequence(&[&DER::element(
        0x31,
        &DER::sequence(&[&DER::oid("2.5.4.3"), &DER::element(0x0C, b"a"), &DER::element(0x0C, b"b")]),
    )]);
    assert!(matches!(Name::from_der(&two_values), Err(X509Error::Encoding(_))));
    // The empty name.
    assert!(Name::from_der(&[0x30, 0x00]).unwrap().is_empty());
    assert_eq!(Name::from_der(&[0x30, 0x00]).unwrap(), Name::empty());
}

#[test]
fn times_take_the_form_rfc_5280_requires() {
    // §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050 (and before 1950, which UTCTime cannot hold).
    assert_eq!(Time::new(time(2049, 12, 31)).unwrap(), Time::UTC(time(2049, 12, 31)));
    assert_eq!(Time::new(time(2050, 1, 1)).unwrap(), Time::Generalized(time(2050, 1, 1)));
    assert_eq!(Time::new(time(1950, 1, 1)).unwrap(), Time::UTC(time(1950, 1, 1)));
    assert_eq!(Time::new(time(1949, 12, 31)).unwrap(), Time::Generalized(time(1949, 12, 31)));
    let fraction = ASN1Time::new(2026, 1, 1, 0, 0, 0, 500_000_000).unwrap();
    assert_eq!(Time::new(fraction).unwrap_err(), X509Error::InvalidTime);
    assert!(!Time::Generalized(time(2049, 1, 1)).is_canonical());
    assert!(!Time::UTC(time(2050, 1, 1)).is_canonical());
    let mut writer = DERWriter::new();
    assert_eq!(Time::UTC(time(2050, 1, 1)).encode(&mut writer).unwrap_err(), X509Error::InvalidTime);
    // §4.1.2.5.1 and §4.1.2.5.2: YYMMDDHHMMSSZ and YYYYMMDDHHMMSSZ.
    let mut writer = DERWriter::new();
    Time::new(time(2026, 1, 1)).unwrap().encode(&mut writer).unwrap();
    Time::new(time(2050, 1, 1)).unwrap().encode(&mut writer).unwrap();
    assert_eq!(writer.as_bytes(), [b"\x17\x0d260101000000Z".as_slice(), b"\x18\x0f20500101000000Z"].concat());
    // A GeneralizedTime with a fraction of a second is refused (§4.1.2.5.2).
    let validity = DER::sequence(&[b"\x18\x1120260101000000.5Z", b"\x17\x0d360101000000Z"]);
    assert!(matches!(Validity::decode(&mut DERReader::new(&validity)), Err(X509Error::Encoding(_))));
    // The validity includes both ends; 9999-12-31T23:59:59Z is the time without an end.
    let period = Validity::new(time(2026, 1, 1), Validity::NO_EXPIRATION).unwrap();
    assert!(period.contains(time(2026, 1, 1)));
    assert!(period.contains(Validity::NO_EXPIRATION));
    assert!(!period.contains(ASN1Time::new(2025, 12, 31, 23, 59, 59, 0).unwrap()));
    assert_eq!(period.not_after, Time::Generalized(Validity::NO_EXPIRATION));
}

#[test]
fn serial_numbers_follow_rfc_5280() {
    // §4.1.2.2: positive, at most 20 octets.
    assert_eq!(SerialNumber::from_u64(0x80).as_bytes(), [0x00, 0x80]);
    assert!(SerialNumber::from_u64(1).is_conforming());
    assert!(!SerialNumber::from_u64(0).is_conforming());
    assert!(!SerialNumber::new(Cow::Owned(vec![0xFF])).unwrap().is_conforming());
    assert!(SerialNumber::from_magnitude(&[0x7F; 20]).is_conforming());
    assert!(!SerialNumber::from_magnitude(&[0xFF; 20]).is_conforming(), "21 octets with the sign octet");
    assert_eq!(SerialNumber::from_u64(0).check().unwrap_err(), X509Error::InvalidSerialNumber);
    assert!(SerialNumber::new(Cow::Owned(vec![0x00, 0x01])).is_err(), "not minimal");
    let mut generator = random();
    let first = SerialNumber::random(&mut generator).unwrap();
    let second = SerialNumber::random(&mut generator).unwrap();
    assert!(first.is_conforming() && second.is_conforming());
    assert_ne!(first, second);
}

#[test]
fn extensions_are_written_in_der() {
    // KeyUsage: a named bit list without trailing zero bits (X.690 §11.2.2).
    let usage = |bits: KeyUsage| KeyUsage::to_der(&bits).unwrap();
    assert_eq!(usage(KeyUsage::DIGITAL_SIGNATURE), [0x03, 0x02, 0x07, 0x80]);
    assert_eq!(usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN), [0x03, 0x02, 0x01, 0x06]);
    assert_eq!(usage(KeyUsage::DECIPHER_ONLY), [0x03, 0x03, 0x07, 0x00, 0x80]);
    assert_eq!(KeyUsage::from_der(&[0x03, 0x02, 0x07, 0x80]).unwrap(), KeyUsage::DIGITAL_SIGNATURE);
    // Trailing zero bits are tolerated; bits beyond decipherOnly are refused.
    assert_eq!(KeyUsage::from_der(&[0x03, 0x03, 0x00, 0x80, 0x00]).unwrap(), KeyUsage::DIGITAL_SIGNATURE);
    assert_eq!(KeyUsage::from_der(&[0x03, 0x03, 0x06, 0x00, 0x40]).unwrap_err(), X509Error::InvalidExtension);
    // BasicConstraints: DEFAULT FALSE is omitted (X.690 §11.5).
    let basic = |ca, path_length| BasicConstraints { ca, path_length }.to_der().unwrap();
    assert_eq!(basic(false, None), [0x30, 0x00]);
    assert_eq!(basic(true, None), [0x30, 0x03, 0x01, 0x01, 0xFF]);
    assert_eq!(basic(true, Some(0)), [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00]);
    assert_eq!(
        BasicConstraints::from_der(&[0x30, 0x03, 0x02, 0x01, 0xFF]).unwrap_err(),
        X509Error::InvalidExtension,
        "pathLenConstraint is INTEGER (0..MAX)"
    );
    // A critical extension writes the BOOLEAN; a non-critical one omits it.
    let extension = Extension::new(&BasicConstraints { ca: true, path_length: None }, true).unwrap();
    let mut writer = DERWriter::new();
    extension.encode(&mut writer).unwrap();
    assert_eq!(
        writer.as_bytes(),
        DER::sequence(&[
            &DER::oid("2.5.29.19"),
            &[0x01, 0x01, 0xFF],
            &DER::element(0x04, &[0x30, 0x03, 0x01, 0x01, 0xFF])
        ])
    );
    let mut writer = DERWriter::new();
    Extension::new(&InhibitAnyPolicy { skip_certs: 1 }, false).unwrap().encode(&mut writer).unwrap();
    assert_eq!(writer.as_bytes(), DER::sequence(&[&DER::oid("2.5.29.54"), &DER::element(0x04, &[0x02, 0x01, 0x01])]));
    // CRLReason: an ENUMERATED of the codes RFC 5280 §5.3.1 defines; 7 is not one.
    assert_eq!(CRLReason::KeyCompromise.to_der().unwrap(), [0x0A, 0x01, 0x01]);
    assert_eq!(CRLReason::from_der(&[0x0A, 0x01, 0x07]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(CRLReason::from_der(&[0x0A, 0x01, 0x0A]).unwrap(), CRLReason::AACompromise);
}

#[test]
fn extensions_refuse_what_rfc_5280_forbids() {
    // AuthorityKeyIdentifier: the issuer and serial number both present or both absent (§4.2.1.1).
    let issuer_only = DER::sequence(&[&DER::element(0xA1, &DER::element(0x82, b"ca.example.com"))]);
    assert_eq!(AuthorityKeyIdentifier::from_der(&issuer_only).unwrap_err(), X509Error::InvalidExtension);
    let both = DER::sequence(&[&DER::element(0xA1, &DER::element(0x82, b"ca.example.com")), &DER::element(0x82, &[1])]);
    let identifier = AuthorityKeyIdentifier::from_der(&both).unwrap();
    assert_eq!(identifier.authority_cert_issuer.unwrap(), [GeneralName::DNSName(Cow::Borrowed("ca.example.com"))]);
    // GeneralNames and the other lists have at least one entry.
    assert_eq!(SubjectAlternativeName::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(ExtendedKeyUsage::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(CertificatePolicies::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(CRLDistributionPoints::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(AuthorityInformationAccess::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(PolicyMappings::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    // An iPAddress of a subject alternative name has 4 or 16 octets (§4.2.1.6).
    let address = |octets: &[u8]| DER::sequence(&[&DER::element(0x87, octets)]);
    assert!(SubjectAlternativeName::from_der(&address(&[192, 0, 2, 1])).is_ok());
    assert!(SubjectAlternativeName::from_der(&address(&[0; 16])).is_ok());
    assert_eq!(SubjectAlternativeName::from_der(&address(&[192, 0, 2])).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(SubjectAlternativeName::from_der(&address(&[0; 8])).unwrap_err(), X509Error::InvalidExtension);
    // A policy appears at most once (§4.2.1.4).
    let policy = DER::sequence(&[&DER::oid("1.2.3")]);
    let twice = DER::sequence(&[&policy, &policy]);
    assert_eq!(CertificatePolicies::from_der(&twice).unwrap_err(), X509Error::InvalidExtension);
    // At most one of the onlyContains flags (§5.2.5).
    let both_only = DER::sequence(&[&[0x81, 0x01, 0xFF], &[0x82, 0x01, 0xFF]]);
    assert_eq!(IssuingDistributionPoint::from_der(&both_only).unwrap_err(), X509Error::InvalidExtension);
    let user_only = DER::sequence(&[&[0x81, 0x01, 0xFF]]);
    let user_only = IssuingDistributionPoint::from_der(&user_only).unwrap();
    assert!(user_only.only_contains_user_certs && !user_only.only_contains_ca_certs);
    // A typed extension of the wrong type, and trailing data after the value.
    let extension = Extension::new(&KeyUsage::DIGITAL_SIGNATURE, true).unwrap();
    assert_eq!(extension.typed::<BasicConstraints>().unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(KeyUsage::from_der(&[0x03, 0x02, 0x07, 0x80, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    // A CRL number is not negative.
    assert_eq!(CRLNumber::from_der(&[0x02, 0x01, 0xFF]).unwrap_err(), X509Error::InvalidExtension);
}

#[test]
fn extension_lists_hold_each_type_once() {
    // §4.2: a certificate MUST NOT include more than one instance of an extension.
    let mut extensions = Extensions::new();
    extensions.push(Extension::new(&KeyUsage::DIGITAL_SIGNATURE, true).unwrap()).unwrap();
    assert_eq!(
        extensions.push(Extension::new(&KeyUsage::KEY_CERT_SIGN, true).unwrap()).unwrap_err(),
        X509Error::DuplicateExtension
    );
    let usage = DER::sequence(&[&DER::oid("2.5.29.15"), &DER::element(0x04, &[0x03, 0x02, 0x07, 0x80])]);
    let twice = DER::sequence(&[&usage, &usage]);
    assert_eq!(Extensions::decode(&mut DERReader::new(&twice)).unwrap_err(), X509Error::DuplicateExtension);
    // `Extensions` is SIZE (1..MAX).
    assert_eq!(Extensions::decode(&mut DERReader::new(&[0x30, 0x00])).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(Extensions::new().encode(&mut DERWriter::new()).unwrap_err(), X509Error::InvalidExtension);
    // A FALSE critical written out is read as not critical.
    let explicit = DER::sequence(&[&DER::sequence(&[
        &DER::oid("2.5.29.15"),
        &[0x01, 0x01, 0x00],
        &DER::element(0x04, &[0x03, 0x02, 0x07, 0x80]),
    ])]);
    let read = Extensions::decode(&mut DERReader::new(&explicit)).unwrap();
    assert!(!read.entries[0].critical);
    assert_eq!(read.typed::<KeyUsage>().unwrap(), Some(KeyUsage::DIGITAL_SIGNATURE));
    assert_eq!(read.typed::<BasicConstraints>().unwrap(), None);
}

#[test]
fn certificates_of_openssl() {
    let root = certificate("root");
    let intermediate = certificate("intermediate");
    let leaf = certificate("leaf");
    let root_key = root.public_key().unwrap();
    let intermediate_key = intermediate.public_key().unwrap();
    // The root: self-signed with ECDSA P-256.
    let tbs = root.tbs_certificate();
    assert_eq!(tbs.version, Version::V3);
    assert_eq!(tbs.serial_number, SerialNumber::from_u64(1));
    assert_eq!(
        SignatureAlgorithm::from_identifier(root.signature_algorithm()).unwrap(),
        SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256)
    );
    let root_name = Name::from_attributes(&[
        (NameAttribute::Country, "JP"),
        (NameAttribute::Organization, "umilib"),
        (NameAttribute::CommonName, "umilib Root CA"),
    ])
    .unwrap();
    assert_eq!(tbs.subject, root_name, "the encoding of the names OpenSSL wrote");
    assert_eq!(tbs.subject.to_rfc4514(), "CN=umilib Root CA,O=umilib,C=JP");
    assert!(root.is_self_issued());
    assert_eq!(tbs.validity, Validity::new(time(2026, 1, 1), time(2036, 1, 1)).unwrap());
    assert_eq!(root_key, private_key("root").public_key().unwrap());
    root.verify(&root_key).unwrap();
    let basic = tbs.extensions.get(&BasicConstraints::OID).unwrap();
    assert!(basic.critical);
    assert_eq!(basic.typed::<BasicConstraints>().unwrap(), BasicConstraints { ca: true, path_length: None });
    assert_eq!(tbs.extensions.typed::<KeyUsage>().unwrap(), Some(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN));
    let root_identifier = tbs.extensions.typed::<SubjectKeyIdentifier>().unwrap().unwrap();
    assert_eq!(root_identifier, SubjectKeyIdentifier::from_public_key(&root_key), "RFC 5280 §4.2.1.2 method 1");

    // The intermediate: every extension of a CA, signed by the root.
    intermediate.verify(&root_key).unwrap();
    assert_eq!(
        intermediate.verify(&intermediate_key).unwrap_err(),
        X509Error::Key(umilib::auth::cert::key::KeyError::Mismatch)
    );
    let tbs = intermediate.tbs_certificate();
    assert_eq!(
        tbs.serial_number.as_bytes(),
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
            0x45, 0x67
        ]
    );
    assert_eq!(tbs.issuer, root_name);
    let text = |attribute, text| AttributeTypeAndValue::from_text(attribute, text).unwrap();
    let intermediate_name = Name::new(&[
        RelativeDistinguishedName::new(&[text(NameAttribute::Country, "JP")]).unwrap(),
        RelativeDistinguishedName::new(&[text(NameAttribute::Organization, "umilib")]).unwrap(),
        RelativeDistinguishedName::new(&[
            text(NameAttribute::CommonName, "umilib Intermediate CA"),
            text(NameAttribute::OrganizationalUnit, "Testing"),
        ])
        .unwrap(),
    ])
    .unwrap();
    assert_eq!(tbs.subject, intermediate_name);
    assert_eq!(tbs.subject.to_rfc4514(), "OU=Testing+CN=umilib Intermediate CA,O=umilib,C=JP");
    let extensions = &tbs.extensions;
    assert_eq!(
        extensions.typed::<BasicConstraints>().unwrap(),
        Some(BasicConstraints { ca: true, path_length: Some(0) })
    );
    assert_eq!(
        extensions.typed::<KeyUsage>().unwrap(),
        Some(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
    );
    let intermediate_identifier = extensions.typed::<SubjectKeyIdentifier>().unwrap().unwrap();
    assert_eq!(intermediate_identifier, SubjectKeyIdentifier::from_public_key(&intermediate_key));
    assert_eq!(
        extensions.typed::<AuthorityKeyIdentifier>().unwrap().unwrap(),
        AuthorityKeyIdentifier {
            key_identifier: Some(root_identifier.key_identifier.clone()),
            authority_cert_issuer: Some(vec![GeneralName::DirectoryName(root_name.clone())]),
            authority_cert_serial_number: Some(SerialNumber::from_u64(1)),
        }
    );
    let constraints = extensions.get(&NameConstraints::OID).unwrap();
    assert!(constraints.critical);
    let subtree = |base| GeneralSubtree { base, minimum: 0, maximum: None };
    let mut ipv6 = vec![0x20, 0x01, 0x0d, 0xb8];
    ipv6.extend_from_slice(&[0; 12]);
    ipv6.extend_from_slice(&[0xff; 4]);
    ipv6.extend_from_slice(&[0; 12]);
    assert_eq!(
        constraints.typed::<NameConstraints>().unwrap(),
        NameConstraints {
            permitted_subtrees: vec![
                subtree(GeneralName::DNSName(Cow::Borrowed("example.com"))),
                subtree(GeneralName::IPAddress(Cow::Borrowed(&[192, 0, 2, 0, 255, 255, 255, 0]))),
                subtree(GeneralName::IPAddress(Cow::Owned(ipv6))),
                subtree(GeneralName::RFC822Name(Cow::Borrowed("example.com"))),
                subtree(GeneralName::DirectoryName(
                    Name::from_attributes(&[(NameAttribute::Country, "JP"), (NameAttribute::Organization, "umilib")])
                        .unwrap()
                )),
            ],
            excluded_subtrees: vec![subtree(GeneralName::DNSName(Cow::Borrowed("bad.example.com")))],
        }
    );
    let policies = extensions.typed::<CertificatePolicies>().unwrap().unwrap();
    assert_eq!(policies.policies.len(), 2);
    assert_eq!(policies.policies[0].identifier, arcs("1.3.6.1.4.1.55555.1"));
    let qualifiers = &policies.policies[0].qualifiers;
    assert_eq!(qualifiers[0].cps_uri().unwrap(), "https://example.com/cps");
    let notice = qualifiers[1].notice().unwrap();
    let reference = notice.notice_reference.unwrap();
    assert_eq!(reference.organization.text(), "umilib");
    assert_eq!(reference.notice_numbers, [1, 2, 3]);
    assert_eq!(notice.explicit_text.unwrap().text(), "Explicit text");
    assert_eq!(qualifiers[0].notice().unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(policies.policies[1].identifier, CertificatePolicies::ANY_POLICY);
    assert!(policies.policies[1].qualifiers.is_empty());
    assert_eq!(
        extensions.typed::<PolicyConstraints>().unwrap(),
        Some(PolicyConstraints { require_explicit_policy: Some(0), inhibit_policy_mapping: Some(1) })
    );
    assert_eq!(extensions.typed::<InhibitAnyPolicy>().unwrap(), Some(InhibitAnyPolicy { skip_certs: 2 }));
    assert_eq!(
        extensions.typed::<PolicyMappings>().unwrap().unwrap().mappings,
        [PolicyMapping {
            issuer_domain_policy: arcs("1.3.6.1.4.1.55555.1"),
            subject_domain_policy: arcs("1.3.6.1.4.1.55555.2")
        }]
    );
    assert_eq!(
        extensions.typed::<CRLDistributionPoints>().unwrap().unwrap().points,
        [DistributionPoint {
            name: Some(DistributionPointName::FullName(vec![GeneralName::URI(Cow::Borrowed(
                "http://crl.example.com/root.crl"
            ))])),
            reasons: None,
            crl_issuer: None,
        }]
    );
    let access = extensions.typed::<AuthorityInformationAccess>().unwrap().unwrap();
    assert_eq!(
        access.descriptions,
        [
            AccessDescription {
                method: AccessDescription::OCSP,
                location: GeneralName::URI(Cow::Borrowed("http://ocsp.example.com/"))
            },
            AccessDescription {
                method: AccessDescription::CA_ISSUERS,
                location: GeneralName::URI(Cow::Borrowed("http://ca.example.com/root.der"))
            },
        ]
    );

    // The leaf: every form of general name, signed by the intermediate with RSASSA-PKCS1-v1_5.
    leaf.verify(&intermediate_key).unwrap();
    assert_eq!(leaf.verify(&root_key).unwrap_err(), X509Error::Key(umilib::auth::cert::key::KeyError::Mismatch));
    let tbs = leaf.tbs_certificate();
    assert_eq!(tbs.issuer, intermediate_name);
    let leaf_name = Name::from_attributes(&[
        (NameAttribute::Country, "JP"),
        (NameAttribute::StateOrProvince, "東京都"),
        (NameAttribute::Locality, "Chiyoda"),
        (NameAttribute::Organization, "umilib"),
        (NameAttribute::CommonName, "www.example.com"),
        (NameAttribute::EmailAddress, "user@example.com"),
    ])
    .unwrap();
    assert_eq!(tbs.subject, leaf_name);
    let email = format!("1.2.840.113549.1.9.1=#1610{}", hex(b"user@example.com"));
    assert_eq!(tbs.subject.to_rfc4514(), format!("{email},CN=www.example.com,O=umilib,L=Chiyoda,ST=東京都,C=JP"));
    let extensions = &tbs.extensions;
    assert_eq!(
        extensions.typed::<BasicConstraints>().unwrap(),
        Some(BasicConstraints { ca: false, path_length: None })
    );
    assert_eq!(extensions.typed::<KeyUsage>().unwrap(), Some(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT));
    let usage = extensions.typed::<ExtendedKeyUsage>().unwrap().unwrap();
    assert_eq!(usage.purposes, [ExtendedKeyUsage::SERVER_AUTH, ExtendedKeyUsage::CLIENT_AUTH]);
    assert!(usage.contains(&ExtendedKeyUsage::SERVER_AUTH) && !usage.contains(&ExtendedKeyUsage::CODE_SIGNING));
    let mut ipv6 = vec![0x20, 0x01, 0x0d, 0xb8];
    ipv6.extend_from_slice(&[0; 11]);
    ipv6.push(1);
    let upn = der(|writer| writer.write_utf8_string("user@example.com"));
    assert_eq!(
        extensions.typed::<SubjectAlternativeName>().unwrap().unwrap().names,
        [
            GeneralName::DNSName(Cow::Borrowed("www.example.com")),
            GeneralName::DNSName(Cow::Borrowed("example.com")),
            GeneralName::IPAddress(Cow::Borrowed(&[192, 0, 2, 1])),
            GeneralName::IPAddress(Cow::Owned(ipv6)),
            GeneralName::RFC822Name(Cow::Borrowed("user@example.com")),
            GeneralName::URI(Cow::Borrowed("https://www.example.com/")),
            GeneralName::DirectoryName(
                Name::from_attributes(&[
                    (NameAttribute::Country, "JP"),
                    (NameAttribute::Organization, "umilib"),
                    (NameAttribute::CommonName, "Directory Name"),
                ])
                .unwrap()
            ),
            GeneralName::RegisteredID(arcs("1.2.3.4")),
            GeneralName::OtherName(OtherName { type_id: arcs("1.3.6.1.4.1.311.20.2.3"), value: Cow::Owned(upn) }),
        ]
    );
    assert_eq!(
        extensions.typed::<IssuerAlternativeName>().unwrap().unwrap().names,
        [GeneralName::URI(Cow::Borrowed("https://ca.example.com/"))]
    );
    assert_eq!(
        extensions.typed::<SubjectKeyIdentifier>().unwrap().unwrap(),
        SubjectKeyIdentifier::from_public_key(&leaf.public_key().unwrap())
    );
    assert_eq!(
        extensions.typed::<AuthorityKeyIdentifier>().unwrap().unwrap(),
        AuthorityKeyIdentifier {
            key_identifier: Some(intermediate_identifier.key_identifier.clone()),
            ..Default::default()
        }
    );
    assert_eq!(
        extensions.typed::<CRLDistributionPoints>().unwrap().unwrap().points,
        [DistributionPoint {
            name: Some(DistributionPointName::FullName(vec![GeneralName::URI(Cow::Borrowed(
                "http://crl.example.com/intermediate.crl"
            ))])),
            reasons: Some(ReasonFlags { bits: ReasonFlags::KEY_COMPROMISE.bits | ReasonFlags::CA_COMPROMISE.bits }),
            crl_issuer: Some(vec![GeneralName::DirectoryName(
                Name::from_attributes(&[
                    (NameAttribute::Country, "JP"),
                    (NameAttribute::Organization, "umilib"),
                    (NameAttribute::CommonName, "CRL Issuer"),
                ])
                .unwrap()
            )]),
        }]
    );
    assert_eq!(
        extensions.typed::<FreshestCRL>().unwrap().unwrap().points[0].name,
        Some(DistributionPointName::FullName(vec![GeneralName::URI(Cow::Borrowed(
            "http://crl.example.com/delta.crl"
        ))]))
    );
    assert_eq!(
        extensions.typed::<SubjectInformationAccess>().unwrap().unwrap().descriptions,
        [AccessDescription {
            method: AccessDescription::CA_REPOSITORY,
            location: GeneralName::URI(Cow::Borrowed("http://repository.example.com/"))
        }]
    );

    // Leaves of other key types and signature algorithms.
    let pss = certificate("leaf-pss");
    pss.verify(&intermediate_key).unwrap();
    assert_eq!(
        SignatureAlgorithm::from_identifier(pss.signature_algorithm()).unwrap(),
        SignatureAlgorithm::RSAPSS(PSSParameters {
            salt_length: 32,
            ..PSSParameters::with_hash(HashAlgorithm::SHA256)
        })
    );
    assert_eq!(
        pss.tbs_certificate().validity.not_after,
        Time::Generalized(time(2051, 1, 1)),
        "§4.1.2.5: 2050 and later"
    );
    let kem = certificate("leaf-mlkem768");
    kem.verify(&intermediate_key).unwrap();
    assert_eq!(kem.public_key().unwrap().algorithm(), &KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM768));
    assert_eq!(kem.public_key().unwrap(), private_key("leaf-mlkem768").public_key().unwrap());
    assert_eq!(kem.tbs_certificate().extensions.typed::<KeyUsage>().unwrap(), Some(KeyUsage::KEY_ENCIPHERMENT));
    let x25519 = certificate("leaf-x25519");
    x25519.verify(&intermediate_key).unwrap();
    assert_eq!(x25519.public_key().unwrap().algorithm(), &KeyAlgorithm::X25519);
    assert_eq!(x25519.tbs_certificate().extensions.typed::<KeyUsage>().unwrap(), Some(KeyUsage::KEY_AGREEMENT));
}

#[test]
fn self_signed_certificates_of_each_algorithm() {
    let cases = [
        ("p384", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA384), KeyAlgorithm::EC(NamedCurve::P384)),
        ("p521", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA512), KeyAlgorithm::EC(NamedCurve::P521)),
        ("rsa", SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA512), KeyAlgorithm::RSA),
        (
            "rsa-pss",
            SignatureAlgorithm::RSAPSS(PSSParameters {
                salt_length: 48,
                ..PSSParameters::with_hash(HashAlgorithm::SHA384)
            }),
            KeyAlgorithm::RSAPSS(Some(PSSParameters {
                salt_length: 48,
                ..PSSParameters::with_hash(HashAlgorithm::SHA384)
            })),
        ),
        ("ed25519", SignatureAlgorithm::Ed25519, KeyAlgorithm::Ed25519),
        ("ed448", SignatureAlgorithm::Ed448, KeyAlgorithm::Ed448),
        (
            "mldsa44",
            SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44),
            KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44),
        ),
        (
            "mldsa65",
            SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65),
            KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65),
        ),
        (
            "mldsa87",
            SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA87),
            KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA87),
        ),
        (
            "slhdsa-sha2-128s",
            SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128s),
            KeyAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128s),
        ),
        (
            "slhdsa-shake-128f",
            SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHAKE_128f),
            KeyAlgorithm::SLHDSA(SLHDSAParameterSet::SHAKE_128f),
        ),
    ];
    for (name, signature, key) in cases {
        let certificate = certificate(name);
        assert_eq!(
            SignatureAlgorithm::from_identifier(certificate.signature_algorithm()).unwrap(),
            signature,
            "{name}"
        );
        let public_key = certificate.public_key().unwrap();
        assert_eq!(public_key.algorithm(), &key, "{name}");
        assert_eq!(public_key, private_key(name).public_key().unwrap(), "{name}");
        certificate.verify(&public_key).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert!(certificate.is_self_issued());
        assert_eq!(certificate.tbs_certificate().subject.to_rfc4514(), format!("CN={name}"));
        // A changed signed byte or signature byte fails.
        let mut tampered = Fixtures::X509.bytes(&format!("{name}.der"));
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(Certificate::from_der(&tampered).unwrap().verify(&public_key).is_err(), "{name}");
    }
}

/// Every certificate fixture, by file name.
const CERTIFICATES: [&str; 17] = [
    "root",
    "intermediate",
    "leaf",
    "leaf-pss",
    "leaf-mlkem768",
    "leaf-x25519",
    "p384",
    "p521",
    "rsa",
    "rsa-pss",
    "ed25519",
    "ed448",
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "slhdsa-sha2-128s",
    "slhdsa-shake-128f",
];

/// Decodes every extension of `extensions` of a known type and checks that
/// it is written back to the same bytes, as DER makes every value one encoding.
fn check_extensions(extensions: &Extensions<'_>, context: &str) {
    for extension in &extensions.entries {
        let value = extension.value.as_ref();
        let written = match &extension.oid {
            oid if *oid == AuthorityKeyIdentifier::OID => AuthorityKeyIdentifier::from_der(value).unwrap().to_der(),
            oid if *oid == SubjectKeyIdentifier::OID => SubjectKeyIdentifier::from_der(value).unwrap().to_der(),
            oid if *oid == KeyUsage::OID => KeyUsage::from_der(value).unwrap().to_der(),
            oid if *oid == ExtendedKeyUsage::OID => ExtendedKeyUsage::from_der(value).unwrap().to_der(),
            oid if *oid == SubjectAlternativeName::OID => SubjectAlternativeName::from_der(value).unwrap().to_der(),
            oid if *oid == IssuerAlternativeName::OID => IssuerAlternativeName::from_der(value).unwrap().to_der(),
            oid if *oid == BasicConstraints::OID => BasicConstraints::from_der(value).unwrap().to_der(),
            oid if *oid == NameConstraints::OID => NameConstraints::from_der(value).unwrap().to_der(),
            oid if *oid == CertificatePolicies::OID => CertificatePolicies::from_der(value).unwrap().to_der(),
            oid if *oid == PolicyConstraints::OID => PolicyConstraints::from_der(value).unwrap().to_der(),
            oid if *oid == PolicyMappings::OID => PolicyMappings::from_der(value).unwrap().to_der(),
            oid if *oid == InhibitAnyPolicy::OID => InhibitAnyPolicy::from_der(value).unwrap().to_der(),
            oid if *oid == CRLDistributionPoints::OID => CRLDistributionPoints::from_der(value).unwrap().to_der(),
            oid if *oid == FreshestCRL::OID => FreshestCRL::from_der(value).unwrap().to_der(),
            oid if *oid == AuthorityInformationAccess::OID => {
                AuthorityInformationAccess::from_der(value).unwrap().to_der()
            }
            oid if *oid == SubjectInformationAccess::OID => SubjectInformationAccess::from_der(value).unwrap().to_der(),
            oid if *oid == CRLNumber::OID => CRLNumber::from_der(value).unwrap().to_der(),
            oid if *oid == CRLReason::OID => CRLReason::from_der(value).unwrap().to_der(),
            oid if *oid == InvalidityDate::OID => InvalidityDate::from_der(value).unwrap().to_der(),
            oid if *oid == HoldInstructionCode::OID => HoldInstructionCode::from_der(value).unwrap().to_der(),
            oid => panic!("{context}: an extension the fixtures were not expected to have: {oid}"),
        };
        assert_eq!(written.unwrap(), value, "{context}: {}", extension.oid);
    }
}

#[test]
fn fixtures_are_written_back_to_their_bytes() {
    for name in CERTIFICATES {
        let bytes = Fixtures::X509.bytes(&format!("{name}.der"));
        let certificate = Certificate::from_der(&bytes).unwrap();
        assert_eq!(certificate.to_der().unwrap(), bytes, "{name}");
        assert_eq!(certificate.tbs_certificate().to_der().unwrap(), certificate.tbs_encoding(), "{name}");
        let pem = certificate.to_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert_eq!(Certificate::from_pem(&pem).unwrap(), certificate.clone().into_owned(), "{name}");
        check_extensions(&certificate.tbs_certificate().extensions, name);
    }
    for name in ["root", "intermediate"] {
        let bytes = Fixtures::X509.bytes(&format!("{name}.crl"));
        let list = CertificateList::from_der(&bytes).unwrap();
        assert_eq!(list.to_der().unwrap(), bytes, "{name}.crl");
        assert_eq!(list.tbs_cert_list().to_der().unwrap(), list.tbs_encoding(), "{name}.crl");
        assert_eq!(CertificateList::from_pem(&list.to_pem().unwrap()).unwrap(), list.clone().into_owned());
        check_extensions(&list.tbs_cert_list().extensions, name);
        for entry in &list.tbs_cert_list().revoked_certificates {
            check_extensions(&entry.extensions, name);
        }
    }
    // A chain in PEM; documents of other labels are refused.
    let chain: String =
        ["leaf", "intermediate", "root"].iter().map(|name| certificate(name).to_pem().unwrap()).collect();
    let certificates = Certificate::from_pem_all(&chain).unwrap();
    assert_eq!(certificates, [certificate("leaf"), certificate("intermediate"), certificate("root")]);
    let key = Fixtures::X509.text("root.key");
    assert_eq!(Certificate::from_pem(&key).unwrap_err(), X509Error::PEMLabel);
    assert_eq!(Certificate::from_pem_all(&(chain + &key)).unwrap_err(), X509Error::PEMLabel);
}

#[test]
fn crls_of_openssl() {
    let root = certificate("root");
    let intermediate = certificate("intermediate");
    let bytes = Fixtures::X509.bytes("root.crl");
    let list = CertificateList::from_der(&bytes).unwrap();
    list.verify(&root.public_key().unwrap()).unwrap();
    let tbs = list.tbs_cert_list();
    assert_eq!(tbs.version, Version::V2);
    assert_eq!(tbs.issuer, root.tbs_certificate().subject);
    assert!(tbs.revoked_certificates.is_empty());
    let next_update = tbs.next_update.unwrap();
    assert_eq!(next_update.to_unix_seconds() - tbs.this_update.to_unix_seconds(), 30 * 86_400);
    assert_eq!(tbs.extensions.typed::<CRLNumber>().unwrap().unwrap().as_u128().unwrap(), 0x1000);
    let root_identifier = root.tbs_certificate().extensions.typed::<SubjectKeyIdentifier>().unwrap().unwrap();
    assert_eq!(
        tbs.extensions.typed::<AuthorityKeyIdentifier>().unwrap().unwrap().key_identifier.unwrap(),
        root_identifier.key_identifier
    );

    let bytes = Fixtures::X509.bytes("intermediate.crl");
    let list = CertificateList::from_der(&bytes).unwrap();
    list.verify(&intermediate.public_key().unwrap()).unwrap();
    assert!(list.verify(&root.public_key().unwrap()).is_err());
    let tbs = list.tbs_cert_list();
    assert_eq!(tbs.extensions.typed::<CRLNumber>().unwrap().unwrap().as_u128().unwrap(), 0x1001);
    assert_eq!(
        tbs.extensions.typed::<IssuerAlternativeName>().unwrap().unwrap().names,
        [GeneralName::URI(Cow::Borrowed("https://ca.example.com/"))]
    );
    assert_eq!(tbs.revoked_certificates.len(), 2);
    let compromised = list.find(&SerialNumber::from_u64(2)).unwrap();
    assert_eq!(compromised.extensions.typed::<CRLReason>().unwrap(), Some(CRLReason::KeyCompromise));
    assert_eq!(
        compromised.extensions.typed::<InvalidityDate>().unwrap(),
        Some(InvalidityDate { time: time(2026, 2, 1) })
    );
    let held = list.find(&SerialNumber::from_u64(3)).unwrap();
    assert_eq!(held.extensions.typed::<CRLReason>().unwrap(), Some(CRLReason::CertificateHold));
    assert_eq!(
        held.extensions.typed::<HoldInstructionCode>().unwrap().unwrap().instruction,
        HoldInstructionCode::CALL_ISSUER
    );
    assert!(list.find(&SerialNumber::from_u64(4)).is_none());
}

/// A certificate of a self-signed CA of `key`, whose fields `change` may alter before signing.
fn build(
    key: &PrivateKey,
    algorithm: SignatureAlgorithm,
    change: impl FnOnce(&mut TBSCertificate<'static>),
) -> Result<Certificate<'static>, X509Error> {
    let public_key = key.public_key().unwrap();
    let name =
        Name::from_attributes(&[(NameAttribute::Country, "JP"), (NameAttribute::CommonName, "umilib built")]).unwrap();
    let mut extensions = Extensions::new();
    extensions.push(Extension::new(&BasicConstraints { ca: true, path_length: Some(1) }, true).unwrap()).unwrap();
    extensions.push(Extension::new(&(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN), true).unwrap()).unwrap();
    extensions.push(Extension::new(&SubjectKeyIdentifier::from_public_key(&public_key), false).unwrap()).unwrap();
    let mut tbs = TBSCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from_u64(0x0102030405),
        signature: algorithm.identifier().unwrap(),
        issuer: name.clone(),
        validity: Validity::new(time(2026, 1, 1), time(2056, 1, 1)).unwrap(),
        subject: name,
        subject_public_key_info: public_key.info().unwrap().into_owned(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };
    change(&mut tbs);
    tbs.sign(key, &mut random())
}

#[test]
fn built_certificates_are_signed_and_read_back() {
    let cases = [
        ("root", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256)),
        ("rsa", SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256)),
        ("rsa", SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA512))),
        (
            "rsa-pss",
            SignatureAlgorithm::RSAPSS(PSSParameters {
                salt_length: 48,
                ..PSSParameters::with_hash(HashAlgorithm::SHA384)
            }),
        ),
        ("ed25519", SignatureAlgorithm::Ed25519),
        ("ed448", SignatureAlgorithm::Ed448),
        ("mldsa44", SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44)),
        ("slhdsa-shake-128f", SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHAKE_128f)),
    ];
    for (name, algorithm) in cases {
        let key = private_key(name);
        let built = build(&key, algorithm, |_| {}).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        built.verify(&key.public_key().unwrap()).unwrap();
        let bytes = built.to_der().unwrap();
        let read = Certificate::from_der(&bytes).unwrap();
        assert_eq!(read, built, "{name}");
        let tbs = read.tbs_certificate();
        assert_eq!(tbs.validity.not_after, Time::Generalized(time(2056, 1, 1)));
        assert_eq!(
            tbs.extensions.typed::<BasicConstraints>().unwrap(),
            Some(BasicConstraints { ca: true, path_length: Some(1) })
        );
        assert_eq!(tbs.subject.to_rfc4514(), "CN=umilib built,C=JP");
        // A key that cannot make the signature algorithm is refused.
        if name == "ed25519" {
            assert_eq!(
                build(&key, SignatureAlgorithm::Ed448, |_| {}).unwrap_err(),
                X509Error::Key(umilib::auth::cert::key::KeyError::Mismatch)
            );
        }
    }
    // Deterministic signatures make the same certificate.
    let key = private_key("ed25519");
    assert_eq!(
        build(&key, SignatureAlgorithm::Ed25519, |_| {}).unwrap(),
        build(&key, SignatureAlgorithm::Ed25519, |_| {}).unwrap()
    );
}

#[test]
fn built_certificates_meet_the_requirements_on_cas() {
    let key = private_key("ed25519");
    let build = |change: fn(&mut TBSCertificate<'static>)| build(&key, SignatureAlgorithm::Ed25519, change);
    // §4.1.2.2: a positive serial number of at most 20 octets.
    assert_eq!(build(|tbs| tbs.serial_number = SerialNumber::from_u64(0)).unwrap_err(), X509Error::InvalidSerialNumber);
    assert_eq!(
        build(|tbs| tbs.serial_number = SerialNumber::from_magnitude(&[0xFF; 20])).unwrap_err(),
        X509Error::InvalidSerialNumber
    );
    // §4.1.2.4: a non-empty issuer.
    assert_eq!(build(|tbs| tbs.issuer = Name::empty()).unwrap_err(), X509Error::InvalidName);
    // §4.2.1.9: a pathLenConstraint only with cA and the keyCertSign usage.
    fn replace(tbs: &mut TBSCertificate<'static>, extension: Extension<'static>) {
        let index = tbs.extensions.entries.iter().position(|entry| entry.oid == extension.oid).unwrap();
        tbs.extensions.entries[index] = extension;
    }
    assert_eq!(
        build(|tbs| replace(tbs, Extension::new(&BasicConstraints { ca: false, path_length: Some(0) }, true).unwrap()))
            .unwrap_err(),
        X509Error::InvalidExtension
    );
    assert_eq!(
        build(|tbs| replace(tbs, Extension::new(&KeyUsage::CRL_SIGN, true).unwrap())).unwrap_err(),
        X509Error::InvalidExtension
    );
    assert!(
        build(|tbs| {
            replace(tbs, Extension::new(&BasicConstraints { ca: true, path_length: None }, true).unwrap());
            replace(tbs, Extension::new(&KeyUsage::CRL_SIGN, true).unwrap());
        })
        .is_ok()
    );
    // §4.1.2.5: UTCTime through 2049.
    assert_eq!(
        build(|tbs| tbs.validity.not_before = Time::Generalized(time(2026, 1, 1))).unwrap_err(),
        X509Error::InvalidTime
    );
    // §4.1.2.6: an empty subject needs a critical subject alternative name.
    assert_eq!(build(|tbs| tbs.subject = Name::empty()).unwrap_err(), X509Error::InvalidName);
    let names = SubjectAlternativeName { names: vec![GeneralName::DNSName(Cow::Borrowed("example.com"))] };
    let built = build(|tbs| {
        tbs.subject = Name::empty();
        let names = SubjectAlternativeName { names: vec![GeneralName::DNSName(Cow::Borrowed("example.com"))] };
        tbs.extensions.push(Extension::new(&names, true).unwrap()).unwrap();
    })
    .unwrap();
    assert_eq!(built.tbs_certificate().extensions.typed::<SubjectAlternativeName>().unwrap().unwrap(), names);
    assert_eq!(
        build(|tbs| {
            tbs.subject = Name::empty();
            let names = SubjectAlternativeName { names: vec![GeneralName::DNSName(Cow::Borrowed("example.com"))] };
            tbs.extensions.push(Extension::new(&names, false).unwrap()).unwrap();
        })
        .unwrap_err(),
        X509Error::InvalidName
    );
    // §4.1.2.8: no unique identifiers; §4.1.2.1: extensions need v3.
    assert_eq!(
        build(|tbs| tbs.subject_unique_id = Some(umilib::codec::asn1::BitString::new(0, vec![1]).unwrap()))
            .unwrap_err(),
        X509Error::InvalidName
    );
    assert_eq!(build(|tbs| tbs.version = Version::V2).unwrap_err(), X509Error::Version);
    // §4.2: each extension once.
    assert_eq!(
        build(|tbs| tbs.extensions.entries.push(Extension::new(&KeyUsage::DIGITAL_SIGNATURE, true).unwrap()))
            .unwrap_err(),
        X509Error::DuplicateExtension
    );
    // A v1 certificate has no version field and no extensions.
    let v1 = build(|tbs| {
        tbs.version = Version::V1;
        tbs.extensions = Extensions::new();
    })
    .unwrap();
    let encoding = v1.tbs_certificate().to_der().unwrap();
    let mut reader = DERReader::new(&encoding);
    let mut fields = reader.read_sequence().unwrap();
    assert_eq!(fields.peek_tag(), Some(umilib::codec::asn1::Tag::INTEGER), "the serial number comes first");
    let _ = fields.read_integer();
    assert_eq!(Certificate::from_der(&v1.to_der().unwrap()).unwrap().tbs_certificate().version, Version::V1);
}

/// The DER of a certificate whose `TBSCertificate` contents are `fields` and whose outer algorithm is `algorithm`.
fn handmade(fields: &[&[u8]], algorithm: &[u8]) -> Vec<u8> {
    DER::sequence(&[&DER::sequence(fields), algorithm, &DER::element(0x03, &[0x00, 0x01])])
}

#[test]
fn certificates_are_read_as_rfc_5280_defines_them() {
    let ed25519 = DER::sequence(&[&DER::oid("1.3.101.112")]);
    let name =
        DER::sequence(&[&DER::element(0x31, &DER::sequence(&[&DER::oid("2.5.4.3"), &DER::element(0x0C, b"x")]))]);
    let validity = DER::sequence(&[b"\x17\x0d260101000000Z", b"\x17\x0d360101000000Z"]);
    let key = DER::sequence(&[&ed25519, &DER::element(0x03, &[[0u8].as_slice(), &[1; 32]].concat())]);
    let usage = DER::sequence(&[&DER::oid("2.5.29.15"), &DER::element(0x04, &[0x03, 0x02, 0x07, 0x80])]);
    let extensions = DER::element(0xA3, &DER::sequence(&[&usage]));
    let version = |number: u8| DER::element(0xA0, &DER::integer(number));
    let serial = DER::integer(1);
    let base: [&[u8]; 6] = [&serial, &ed25519, &name, &validity, &name, &key];
    let read = |fields: &[&[u8]]| {
        Certificate::from_der(&handmade(fields, &ed25519)).map(|certificate| certificate.tbs_certificate().version)
    };
    // v1 without the version field, and with it written out (its DEFAULT), v3 with extensions.
    assert_eq!(read(&base), Ok(Version::V1));
    assert_eq!(read(&[&[version(0).as_slice()], base.as_slice()].concat()), Ok(Version::V1));
    assert_eq!(read(&[&[version(2).as_slice()], base.as_slice(), &[extensions.as_slice()]].concat()), Ok(Version::V3));
    // §4.1.2.1: unknown versions, and extensions before v3.
    assert_eq!(read(&[&[version(3).as_slice()], base.as_slice()].concat()), Err(X509Error::Version));
    assert_eq!(
        read(&[&[version(1).as_slice()], base.as_slice(), &[extensions.as_slice()]].concat()),
        Err(X509Error::Version)
    );
    assert_eq!(read(&[base.as_slice(), &[extensions.as_slice()]].concat()), Err(X509Error::Version));
    // §4.1.2.8: unique identifiers need v2 or v3.
    let unique = DER::element(0x81, &[0x00, 0xAA]);
    assert_eq!(read(&[base.as_slice(), &[unique.as_slice()]].concat()), Err(X509Error::Version));
    assert_eq!(read(&[&[version(1).as_slice()], base.as_slice(), &[unique.as_slice()]].concat()), Ok(Version::V2));
    // §4.2: Extensions is SIZE (1..MAX), each type once.
    let empty = DER::element(0xA3, &[0x30, 0x00]);
    assert_eq!(
        read(&[&[version(2).as_slice()], base.as_slice(), &[empty.as_slice()]].concat()),
        Err(X509Error::InvalidExtension)
    );
    let twice = DER::element(0xA3, &DER::sequence(&[&usage, &usage]));
    assert_eq!(
        read(&[&[version(2).as_slice()], base.as_slice(), &[twice.as_slice()]].concat()),
        Err(X509Error::DuplicateExtension)
    );
    // §4.1.1.2: the outer algorithm equals the inner one.
    let ed448 = DER::sequence(&[&DER::oid("1.3.101.113")]);
    assert_eq!(Certificate::from_der(&handmade(&base, &ed448)).unwrap_err(), X509Error::AlgorithmMismatch);
    // The signature is whole octets; nothing follows the certificate.
    let mut odd = handmade(&base, &ed25519);
    let length = odd.len();
    odd[length - 2] = 0x01;
    assert!(matches!(Certificate::from_der(&odd), Err(X509Error::Encoding(_))));
    let mut trailing = handmade(&base, &ed25519);
    trailing.push(0);
    assert!(matches!(Certificate::from_der(&trailing), Err(X509Error::Encoding(_))));
    // Every field is required; a field out of order is refused.
    assert!(Certificate::from_der(&handmade(&base[..5], &ed25519)).is_err());
    assert!(Certificate::from_der(&handmade(&[&serial, &ed25519, &validity, &name, &name, &key], &ed25519)).is_err());
}

#[test]
fn crls_are_read_and_built_as_rfc_5280_defines_them() {
    let key = private_key("ed25519");
    let issuer = Name::from_attributes(&[(NameAttribute::CommonName, "CRL Issuer")]).unwrap();
    let entry = |serial, extensions: Extensions<'static>| RevokedCertificate {
        serial_number: SerialNumber::from_u64(serial),
        revocation_date: Time::new(time(2026, 3, 1)).unwrap(),
        extensions,
    };
    let mut reason = Extensions::new();
    reason.push(Extension::new(&CRLReason::Superseded, false).unwrap()).unwrap();
    let mut extensions = Extensions::new();
    extensions.push(Extension::new(&CRLNumber::from_u64(7), false).unwrap()).unwrap();
    let tbs = TBSCertList {
        version: Version::V2,
        signature: SignatureAlgorithm::Ed25519.identifier().unwrap(),
        issuer: issuer.clone(),
        this_update: Time::new(time(2026, 3, 1)).unwrap(),
        next_update: Some(Time::new(time(2026, 4, 1)).unwrap()),
        revoked_certificates: vec![entry(10, reason), entry(11, Extensions::new())],
        extensions,
    };
    let list = tbs.sign(&key, &mut random()).unwrap();
    list.verify(&key.public_key().unwrap()).unwrap();
    let bytes = list.to_der().unwrap();
    let read = CertificateList::from_der(&bytes).unwrap();
    assert_eq!(read, list);
    assert_eq!(
        read.find(&SerialNumber::from_u64(10)).unwrap().extensions.typed::<CRLReason>().unwrap(),
        Some(CRLReason::Superseded)
    );
    // §5.1.2.1: v2 when there are extensions; only v1 and v2 exist.
    assert_eq!(
        TBSCertList { version: Version::V1, ..tbs.clone() }.sign(&key, &mut random()).unwrap_err(),
        X509Error::Version
    );
    assert_eq!(
        TBSCertList { version: Version::V3, ..tbs.clone() }.sign(&key, &mut random()).unwrap_err(),
        X509Error::Version
    );
    let plain = TBSCertList {
        version: Version::V1,
        revoked_certificates: vec![entry(12, Extensions::new())],
        extensions: Extensions::new(),
        ..tbs.clone()
    };
    let v1 = plain.sign(&key, &mut random()).unwrap();
    assert_eq!(CertificateList::from_der(&v1.to_der().unwrap()).unwrap().tbs_cert_list().version, Version::V1);
    // §5.1.2.5: conforming issuers include nextUpdate; §5.1.2.3: a non-empty issuer.
    assert_eq!(
        TBSCertList { next_update: None, ..tbs.clone() }.sign(&key, &mut random()).unwrap_err(),
        X509Error::InvalidTime
    );
    assert_eq!(
        TBSCertList { issuer: Name::empty(), ..tbs.clone() }.sign(&key, &mut random()).unwrap_err(),
        X509Error::InvalidName
    );
    // A CRL without entries omits the list (§5.1.2.6); one without nextUpdate is still read.
    let empty = TBSCertList { revoked_certificates: Vec::new(), next_update: None, ..tbs.clone() };
    let encoding = empty.to_der().unwrap();
    let ed25519 = DER::sequence(&[&DER::oid("1.3.101.112")]);
    let crl_number = DER::sequence(&[&DER::oid("2.5.29.20"), &DER::element(0x04, &DER::integer(7))]);
    let extensions = DER::element(0xA0, &DER::sequence(&[&crl_number]));
    let expected = DER::sequence(&[&DER::integer(1), &ed25519, issuer.as_der(), b"\x17\x0d260301000000Z", &extensions]);
    assert_eq!(encoding, expected);
    assert_eq!(TBSCertList::from_der(&encoding).unwrap(), empty);
    // An empty list written out is read as no entries.
    let written = DER::sequence(&[
        &DER::integer(1),
        &ed25519,
        issuer.as_der(),
        b"\x17\x0d260301000000Z",
        &[0x30, 0x00],
        &extensions,
    ]);
    assert_eq!(TBSCertList::from_der(&written).unwrap(), empty);
    // A version written as v1 is refused: the field is present only for v2.
    let ed25519 = DER::sequence(&[&DER::oid("1.3.101.112")]);
    let this_update = b"\x17\x0d260101000000Z";
    let fields = |version: &[u8]| DER::sequence(&[version, &ed25519, issuer.as_der(), this_update]);
    assert!(TBSCertList::from_der(&fields(&DER::integer(1))).is_ok());
    assert_eq!(TBSCertList::from_der(&fields(&DER::integer(0))).unwrap_err(), X509Error::Version);
    assert_eq!(TBSCertList::from_der(&fields(&DER::integer(2))).unwrap_err(), X509Error::Version);
}

#[test]
fn rfc_example_certificates() {
    // RFC 8410 §10.2: an X25519 key certified with Ed25519.
    let blocks = RFCExamples::pem_blocks(RFC8410);
    let (_, _, data) =
        blocks.iter().find(|(heading, label, _)| heading.starts_with("10.2.") && label == "CERTIFICATE").unwrap();
    let x25519 = Certificate::from_der(data).unwrap();
    assert_eq!(x25519.public_key().unwrap().algorithm(), &KeyAlgorithm::X25519);
    assert_eq!(x25519.tbs_certificate().subject.to_rfc4514(), "CN=IETF Test Demo");
    assert_eq!(x25519.to_der().unwrap(), *data);
    let signer =
        PublicKey::from_der(&blocks.iter().find(|(heading, _, _)| heading.starts_with("10.1.")).unwrap().2).unwrap();
    x25519.verify(&signer).unwrap();
    // RFC 9881 C.3: self-signed ML-DSA certificates; RFC 9935 C.3: ML-KEM certificates they issued.
    let certificates = |text: &str| -> Vec<Certificate<'static>> {
        RFCExamples::pem_blocks(text)
            .iter()
            .filter(|(heading, label, _)| heading.starts_with("C.3.") && label == "CERTIFICATE")
            .map(|(_, _, data)| Certificate::from_der(data).unwrap().into_owned())
            .collect()
    };
    let mldsa = certificates(RFC9881);
    assert_eq!(mldsa.len(), 3);
    for (certificate, set) in mldsa.iter().zip(MLDSAParameterSet::ALL) {
        assert_eq!(certificate.public_key().unwrap().algorithm(), &KeyAlgorithm::MLDSA(set));
        certificate.verify(&certificate.public_key().unwrap()).unwrap();
        assert_eq!(
            certificate.tbs_certificate().extensions.typed::<KeyUsage>().unwrap(),
            Some(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
        );
    }
    let mlkem = certificates(RFC9935);
    assert_eq!(mlkem.len(), 3);
    for ((certificate, issuer), set) in mlkem.iter().zip(&mldsa).zip(MLKEMParameterSet::ALL) {
        assert_eq!(certificate.public_key().unwrap().algorithm(), &KeyAlgorithm::MLKEM(set));
        assert_eq!(certificate.tbs_certificate().issuer, issuer.tbs_certificate().subject);
        certificate.verify(&issuer.public_key().unwrap()).unwrap();
    }
    // RFC 9909 C.3: a self-signed SLH-DSA certificate.
    let slhdsa = certificates(RFC9909);
    assert_eq!(slhdsa.len(), 1);
    slhdsa[0].verify(&slhdsa[0].public_key().unwrap()).unwrap();
    for certificate in mldsa.iter().chain(&mlkem).chain(&slhdsa) {
        check_extensions(&certificate.tbs_certificate().extensions, "RFC example");
        assert_eq!(certificate.tbs_certificate().to_der().unwrap(), certificate.tbs_encoding());
    }
}

#[test]
fn empty_values_rfc_5280_forbids_are_refused_both_ways() {
    // §4.2.1.10 and §4.2.1.11: one of the two fields is present.
    assert_eq!(NameConstraints::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(NameConstraints::default().to_der().unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(PolicyConstraints::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(PolicyConstraints::default().to_der().unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(
        PolicyConstraints::from_der(&[0x30, 0x03, 0x81, 0x01, 0x00]).unwrap(),
        PolicyConstraints { require_explicit_policy: None, inhibit_policy_mapping: Some(0) }
    );
    // §4.2.1.13: a distribution point has a name or a CRL issuer, not only reasons.
    let only_reasons = DER::sequence(&[&DER::sequence(&[&[0x81, 0x02, 0x07, 0x80]])]);
    assert_eq!(CRLDistributionPoints::from_der(&only_reasons).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(
        CRLDistributionPoints::from_der(&DER::sequence(&[&[0x30, 0x00]])).unwrap_err(),
        X509Error::InvalidExtension
    );
    let point = DistributionPoint { reasons: Some(ReasonFlags::KEY_COMPROMISE), ..Default::default() };
    assert_eq!(CRLDistributionPoints { points: vec![point] }.to_der().unwrap_err(), X509Error::InvalidExtension);
    // §5.2.5: the issuing distribution point is not the empty sequence.
    assert_eq!(IssuingDistributionPoint::from_der(&[0x30, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(IssuingDistributionPoint::default().to_der().unwrap_err(), X509Error::InvalidExtension);
    let indirect = IssuingDistributionPoint { indirect_crl: true, ..Default::default() };
    assert_eq!(indirect.to_der().unwrap(), [0x30, 0x03, 0x84, 0x01, 0xFF]);
    // §4.2.1.3: at least one bit of a key usage is set.
    assert_eq!(KeyUsage::from_der(&[0x03, 0x01, 0x00]).unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(KeyUsage { bits: 0 }.to_der().unwrap_err(), X509Error::InvalidExtension);
    // §5.3.2: an invalidity date is a GeneralizedTime as §4.1.2.5.2 defines it, without a fraction.
    assert_eq!(
        InvalidityDate::from_der(b"\x18\x0f20260201000000Z").unwrap(),
        InvalidityDate { time: time(2026, 2, 1) }
    );
    assert_eq!(InvalidityDate::from_der(b"\x18\x1120260201000000.5Z").unwrap_err(), X509Error::InvalidExtension);
    assert_eq!(InvalidityDate::from_der(b"\x17\x0d260201000000Z").unwrap_err(), X509Error::InvalidExtension);
    let fraction = ASN1Time::new(2026, 2, 1, 0, 0, 0, 500_000_000).unwrap();
    assert!(InvalidityDate { time: fraction }.to_der().is_err());
}

#[test]
fn extension_values_are_tagged_as_rfc_5280_appendix_a2_defines() {
    let common_name = DER::sequence(&[&DER::oid("2.5.4.3"), &DER::element(0x0C, b"x")]);
    // DistributionPointName is a CHOICE, explicitly tagged [0]; nameRelativeToCRLIssuer is [1] IMPLICIT SET OF.
    let rdn =
        RelativeDistinguishedName::new(&[AttributeTypeAndValue::from_text(NameAttribute::CommonName, "x").unwrap()])
            .unwrap();
    let point =
        DistributionPoint { name: Some(DistributionPointName::NameRelativeToCRLIssuer(rdn)), ..Default::default() };
    let points = CRLDistributionPoints { points: vec![point] };
    let expected = DER::sequence(&[&DER::sequence(&[&DER::element(0xA0, &DER::element(0xA1, &common_name))])]);
    assert_eq!(points.to_der().unwrap(), expected);
    assert_eq!(CRLDistributionPoints::from_der(&expected).unwrap(), points);
    // x400Address [3] and ediPartyName [5] keep the contents of their implicitly tagged SEQUENCE.
    let party = DER::element(0xA1, &DER::element(0x0C, b"party"));
    let names = SubjectAlternativeName {
        names: vec![
            GeneralName::EDIPartyName(Cow::Owned(party.clone())),
            GeneralName::X400Address(Cow::Owned(common_name.clone())),
        ],
    };
    let expected = DER::sequence(&[&DER::element(0xA5, &party), &DER::element(0xA3, &common_name)]);
    assert_eq!(names.to_der().unwrap(), expected);
    assert_eq!(SubjectAlternativeName::from_der(&expected).unwrap(), names);
    let broken = SubjectAlternativeName { names: vec![GeneralName::EDIPartyName(Cow::Borrowed(&[0xA1, 0x05]))] };
    assert!(broken.to_der().is_err());
    // GeneralSubtree: minimum [0] DEFAULT 0 and maximum [1], implicit INTEGERs.
    let subtree = GeneralSubtree { base: GeneralName::DNSName(Cow::Borrowed("a")), minimum: 1, maximum: Some(2) };
    let constraints = NameConstraints { permitted_subtrees: vec![subtree], excluded_subtrees: Vec::new() };
    let expected = DER::sequence(&[&DER::element(
        0xA0,
        &DER::sequence(&[&DER::element(0x82, b"a"), &[0x80, 0x01, 0x01], &[0x81, 0x01, 0x02]]),
    )]);
    assert_eq!(constraints.to_der().unwrap(), expected);
    assert_eq!(NameConstraints::from_der(&expected).unwrap(), constraints);
    // PrivateKeyUsagePeriod: [0] and [1] IMPLICIT GeneralizedTime, at least one.
    let period = umilib::auth::cert::x509::PrivateKeyUsagePeriod {
        not_before: Some(time(2026, 1, 1)),
        not_after: Some(time(2027, 1, 1)),
    };
    let expected = DER::sequence(&[&DER::element(0x80, b"20260101000000Z"), &DER::element(0x81, b"20270101000000Z")]);
    assert_eq!(period.to_der().unwrap(), expected);
    assert_eq!(umilib::auth::cert::x509::PrivateKeyUsagePeriod::from_der(&expected).unwrap(), period);
    assert!(umilib::auth::cert::x509::PrivateKeyUsagePeriod::from_der(&[0x30, 0x00]).is_err());
    // Policy qualifiers: a CPS URI as IA5String, a user notice as a SEQUENCE.
    let cps = PolicyQualifierInfo::cps("https://example.com/cps").unwrap();
    assert_eq!(cps.qualifier.as_ref(), DER::element(0x16, b"https://example.com/cps"));
    let notice = umilib::auth::cert::x509::UserNotice {
        notice_reference: None,
        explicit_text: Some(umilib::auth::cert::x509::DisplayText::UTF8String(Cow::Borrowed("text"))),
    };
    let qualifier = PolicyQualifierInfo::user_notice(&notice).unwrap();
    assert_eq!(qualifier.qualifier.as_ref(), DER::sequence(&[&DER::element(0x0C, b"text")]));
    assert_eq!(qualifier.notice().unwrap(), notice);
    // SubjectDirectoryAttributes: at least one attribute, each with at least one value.
    let attribute = umilib::auth::cert::x509::Attribute {
        oid: arcs("2.5.4.3"),
        values: vec![Cow::Owned(DER::element(0x0C, b"x"))],
    };
    let attributes = umilib::auth::cert::x509::SubjectDirectoryAttributes { attributes: vec![attribute.clone()] };
    let expected =
        DER::sequence(&[&DER::sequence(&[&DER::oid("2.5.4.3"), &DER::element(0x31, &DER::element(0x0C, b"x"))])]);
    assert_eq!(attributes.to_der().unwrap(), expected);
    assert_eq!(umilib::auth::cert::x509::SubjectDirectoryAttributes::from_der(&expected).unwrap(), attributes);
    assert!(umilib::auth::cert::x509::SubjectDirectoryAttributes::from_der(&[0x30, 0x00]).is_err());
    let no_value = umilib::auth::cert::x509::Attribute { values: Vec::new(), ..attribute };
    assert!(umilib::auth::cert::x509::SubjectDirectoryAttributes { attributes: vec![no_value] }.to_der().is_err());
    // DeltaCRLIndicator: a non-negative INTEGER.
    let delta = umilib::auth::cert::x509::DeltaCRLIndicator::from_u64(5);
    assert_eq!(delta.to_der().unwrap(), [0x02, 0x01, 0x05]);
    assert_eq!(umilib::auth::cert::x509::DeltaCRLIndicator::from_der(&[0x02, 0x01, 0x05]).unwrap(), delta);
    // CRL numbers of 20 octets (§5.2.3).
    let long = DER::element(0x02, &[0x7F; 20]);
    assert_eq!(CRLNumber::from_der(&long).unwrap().to_der().unwrap(), long);
}
