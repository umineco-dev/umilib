"""Tests of umilib.auth.cert.x509 and umilib.auth.cert.csr: certificates, CRLs and requests, against RFC 5280,
RFC 4514, RFC 2986 and the fixtures OpenSSL made."""

from pathlib import Path

import pytest

from umilib.auth.cert.csr import CertificationRequest, CertificationRequestInfo
from umilib.auth.cert.key import HashAlgorithm, KeyStatusError, PrivateKey, SignatureAlgorithm
from umilib.auth.cert.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CertificateList,
    CRLNumber,
    CRLReason,
    ExtendedKeyUsage,
    Extension,
    Extensions,
    GeneralName,
    Integer,
    KeyUsage,
    Name,
    NameAttribute,
    RevokedCertificate,
    SerialNumber,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    TBSCertificate,
    TBSCertList,
    Version,
    X509StatusError,
)
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "auth" / "cert" / "x509" / "openssl"
JANUARY_2026 = 1767225600
JANUARY_2036 = 2082758400


def drbg():
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte")


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def key(name: str) -> PrivateKey:
    return PrivateKey.from_pem((FIXTURES / f"{name}.key").read_text())


def test_integers_are_minimal_twos_complement():
    # X.690 §8.3: the fewest octets.
    assert Integer.encode(0) == b"\x00"
    assert Integer.encode(127) == b"\x7f"
    assert Integer.encode(128) == b"\x00\x80"
    assert Integer.encode(-128) == b"\x80"
    assert Integer.encode(-129) == b"\xff\x7f"
    for value in (0, 1, 255, 256, -1, 2**159 - 1):
        assert Integer.decode(Integer.encode(value)) == value


def test_names_and_rfc4514():
    name = Name.from_attributes([(NameAttribute.DomainComponent, "net"), (NameAttribute.DomainComponent, "example"), (NameAttribute.UserID, "jsmith")])
    assert name.to_rfc4514() == "UID=jsmith,DC=example,DC=net"
    assert str(Name.from_attributes([(NameAttribute.CommonName, 'James "Jim" Smith, III')])) == 'CN=James \\"Jim\\" Smith\\, III'
    assert Name.from_der(name.to_der()) == name
    assert Name.empty().to_der() == b"\x30\x00"
    with pytest.raises(X509StatusError) as error:
        Name.empty().append(NameAttribute.Country, "JPN")
    assert error.value.name == "InvalidName"


def test_certificates_of_openssl():
    root = Certificate.from_der(fixture("root.der"))
    intermediate = Certificate.from_der(fixture("intermediate.der"))
    leaf = Certificate.from_der(fixture("leaf.der"))
    root.verify(root.public_key())
    intermediate.verify(root.public_key())
    leaf.verify(intermediate.public_key())
    with pytest.raises(KeyStatusError):
        leaf.verify(root.public_key())
    assert root.is_self_issued() and not leaf.is_self_issued()
    assert root.version == Version.V3
    assert root.serial_number == 1
    assert intermediate.serial_number == 0x0123456789ABCDEF0123456789ABCDEF01234567
    assert root.subject.to_rfc4514() == "CN=umilib Root CA,O=umilib,C=JP"
    assert intermediate.issuer == root.subject
    assert root.validity == (JANUARY_2026, JANUARY_2036)
    assert SignatureAlgorithm.from_der(root.signature_algorithm).to_der() == SignatureAlgorithm.ecdsa(HashAlgorithm.SHA256).to_der()
    extensions = intermediate.extensions
    assert extensions.typed(BasicConstraints) == BasicConstraints(ca=True, path_length=0)
    assert extensions.get(BasicConstraints.OID).critical
    assert extensions.typed(KeyUsage) == KeyUsage.DIGITAL_SIGNATURE | KeyUsage.KEY_CERT_SIGN | KeyUsage.CRL_SIGN
    assert extensions.typed(SubjectKeyIdentifier) == SubjectKeyIdentifier.from_public_key(intermediate.public_key())
    assert extensions.typed(AuthorityKeyIdentifier).key_identifier == root.extensions.typed(SubjectKeyIdentifier).key_identifier
    names = leaf.extensions.typed(SubjectAlternativeName).names
    assert names[0] == GeneralName.dns_name("www.example.com")
    assert names[2] == GeneralName.ip_address(bytes([192, 0, 2, 1]))
    assert names[6].kind == GeneralName.Kind.DirectoryName
    assert Name.from_der(names[6].data).to_rfc4514() == "CN=Directory Name,O=umilib,C=JP"
    assert names[7] == GeneralName.registered_id("1.2.3.4")
    assert leaf.extensions.typed(ExtendedKeyUsage).purposes == (ExtendedKeyUsage.SERVER_AUTH, ExtendedKeyUsage.CLIENT_AUTH)
    assert leaf.extensions.typed(BasicConstraints) == BasicConstraints()
    # Written back to the same bytes, in DER and PEM, alone and as a chain.
    assert leaf.to_der() == fixture("leaf.der")
    assert Certificate.from_pem(leaf.to_pem()) == leaf
    chain = Certificate.from_pem_all(leaf.to_pem() + intermediate.to_pem() + root.to_pem())
    assert chain == [leaf, intermediate, root]
    with pytest.raises(X509StatusError) as error:
        Certificate.from_pem((FIXTURES / "root.key").read_text())
    assert error.value.name == "PEMLabel"


def test_crls_of_openssl():
    intermediate = Certificate.from_der(fixture("intermediate.der"))
    crl = CertificateList.from_der(fixture("intermediate.crl"))
    crl.verify(intermediate.public_key())
    assert crl.version == Version.V2
    assert crl.issuer == intermediate.subject
    assert crl.next_update - crl.this_update == 30 * 86400
    assert crl.extensions.typed(CRLNumber) == CRLNumber(0x1001)
    entries = crl.revoked_certificates
    assert [entry.serial_number for entry in entries] == [2, 3]
    assert crl.find(2).extensions.typed(CRLReason) == CRLReason.KeyCompromise
    assert crl.find(3).extensions.typed(CRLReason) == CRLReason.CertificateHold
    assert crl.find(4) is None
    assert CertificateList.from_pem(crl.to_pem()).to_der() == fixture("intermediate.crl")


def test_built_chain_crl_and_request():
    random = drbg()
    root_key, leaf_key = key("ed25519"), key("leaf")
    eddsa = SignatureAlgorithm.ed25519()
    root_name = Name.from_attributes([(NameAttribute.Country, "JP"), (NameAttribute.CommonName, "Python Root")])
    extensions = Extensions()
    extensions.push(Extension.new(BasicConstraints(ca=True), True))
    extensions.push(Extension.new(KeyUsage.KEY_CERT_SIGN | KeyUsage.CRL_SIGN, True))
    extensions.push(Extension.new(SubjectKeyIdentifier.from_public_key(root_key.public_key()), False))
    with pytest.raises(X509StatusError) as error:
        extensions.push(Extension.new(BasicConstraints(), True))
    assert error.value.name == "DuplicateExtension"
    tbs = TBSCertificate(Version.V3, SerialNumber.random(random), eddsa, root_name, JANUARY_2026, JANUARY_2036, root_name, root_key.public_key(), extensions)
    root = tbs.sign(root_key, random)
    root.verify(root_key.public_key())
    assert Certificate.from_der(root.to_der()).extensions == extensions
    # §4.1.2.2: a positive serial number; §4.1.2.1: extensions need v3.
    with pytest.raises(X509StatusError) as error:
        TBSCertificate(Version.V3, 0, eddsa, root_name, JANUARY_2026, JANUARY_2036, root_name, root_key.public_key(), extensions).check()
    assert error.value.name == "InvalidSerialNumber"
    with pytest.raises(X509StatusError) as error:
        TBSCertificate(Version.V1, 1, eddsa, root_name, JANUARY_2026, JANUARY_2036, root_name, root_key.public_key(), extensions).check()
    assert error.value.name == "Version"

    leaf_extensions = Extensions()
    leaf_extensions.push(Extension.new(SubjectAlternativeName((GeneralName.dns_name("python.example.com"),)), False))
    leaf_extensions.push(Extension.new(AuthorityKeyIdentifier(SubjectKeyIdentifier.from_public_key(root_key.public_key()).key_identifier), False))
    leaf_extensions.push(Extension.new(ExtendedKeyUsage((ExtendedKeyUsage.SERVER_AUTH,)), False))
    leaf_name = Name.from_attributes([(NameAttribute.CommonName, "python.example.com")])
    leaf = TBSCertificate(Version.V3, 2, eddsa, root_name, JANUARY_2026, JANUARY_2036, leaf_name, leaf_key.public_key(), leaf_extensions).sign(root_key, random)
    leaf.verify(root.public_key())
    assert leaf.extensions.typed(SubjectAlternativeName).names == (GeneralName.dns_name("python.example.com"),)

    entry_extensions = Extensions([Extension.new(CRLReason.Superseded, False)])
    crl = TBSCertList(Version.V2, eddsa, root_name, JANUARY_2026, JANUARY_2036, [RevokedCertificate(2, JANUARY_2026, entry_extensions)], Extensions([Extension.new(CRLNumber(1), False)])).sign(root_key, random)
    crl.verify(root.public_key())
    assert crl.find(leaf.serial_number).extensions.typed(CRLReason) == CRLReason.Superseded

    info = CertificationRequestInfo(leaf_name, leaf_key.public_key(), leaf_extensions)
    request = info.sign(leaf_key, SignatureAlgorithm.ecdsa(HashAlgorithm.SHA256), random)
    request.verify()
    assert CertificationRequest.from_pem(request.to_pem()) == request
    assert request.extensions == leaf_extensions
    assert request.subject == leaf_name
    with pytest.raises(KeyStatusError) as error:
        info.sign(root_key, eddsa, random)
    assert error.value.name == "Mismatch"


def test_requests_of_openssl():
    request = CertificationRequest.from_der(fixture("leaf.csr"))
    request.verify()
    assert request.public_key() == key("leaf").public_key()
    assert request.subject.to_rfc4514() == "CN=csr.example.com,O=umilib,C=JP"
    oids = [attribute.oid for attribute in request.attributes]
    assert CertificationRequestInfo.CHALLENGE_PASSWORD in oids and CertificationRequestInfo.EXTENSION_REQUEST in oids
    assert request.extensions.typed(SubjectAlternativeName).names == (GeneralName.dns_name("csr.example.com"),)
    assert request.extensions.typed(KeyUsage) == KeyUsage.DIGITAL_SIGNATURE
    assert request.to_der() == fixture("leaf.csr")
    bare = CertificationRequest.from_der(fixture("bare.csr"))
    bare.verify()
    assert bare.attributes == [] and bare.extensions.is_empty()


def test_extension_values_round_trip_over_their_whole_range():
    # RFC 5280 §5.2.3: CRL numbers of up to 20 octets.
    for number in (0, 1, 2**64, 2**159 - 1):
        assert CRLNumber.from_der(CRLNumber(number).to_der()) == CRLNumber(number)
    # §4.2.1.1: the key identifier, and the issuer with the serial number.
    value = Certificate.from_der(fixture("intermediate.der")).extensions.get(AuthorityKeyIdentifier.OID).value
    identifier = AuthorityKeyIdentifier.from_der(value)
    root = Certificate.from_der(fixture("root.der"))
    assert identifier.authority_cert_issuer == (GeneralName.directory_name(root.subject),)
    assert identifier.authority_cert_serial_number == 1
    assert identifier.to_der() == value
    # §4.2.1.6: every textual and binary kind of general name.
    names = (
        GeneralName.rfc822_name("user@example.com"),
        GeneralName.uri("https://example.com/"),
        GeneralName.ip_address(bytes(16)),
        GeneralName.registered_id("1.2.3.4"),
        GeneralName.directory_name(root.subject),
    )
    assert SubjectAlternativeName.from_der(SubjectAlternativeName(names).to_der()).names == names
    with pytest.raises(X509StatusError) as error:
        SubjectAlternativeName((GeneralName.ip_address(bytes(5)),)).to_der()
    assert error.value.name == "InvalidName"
    # §4.2.1.3 and §4.2.1.9: at least one key usage bit; the fields of basic constraints.
    with pytest.raises(X509StatusError) as error:
        KeyUsage(0).to_der()
    assert error.value.name == "InvalidExtension"
    assert BasicConstraints.from_der(BasicConstraints(True, 3).to_der()) == BasicConstraints(True, 3)
