"""Tests of umilib.auth.cert.ocsp and umilib.auth.cert.path: OCSP against RFC 6960 and RFC 8954 with the
fixtures OpenSSL made, and path validation against RFC 5280 with OCSP responses as revocation sources."""

from pathlib import Path

import pytest

from umilib.auth.cert.key import HashAlgorithm, PrivateKey, PublicKey, SignatureAlgorithm
from umilib.auth.cert.ocsp import (
    BasicOCSPResponse,
    CertID,
    CertStatus,
    OCSPConfig,
    OCSPNonce,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
    OCSPStatusError,
    ResponseData,
    SingleResponse,
    TBSRequest,
)
from umilib.auth.cert.path import PathConfig, PathError, PathValidator, RevocationConfig, TrustAnchor
from umilib.auth.cert.x509 import Certificate, CRLReason, GeneralName, Name
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "auth" / "cert" / "ocsp" / "openssl"
# The fixtures were made on 2026-10-25; their responses are current until 2036-10-22.
JANUARY_2027 = 1798761600
JANUARY_2036 = 2082758400


def drbg():
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte")


def certificate(name: str) -> Certificate:
    return Certificate.from_der((FIXTURES / f"{name}.der").read_bytes())


def key(name: str) -> PrivateKey:
    return PrivateKey.from_pem((FIXTURES / f"{name}.key").read_text(encoding="utf-8"))


def response(name: str) -> OCSPResponse:
    return OCSPResponse.from_der((FIXTURES / f"response-{name}.der").read_bytes())


def cert_id(name: str, hash: HashAlgorithm) -> CertID:
    return CertID.new(certificate(name), certificate("root").public_key(), hash)


def test_requests_of_openssl():
    for name in ("nonce", "multiple", "signed"):
        data = (FIXTURES / f"request-{name}.der").read_bytes()
        assert OCSPRequest.from_der(data).to_der() == data
    nonce = OCSPRequest.from_der((FIXTURES / "request-nonce.der").read_bytes())
    assert [cert_id.serial_number for cert_id in nonce.cert_ids] == [0x10]
    assert nonce.cert_ids[0].matches(cert_id("good", HashAlgorithm.SHA1))
    assert nonce.cert_ids[0].identifies(certificate("good"), certificate("root").public_key())
    assert len(nonce.nonce) == 16 and not nonce.is_signed
    signed = OCSPRequest.from_der((FIXTURES / "request-signed.der").read_bytes())
    assert signed.requestor_name == GeneralName.directory_name(certificate("good").subject)
    assert signed.certificates == [certificate("good")]
    signed.verify(certificate("good").public_key())


def test_responses_of_openssl_are_checked_as_rfc_6960_requires():
    root, root_key = certificate("root").subject, certificate("root").public_key()
    config = OCSPConfig(JANUARY_2027)
    delegated = response("delegated")
    assert delegated.status == OCSPResponseStatus.Successful
    basic = delegated.basic()
    assert basic.responder_id.name() == certificate("responder").subject
    assert basic.certificates == [certificate("responder")]
    assert [single.cert_id.serial_number for single in basic.responses] == [0x10, 0x11, 0x12]
    invalidity = basic.responses[1].extensions.get("2.5.29.24")  # invalidityDate (RFC 5280 §5.3.2)
    assert invalidity is not None and not invalidity.critical and invalidity.value == b"\x18\x0f20260201000000Z"
    assert basic.verify(cert_id("good", HashAlgorithm.SHA256), root, root_key, config).status == CertStatus.good()
    revoked = basic.verify(cert_id("revoked", HashAlgorithm.SHA256), root, root_key, config).status
    assert revoked.kind == CertStatus.Kind.Revoked and revoked.reason == CRLReason.KeyCompromise
    assert basic.verify(cert_id("unknown", HashAlgorithm.SHA256), root, root_key, config).status == CertStatus.unknown()
    assert basic.signer(root, root_key, config) == certificate("responder").public_key()
    key_id = response("key-id").basic()
    assert key_id.responder_id.by_key and len(key_id.responder_id.data) == 20
    # The nonce of the request must be repeated (RFC 8954).
    request_nonce = OCSPRequest.from_der((FIXTURES / "request-nonce.der").read_bytes()).nonce
    direct = response("direct").basic()
    assert direct.nonce == request_nonce
    direct.verify(cert_id("good", HashAlgorithm.SHA1), root, root_key, OCSPConfig(JANUARY_2027, nonce=request_nonce))
    for failure, (name, config_of) in {
        "Nonce": ("direct", OCSPConfig(JANUARY_2027, nonce=b"\x00" * 16)),
        "Signer": ("unauthorized", config),
        "Time": ("direct", OCSPConfig(JANUARY_2036 + 400 * 86400)),
    }.items():
        hash = HashAlgorithm.SHA1 if name == "direct" else HashAlgorithm.SHA256
        with pytest.raises(OCSPStatusError) as error:
            response(name).basic().verify(cert_id("good", hash), root, root_key, config_of)
        assert error.value.name == failure
    with pytest.raises(OCSPStatusError) as error:
        response("other").basic().verify(cert_id("good", HashAlgorithm.SHA256), root, root_key, config)
    assert error.value.name == "Signer"
    with pytest.raises(OCSPStatusError) as error:
        delegated.basic().verify(cert_id("good", HashAlgorithm.SHA1), root, root_key, config)
    assert error.value.name == "NotFound"


def test_requests_and_responses_made_here():
    root_key = certificate("root").public_key()
    nonce = OCSPNonce.random(drbg())
    assert len(nonce) == 32
    tbs = TBSRequest([cert_id("good", HashAlgorithm.SHA256)], GeneralName.directory_name(certificate("good").subject), nonce)
    algorithm = SignatureAlgorithm.ecdsa(HashAlgorithm.SHA256)
    request = OCSPRequest.sign(tbs, key("good"), algorithm, [certificate("good")], drbg())
    assert OCSPRequest.from_der(request.to_der()) == request
    request.verify(certificate("good").public_key())
    assert OCSPRequest.new(tbs).nonce == nonce
    data = ResponseData.by_key(certificate("responder").public_key(), JANUARY_2027)
    data.push(SingleResponse(cert_id("good", HashAlgorithm.SHA256), CertStatus.good(), JANUARY_2027, JANUARY_2027 + 7 * 86400))
    data.push(SingleResponse(cert_id("revoked", HashAlgorithm.SHA256), CertStatus.revoked(JANUARY_2027 - 86400, CRLReason.Superseded), JANUARY_2027))
    data.set_nonce(nonce)
    basic = data.sign(key("responder"), algorithm, [certificate("responder")], drbg())
    made = OCSPResponse(OCSPResponseStatus.Successful, basic)
    assert OCSPResponse.from_der(made.to_der()) == made
    config = OCSPConfig(JANUARY_2027, nonce=nonce)
    root = certificate("root").subject
    single = made.basic().verify(cert_id("revoked", HashAlgorithm.SHA256), root, root_key, config)
    assert single.status == CertStatus.revoked(JANUARY_2027 - 86400, CRLReason.Superseded)
    assert single.this_update == JANUARY_2027 and single.next_update is None
    # A response that is not successful has no basic response (RFC 6960 §4.2.1).
    try_later = OCSPResponse(OCSPResponseStatus.TryLater)
    assert try_later.to_der() == b"\x30\x03\x0a\x01\x03"
    with pytest.raises(OCSPStatusError) as error:
        try_later.basic()
    assert error.value.name == "Status"
    with pytest.raises(OCSPStatusError):
        OCSPResponse(OCSPResponseStatus.Successful)
    # SHA-1 signatures are refused unless accepted.
    sha1 = ResponseData.by_name(root, JANUARY_2027)
    sha1.push(SingleResponse(cert_id("good", HashAlgorithm.SHA256), CertStatus.good(), JANUARY_2027))
    sha1_basic = sha1.sign(key("root"), SignatureAlgorithm.ecdsa(HashAlgorithm.SHA1), None, drbg())
    with pytest.raises(OCSPStatusError) as error:
        sha1_basic.verify(cert_id("good", HashAlgorithm.SHA256), root, root_key, OCSPConfig(JANUARY_2027))
    assert error.value.name == "Algorithm"
    sha1_basic.verify(cert_id("good", HashAlgorithm.SHA256), root, root_key, OCSPConfig(JANUARY_2027, accept_sha1=True))
    assert BasicOCSPResponse.from_der(sha1_basic.to_der()) == sha1_basic


def test_responses_are_revocation_sources_of_path_validation():
    anchors = [TrustAnchor.from_certificate(certificate("root"))]
    config = PathConfig(JANUARY_2027, revocation=RevocationConfig.REQUIRED)
    validator = PathValidator(config, anchors).with_sources([response("delegated")])
    path = validator.validate(certificate("good"))
    assert path.certificates == [certificate("good")]
    assert path.anchor is anchors[0]
    assert path.policies == []
    with pytest.raises(PathError) as error:
        validator.validate(certificate("revoked"))
    assert error.value.name == "Revoked" and error.value.index == 0 and error.value.revocation_reason == CRLReason.KeyCompromise
    with pytest.raises(PathError) as error:
        validator.validate(certificate("unknown"))
    assert error.value.name == "RevocationUnknown"
    with pytest.raises(PathError) as error:
        PathValidator(config, anchors, sources=[response("unauthorized")]).validate(certificate("good"))
    assert error.value.name == "InvalidResponse"
    # A basic response is a source too, and a response that is not successful says nothing.
    PathValidator(config, anchors, sources=[response("delegated").basic()]).validate(certificate("good"))
    with pytest.raises(PathError) as error:
        PathValidator(config, anchors, sources=[OCSPResponse(OCSPResponseStatus.TryLater)]).validate(certificate("good"))
    assert error.value.name == "RevocationUnknown"
    # Without revocation checking, the target's own failures remain: here the validity period.
    with pytest.raises(PathError) as error:
        PathValidator(PathConfig(JANUARY_2036 + 86400), anchors).validate(certificate("good"))
    assert error.value.name == "Validity"
    # No path to an anchor of another CA.
    with pytest.raises(PathError) as error:
        PathValidator(PathConfig(JANUARY_2027), [TrustAnchor.from_certificate(certificate("other-root"))]).validate(certificate("good"))
    assert error.value.name == "NoPath"
    assert TrustAnchor.new(Name.from_der(certificate("root").subject.to_der()), certificate("root").public_key()).name == certificate("root").subject
    assert isinstance(anchors[0].public_key, PublicKey)
