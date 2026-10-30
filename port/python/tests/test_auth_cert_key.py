"""Tests of umilib.auth.cert.key: keys, signatures and their encodings."""

import pytest

from umilib.auth.cert.key import (
    HashAlgorithm,
    KeyAlgorithm,
    KeyStatusError,
    MLDSAParameterSet,
    MLKEMParameterSet,
    NamedCurve,
    PBES2Config,
    PrivateKey,
    PublicKey,
    SignatureAlgorithm,
    SLHDSAParameterSet,
)
from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256


def drbg():
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte")


@pytest.mark.parametrize(
    ("algorithm", "signature"),
    [
        (lambda: KeyAlgorithm.ec(NamedCurve.P256), lambda: SignatureAlgorithm.ecdsa(HashAlgorithm.SHA256)),
        (lambda: KeyAlgorithm.ec(NamedCurve.P384), lambda: SignatureAlgorithm.ecdsa(HashAlgorithm.SHA3_384)),
        (KeyAlgorithm.ed25519, SignatureAlgorithm.ed25519),
        (KeyAlgorithm.ed448, SignatureAlgorithm.ed448),
        (lambda: KeyAlgorithm.mldsa(MLDSAParameterSet.MLDSA65), lambda: SignatureAlgorithm.mldsa(MLDSAParameterSet.MLDSA65)),
        (lambda: KeyAlgorithm.slhdsa(SLHDSAParameterSet.SHA2_128f), lambda: SignatureAlgorithm.slhdsa(SLHDSAParameterSet.SHA2_128f)),
    ],
)
def test_keys_sign_and_verify(algorithm, signature):
    random = drbg()
    key = PrivateKey.generate(algorithm(), random)
    public_key = key.public_key()
    assert key.algorithm == algorithm()
    sig = key.sign(signature(), b"message", random)
    public_key.verify(signature(), b"message", sig)
    with pytest.raises(KeyStatusError) as error:
        public_key.verify(signature(), b"messagf", sig)
    assert error.value.name == "InvalidSignature"
    assert PublicKey.from_der(public_key.to_der()) == public_key
    assert PublicKey.from_pem(public_key.to_pem()) == public_key
    assert PrivateKey.from_pkcs8_der(key.to_pkcs8_der()).public_key() == public_key
    assert PrivateKey.from_pem(key.to_pem()).public_key() == public_key
    assert SignatureAlgorithm.from_der(signature().to_der()).to_der() == signature().to_der()


def test_rsa_and_algorithm_rules():
    random = drbg()
    key = PrivateKey.generate_rsa(KeyAlgorithm.rsa(), 2048, random)
    pss = SignatureAlgorithm.rsa_pss(HashAlgorithm.SHA256)
    key.public_key().verify(pss, b"m", key.sign(pss, b"m", random))
    pkcs1 = SignatureAlgorithm.rsa_pkcs1v15(HashAlgorithm.SHA512)
    key.public_key().verify(pkcs1, b"m", key.sign(pkcs1, b"m", random))
    restricted = KeyAlgorithm.rsa_pss(pss)
    assert restricted.signs(pss)
    assert not restricted.signs(pkcs1)
    assert not KeyAlgorithm.mlkem(MLKEMParameterSet.MLKEM768).signs(pss)
    with pytest.raises(KeyStatusError) as error:
        key.sign(SignatureAlgorithm.ed25519(), b"m", random)
    assert error.value.name == "Mismatch"
    with pytest.raises(KeyStatusError) as error:
        PublicKey.from_der(b"\x30\x00")
    assert error.value.name == "Encoding"


def test_encrypted_private_keys():
    random = drbg()
    key = PrivateKey.generate(KeyAlgorithm.x25519(), random)
    config = PBES2Config(iterations=1000)
    der = key.to_encrypted_pkcs8_der(b"password", random, config)
    assert PrivateKey.from_encrypted_pkcs8_der(der, b"password", config).public_key() == key.public_key()
    with pytest.raises(KeyStatusError) as error:
        PrivateKey.from_encrypted_pkcs8_der(der, b"wrong", config)
    assert error.value.name == "Decryption"
    with pytest.raises(KeyStatusError) as error:
        PrivateKey.from_encrypted_pkcs8_der(der, b"password", PBES2Config(maximum_iterations=10))
    assert error.value.name == "Parameters"


def test_ber_keys_and_limits():
    key = PrivateKey.generate(KeyAlgorithm.ed25519(), drbg())
    der = key.to_pkcs8_der()
    ber = b"\x30\x80" + der[2:] + b"\x00\x00"
    with pytest.raises(KeyStatusError):
        PrivateKey.from_pkcs8_der(ber)
    assert PrivateKey.from_pkcs8_ber(ber).public_key() == key.public_key()
    # RFC 8018 §4: fewer than 1000 iterations are not written.
    with pytest.raises(KeyStatusError) as error:
        key.to_encrypted_pkcs8_der(b"p", drbg(), PBES2Config(iterations=999))
    assert error.value.name == "Parameters"
