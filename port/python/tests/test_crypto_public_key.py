"""Tests of the public-key cryptography of umilib.crypto and umilib.math.pairing against Project
Wycheproof, the RFCs and the drafts in tests/vectors, and of the round trips of the schemes without
published vectors on the curves C names."""

import pytest

from umilib.crypto import CryptoError, PrivateKey, PublicKey
from umilib.crypto.aes import AES128, AES256
from umilib.crypto.chacha20poly1305 import ChaCha20Poly1305
from umilib.crypto.curve.brainpool.p256r1 import BrainpoolP256r1
from umilib.crypto.curve.curve25519 import Curve25519, Edwards25519
from umilib.crypto.curve.curve448 import Curve448
from umilib.crypto.curve.gost import GOST256A
from umilib.crypto.curve.p256 import P256
from umilib.crypto.curve.p384 import P384
from umilib.crypto.curve.p521 import P521
from umilib.crypto.curve.secp256k1 import Secp256k1
from umilib.crypto.curve.sm2 import SM2
from umilib.crypto.dh import DH, FFDHE2048
from umilib.crypto.dragonfly import DragonflyConfig, DragonflyPeer
from umilib.crypto.dsa import DSA, DSAParameters, DSASignature, DSAVerifyingKey
from umilib.crypto.eccsi import ECCSI, ECCSIKMS, ECCSIUserKey
from umilib.crypto.ecdh import ECDH, X448, X25519, XDH
from umilib.crypto.ecdsa import ECDSA, ECDSASignature
from umilib.crypto.eddsa import Ed448, Ed25519, EdDSA
from umilib.crypto.gostr3410 import GOSTR3410
from umilib.crypto.hpke import DHKEM, HPKE, HPKEExportOnly
from umilib.crypto.ibs.chacheon import ChaCheon
from umilib.crypto.ibs.hess import Hess
from umilib.crypto.ibs.sm9 import SM9
from umilib.crypto.mode.gcm import GCM
from umilib.crypto.random import HMACDRBG
from umilib.crypto.rsa import RSAOAEP, RSAPKCS1v15, RSAPSS, RSAPrivateKey, RSAPublicKey
from umilib.crypto.sm2 import SM2DSA, SM2KEP, SM2PKE, SM2CiphertextOrder, SM2Role
from umilib.crypto.sm4 import SM4
from umilib.crypto.sm9 import (
    SM9KEM,
    SM9KEP,
    SM9PKE,
    SM9BlockCipher,
    SM9EncryptMasterKey,
    SM9EncryptUserKey,
    SM9Role,
    SM9StreamCipher,
)
from umilib.crypto.srp import SRP, SRP1024, SRP2048, SRPClient, SRPServer
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA224, SHA256, SHA384, SHA512
from umilib.hash.sha.v3 import SHA3_256, SHA3_512
from umilib.hash.sm3 import SM3
from umilib.hash.streebog import Streebog256
from umilib.math.pairing import BLS12381, BN254, BN462, SM9BN256, Pairing
from vectors import GMT, ROOT, Wycheproof

HASHES = {
    "SHA-1": SHA1,
    "SHA-224": SHA224,
    "SHA-256": SHA256,
    "SHA-384": SHA384,
    "SHA-512": SHA512,
    "SHA3-256": SHA3_256,
    "SHA3-512": SHA3_512,
}
CURVES = {
    "secp256r1": P256,
    "secp384r1": P384,
    "secp521r1": P521,
    "secp256k1": Secp256k1,
    "brainpoolP256r1": BrainpoolP256r1,
}


def generator(label: bytes = b"public key") -> HMACDRBG:
    return HMACDRBG[SHA256](bytes([7]) * 32, bytes([8]) * 16, label)


class Outcome:
    """The expectations of a Wycheproof test on an outcome."""

    @staticmethod
    def check(test: dict, accepted: bool, label: str) -> None:
        if test["result"] == "valid":
            assert accepted, f"{label}: refused"
        elif test["result"] == "invalid":
            assert not accepted, f"{label}: accepted"


class Appendix:
    """The values of the appendices of the specifications."""

    @staticmethod
    def rfc6507(name: str) -> bytes:
        """The value "name := 0x ...;" of RFC 6507 appendix A, or for a hash the value after "=", across lines."""
        text = (ROOT / "crypto/eccsi/rfc6507.txt").read_text()
        section = text[text.index("\nAppendix A.  Test Data") :]
        value = section[section.index(f"\n      {name} ") + 1 :]
        if "hash(" in value[: value.index("\n")]:
            value = value[value.index("),") :]
        start = value.index("0x") + 2
        digits = "".join(value[start : value.index(";", start)].split())
        return bytes.fromhex(digits if len(digits) % 2 == 0 else "0" + digits)

    @staticmethod
    def rfc5054(name: str) -> bytes:
        """The value after "name =" in RFC 5054 appendix B, in groups of hexadecimal digits."""
        text = (ROOT / "crypto/srp/rfc5054.txt").read_text()
        lines = [line.strip() for line in text[text.index("\nAppendix B.  SRP Test Vectors") : text.index("\nAppendix C.")].splitlines()]
        index = next(position for position, line in enumerate(lines) if line.startswith(f"{name} ="))
        digits = "".join(lines[index][len(name) + 2 :].split())
        following = lines[index + 1 :]
        if not digits:
            while following and not following[0]:
                following = following[1:]
        for line in following:
            if not line or not all(all(c in "0123456789abcdefABCDEF" for c in word) for word in line.split()):
                break
            digits += "".join(line.split())
        return bytes.fromhex(digits)

    @staticmethod
    def pairing(name: str) -> dict[str, bytes]:
        """The inputs and e_0 to e_11 of the curve ``name`` in appendix B of the pairing draft."""
        text = (ROOT / "math/pairing/draft-irtf-cfrg-pairing-friendly-curves-11.txt").read_text()
        appendix = text[text.index("\nAppendix B.  Test Vectors") :]
        start = appendix.index(f"\n   {name}:")
        end = appendix.find(":\n\n   Input x value", start + 10)
        lines = [line.strip() for line in appendix[start : end if end > 0 else len(appendix)].splitlines()]
        values: dict[str, bytes] = {}
        for index, line in enumerate(lines):
            if not line.endswith(":") or line == f"{name}:":
                continue
            digits = ""
            for following in lines[index + 1 :]:
                following = following.removeprefix("0x")
                if not following or not all(c in "0123456789abcdef" for c in following):
                    if digits:
                        break
                    continue
                digits += following
            values[line[:-1]] = bytes.fromhex(digits if len(digits) % 2 == 0 else "0" + digits)
        return values


class Setups:
    """The setups of RFC 9180 appendix A: their fields, encryptions and exported values."""

    @staticmethod
    def all() -> list[dict]:
        text = (ROOT / "crypto/hpke/rfc9180.txt").read_text()
        text = text[text.index("\nA.1.  DHKEM(X25519") : text.index("\nAcknowledgements")]
        setups: list[dict] = []
        part, last = "fields", None
        for line in text.splitlines():
            trimmed = line.strip()
            if not trimmed:
                if part != "fields":
                    last = None
                continue
            if line.startswith("A."):
                if trimmed.endswith("Setup Information"):
                    setups.append({"name": trimmed, "fields": {}, "encryptions": [], "exports": []})
                    part = "fields"
                elif trimmed.endswith("Encryptions"):
                    part = "encryptions"
                elif trimmed.endswith("Exported Values"):
                    part = "exports"
                last = None
                continue
            if not setups:
                continue
            setup = setups[-1]
            if part == "fields":
                target = setup["fields"]
            else:
                if trimmed.startswith("sequence number:") or trimmed.startswith("exporter_context:"):
                    setup[part].append({})
                target = setup[part][-1]
            if ":" in trimmed:
                name, value = trimmed.split(":", 1)
                target[name] = value.strip()
                last = name
            elif last is not None:
                target[last] += trimmed
        return setups


def test_ecdh_follows_the_wycheproof_vectors():
    # The C ABI runs every file (tests/ffi); one checks the classes of Python.
    for curve, file in ((P256, "ecdh_secp256r1_ecpoint_test.json"),):
        scheme = ECDH[curve]
        for _, test in Wycheproof.tests(f"crypto/ecdh/{file}"):
            label = f"{file} {test['tcId']}"
            private = Wycheproof.bytes(test, "private").lstrip(b"\0").rjust(scheme.PRIVATE_KEY_SIZE, b"\0")
            shared = bytearray(scheme.SHARED_SECRET_SIZE)
            try:
                scheme.agree(scheme.private_key_from_bytes(private), scheme.public_key_from_bytes(Wycheproof.bytes(test, "public")), shared)
                accepted = True
            except CryptoError:
                accepted = False
            Outcome.check(test, accepted, label)
            if accepted and test["result"] != "invalid":
                assert bytes(shared) == Wycheproof.bytes(test, "shared"), label


def test_xdh_follows_rfc7748_and_the_wycheproof_vectors():
    alice = X25519.private_key_from_bytes(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    bob_public = X25519.public_key_from_bytes(bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
    assert X25519.public_key(alice).to_bytes().hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    shared = bytearray(32)
    X25519.agree(alice, bob_public, shared)
    assert shared.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert XDH[Curve25519] is X25519 and XDH[Curve448] is X448
    for scheme, file in ((X25519, "x25519_test.json"), (X448, "x448_test.json")):
        for _, test in Wycheproof.tests(f"crypto/ecdh/{file}"):
            label = f"{file} {test['tcId']}"
            shared = bytearray(scheme.SHARED_SECRET_SIZE)
            try:
                scheme.agree(
                    scheme.private_key_from_bytes(Wycheproof.bytes(test, "private")),
                    scheme.public_key_from_bytes(Wycheproof.bytes(test, "public")),
                    shared,
                )
                accepted = True
            except CryptoError:
                accepted = False
            Outcome.check(test, accepted, label)
            if accepted and test["result"] != "invalid":
                assert bytes(shared) == Wycheproof.bytes(test, "shared"), label


def test_key_agreements_round_trip_and_hold_their_keys():
    random = generator()
    for scheme in (ECDH[P256], ECDH[P384], ECDH[P521], X25519, X448, DH[FFDHE2048]):
        a, b = scheme.generate(random), scheme.generate(random)
        public_a, public_b = scheme.public_key(a), scheme.public_key(b)
        shared_a, shared_b = bytearray(scheme.SHARED_SECRET_SIZE), bytearray(scheme.SHARED_SECRET_SIZE)
        scheme.agree(a, public_b, shared_a)
        scheme.agree(b, public_a, shared_b)
        assert shared_a == shared_b
        encoded = bytearray(scheme.PRIVATE_KEY_SIZE)
        scheme.write_private_key(a, encoded)
        assert scheme.private_key_from_bytes(encoded) == a
        assert scheme.public_key_from_bytes(public_a.to_bytes()) == public_a
        assert repr(a) == f"PrivateKey({scheme.__name__}, ..)"
        with pytest.raises(TypeError):
            a.to_bytes()
        with pytest.raises(CryptoError) as error:
            scheme.public_key_from_bytes(public_a.to_bytes()[:-1])
        assert error.value.name == "InvalidKey"
    # Keys of one scheme are not keys of another.
    with pytest.raises(TypeError):
        ECDH[P384].public_key(ECDH[P256].generate(random))
    assert isinstance(ECDH[P256].generate(random), PrivateKey)
    assert ECDH[P256] is ECDH[P256]
    with pytest.raises(TypeError):
        ECDH[Curve25519]


def test_ecdsa_follows_the_wycheproof_vectors():
    files = (
        "ecdsa_secp256r1_sha256_p1363_test.json",
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp256k1_sha256_test.json",
        "ecdsa_brainpoolP256r1_sha3_256_test.json",
        "ecdsa_secp384r1_sha3_512_test.json",
    )
    for file in files:
        for group, test in Wycheproof.tests(f"crypto/ecdsa/{file}"):
            label = f"{file} {test['tcId']}"
            curve = CURVES[group["publicKey"]["curve"]]
            scheme = ECDSA[curve, HASHES[group["sha"]]]
            key = scheme.verifying_key_from_bytes(bytes.fromhex(group["publicKey"]["uncompressed"]))
            try:
                if "_p1363_" in file:
                    signature = Wycheproof.bytes(test, "sig")
                else:
                    parsed = ECDSASignature[curve].from_der(Wycheproof.bytes(test, "sig"))
                    assert parsed.to_der() == Wycheproof.bytes(test, "sig"), label
                    signature = parsed.to_bytes()
                scheme.verify(key, Wycheproof.bytes(test, "msg"), signature)
                accepted = True
            except CryptoError:
                accepted = False
            Outcome.check(test, accepted, label)


def test_signature_schemes_round_trip():
    random = generator(b"signature")
    for scheme in (ECDSA[P256, SHA256], Ed25519, Ed448, GOSTR3410[GOST256A, Streebog256], SM2DSA[SM2, SM3]):
        key = scheme.generate(random)
        verifying = scheme.verifying_key(key)
        signature = scheme.sign(key, b"message")
        assert len(signature) == scheme.SIGNATURE_SIZE
        # The schemes sign deterministically.
        assert scheme.sign(key, b"message") == signature
        scheme.verify(verifying, b"message", signature)
        with pytest.raises(CryptoError) as error:
            scheme.verify(verifying, b"massage", signature)
        assert error.value.name == "InvalidSignature"
        assert scheme.verifying_key_from_bytes(verifying.to_bytes()) == verifying
        encoded = bytearray(scheme.SIGNING_KEY_SIZE)
        scheme.write_signing_key(key, encoded)
        assert scheme.verifying_key(scheme.signing_key_from_bytes(encoded)) == verifying
    sm2 = SM2DSA[SM2, SM3]
    key = sm2.generate(random)
    signature = sm2.sign_with_identity(key, b"alice@example.com", b"message")
    sm2.verify_with_identity(sm2.verifying_key(key), b"alice@example.com", b"message", signature)
    with pytest.raises(CryptoError):
        sm2.verify(sm2.verifying_key(key), b"message", signature)


def test_eddsa_follows_rfc8032_and_the_wycheproof_vectors():
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    key = Ed25519.signing_key_from_bytes(secret)
    assert Ed25519.verifying_key(key).to_bytes().hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert Ed25519.sign(key, b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert EdDSA[Edwards25519] is Ed25519
    for scheme, file in ((Ed25519, "ed25519_test.json"), (Ed448, "ed448_test.json")):
        for group, test in Wycheproof.tests(f"crypto/eddsa/{file}"):
            try:
                scheme.verify(scheme.verifying_key_from_bytes(bytes.fromhex(group["publicKey"]["pk"])), Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "sig"))
                accepted = True
            except CryptoError:
                accepted = False
            Outcome.check(test, accepted, f"{file} {test['tcId']}")
    # The variants with a context and of a prehashed message.
    key = Ed448.generate(generator(b"ed448"))
    verifying = Ed448.verifying_key(key)
    for sign, verify in ((Ed448.sign_with_context, Ed448.verify_with_context), (Ed448.sign_prehashed, Ed448.verify_prehashed)):
        signature = sign(key, b"context", b"message")
        verify(verifying, b"context", b"message", signature)
        with pytest.raises(CryptoError):
            verify(verifying, b"other", b"message", signature)


def test_dsa_follows_the_wycheproof_vectors():
    for file in ("dsa_2048_224_sha224_p1363_test.json",):
        for group, test in Wycheproof.tests(f"crypto/dsa/{file}"):
            public = group["publicKey"]
            parameters = DSAParameters(*(bytes.fromhex(public[name]) for name in ("p", "q", "g")))
            key = DSAVerifyingKey(parameters, bytes.fromhex(public["y"]))
            try:
                if "_p1363_" in file:
                    signature = DSASignature.from_bytes(parameters, Wycheproof.bytes(test, "sig"))
                else:
                    signature = DSASignature.from_der(parameters, Wycheproof.bytes(test, "sig"))
                DSA[HASHES[group["sha"]]].verify(key, Wycheproof.bytes(test, "msg"), signature)
                accepted = True
            except CryptoError:
                accepted = False
            Outcome.check(test, accepted, f"{file} {test['tcId']}")


def test_rsa_follows_the_wycheproof_vectors():
    for group, test in Wycheproof.tests("crypto/rsa/rsa_signature_2048_sha256_test.json"):
        key = RSAPublicKey(bytes.fromhex(group["publicKey"]["modulus"]), bytes.fromhex(group["publicKey"]["publicExponent"]))
        try:
            RSAPKCS1v15[SHA256].verify(key, Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "sig"))
            accepted = True
        except CryptoError:
            accepted = False
        Outcome.check(test, accepted, f"pkcs1 {test['tcId']}")
    for group, test in Wycheproof.tests("crypto/rsa/rsa_pss_2048_sha256_mgf1sha1_20_test.json"):
        key = RSAPublicKey(bytes.fromhex(group["publicKey"]["modulus"]), bytes.fromhex(group["publicKey"]["publicExponent"]))
        try:
            RSAPSS[SHA256, SHA1].verify(key, Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "sig"), group["sLen"])
            accepted = True
        except CryptoError:
            accepted = False
        Outcome.check(test, accepted, f"pss {test['tcId']}")
    random = generator(b"rsa")
    for group, test in Wycheproof.tests("crypto/rsa/rsa_oaep_2048_sha256_mgf1sha256_test.json"):
        private = group["privateKey"]
        key = RSAPrivateKey.from_primes(*(bytes.fromhex(private[name]) for name in ("prime1", "prime2", "publicExponent")))
        try:
            message = RSAOAEP[SHA256].decrypt(key, Wycheproof.bytes(test, "ct"), Wycheproof.bytes(test, "label"), random)
            accepted = True
        except CryptoError:
            accepted = False
        Outcome.check(test, accepted, f"oaep {test['tcId']}")
        if accepted and test["result"] == "valid":
            assert bytes(message) == Wycheproof.bytes(test, "msg")
    # The keys of the last group sign, verify, encrypt and survive their encodings.
    public = key.public_key()
    assert public.size() == 256
    assert RSAPublicKey.from_pkcs1_der(public.to_pkcs1_der()).n() == public.n()
    assert RSAPrivateKey.from_pkcs1_der(key.to_pkcs1_der()).public_key().n() == public.n()
    for scheme in (RSAPKCS1v15[SHA256],):
        scheme.verify(public, b"message", scheme.sign(key, b"message", random))
    RSAPSS[SHA256].verify(public, b"message", RSAPSS[SHA256].sign(key, b"message", 32, random), 32)
    assert RSAOAEP[SHA256].maximum_message(public) == 256 - 2 * 32 - 2
    ciphertext = RSAOAEP[SHA256].encrypt(public, b"secret", b"label", random)
    assert RSAOAEP[SHA256].decrypt(key, ciphertext, b"label", random) == b"secret"


def test_hpke_follows_rfc9180():
    kems = {
        0x0010: DHKEM[ECDH[P256], SHA256],
        0x0012: DHKEM[ECDH[P521], SHA512],
        0x0020: DHKEM[X25519, SHA256],
    }
    kdfs = {1: SHA256, 3: SHA512}
    aeads = {1: GCM[AES128], 2: GCM[AES256], 3: ChaCha20Poly1305, 0xFFFF: HPKEExportOnly}
    setups = Setups.all()
    assert len(setups) == 28
    for setup in setups:
        fields = setup["fields"]
        label = setup["name"]
        kem = kems[int(fields["kem_id"])]
        suite = HPKE[kem, kdfs[int(fields["kdf_id"])], aeads[int(fields["aead_id"])]]
        recipient, recipient_public = kem.derive_key_pair(bytes.fromhex(fields["ikmR"]))
        assert recipient_public.to_bytes() == bytes.fromhex(fields["pkRm"]), label
        ephemeral, _ = kem.derive_key_pair(bytes.fromhex(fields["ikmE"]))
        sender, sender_public = kem.derive_key_pair(bytes.fromhex(fields["ikmS"])) if "ikmS" in fields else (None, None)
        psk = (bytes.fromhex(fields["psk"]), bytes.fromhex(fields["psk_id"])) if "psk" in fields else None
        info = bytes.fromhex(fields["info"])
        encapsulated, sealing = suite.setup_sender_with_ephemeral(recipient_public, info, psk, sender, ephemeral)
        assert encapsulated == bytes.fromhex(fields["enc"]), label
        opening = suite.setup_receiver(encapsulated, recipient, info, psk, sender_public)
        for encryption in setup["encryptions"]:
            while sealing.sequence() < int(encryption["sequence number"]):
                opening.open(b"", sealing.seal(b"", b""))
            associated, plaintext = bytes.fromhex(encryption["aad"]), bytes.fromhex(encryption["pt"])
            ciphertext = sealing.seal(associated, plaintext)
            assert ciphertext == bytes.fromhex(encryption["ct"]), label
            assert opening.open(associated, ciphertext) == plaintext
        for export in setup["exports"]:
            value = bytearray(int(export["L"]))
            sealing.export(bytes.fromhex(export["exporter_context"]), value)
            assert bytes(value) == bytes.fromhex(export["exported_value"]), label
            opening.export(bytes.fromhex(export["exporter_context"]), value)
            assert bytes(value) == bytes.fromhex(export["exported_value"]), label
    # The single-shot functions, and keys of another length (section 7.1.1).
    kem = DHKEM[X25519, SHA256]
    suite = HPKE[kem, SHA256, ChaCha20Poly1305]
    random = generator(b"hpke")
    recipient, recipient_public = kem.generate_key_pair(random)
    encapsulated, ciphertext = suite.seal(recipient_public, b"info", b"aad", b"message", None, None, random)
    assert suite.open(encapsulated, recipient, b"info", b"aad", ciphertext, None, None) == b"message"
    with pytest.raises(CryptoError) as error:
        suite.open(encapsulated, recipient, b"other", b"aad", ciphertext, None, None)
    assert error.value.name == "AuthenticationFailed"
    with pytest.raises(CryptoError) as error:
        kem.deserialize_public_key(bytes(31))
    assert error.value.name == "InvalidKey"
    with pytest.raises(TypeError):
        DHKEM[X25519, SHA512]
    with pytest.raises(CryptoError) as error:
        suite.setup_sender(recipient_public, b"", (b"psk", b""), None, random)
    assert error.value.name == "InvalidParameter"


def test_sm2_encryption_and_key_exchange_round_trip():
    random = generator(b"sm2")
    scheme = SM2DSA[SM2, SM3]
    a, b = scheme.generate(random), scheme.generate(random)
    public_a, public_b = scheme.verifying_key(a), scheme.verifying_key(b)
    for order in SM2CiphertextOrder:
        ciphertext = SM2PKE[SM2, SM3].encrypt(public_b, b"encryption standard", order, random)
        out = bytearray(len(ciphertext) - SM2PKE.OVERHEAD)
        SM2PKE[SM2, SM3].decrypt(b, ciphertext, order, out)
        assert out == b"encryption standard"
    initiator = SM2KEP.generate(SM2Role.INITIATOR, a, b"alice", random)
    responder = SM2KEP.generate(SM2Role.RESPONDER, b, b"bob", random)
    key_a, key_b = bytearray(16), bytearray(16)
    confirmation_a = initiator.agree(public_b, b"bob", responder.ephemeral_public_key(), key_a)
    confirmation_b = responder.agree(public_a, b"alice", initiator.ephemeral_public_key(), key_b)
    assert key_a == key_b
    assert initiator.confirm(confirmation_a, confirmation_b.responder())
    assert responder.confirm(confirmation_b, confirmation_a.initiator())
    assert not initiator.confirm(confirmation_a, confirmation_b.initiator())


def test_eccsi_follows_rfc6507():
    kms = ECCSIKMS[P256](Appendix.rfc6507("KSAK").rjust(32, b"\0"))
    assert kms.public_key() == Appendix.rfc6507("KPAK")
    identity = Appendix.rfc6507("ID")
    key = kms.issue_with_ephemeral(SHA256, identity, Appendix.rfc6507("v").rjust(32, b"\0"))
    assert key.token() == Appendix.rfc6507("PVT")
    assert key.secret().expose() == Appendix.rfc6507("SSK")
    message = Appendix.rfc6507("M")
    signature = ECCSI[P256, SHA256].sign_with_ephemeral(key, message, Appendix.rfc6507("j").rjust(32, b"\0"))
    assert signature == Appendix.rfc6507("Sig")
    ECCSI[P256, SHA256].verify(kms.public_key(), identity, message, signature)
    with pytest.raises(CryptoError):
        ECCSI[P256, SHA256].verify(kms.public_key(), b"other", message, signature)
    # A generated community, and a key validated from its parts.
    random = generator(b"eccsi")
    kms = ECCSIKMS[P256].generate(random)
    key = kms.issue(SHA256, b"alice", random)
    copy = ECCSIUserKey[P256, SHA256](kms.public_key(), b"alice", key.secret().expose(), key.token())
    signature = ECCSI[P256, SHA256].sign(copy, b"message", random)
    ECCSI[P256, SHA256].verify(kms.public_key(), b"alice", b"message", signature)
    with pytest.raises(CryptoError) as error:
        ECCSIUserKey[P256, SHA256](kms.public_key(), b"bob", key.secret().expose(), key.token())
    assert error.value.name == "InvalidKey"


def test_srp_follows_rfc5054():
    salt, identity, password = Appendix.rfc5054("s"), b"alice", b"password123"
    verifier = SRP[SRP1024, SHA1].verifier(salt, identity, password)
    assert verifier.lstrip(b"\0") == Appendix.rfc5054("v").lstrip(b"\0")
    client = SRPClient[SRP1024, SHA1](Appendix.rfc5054("a"))
    server = SRPServer[SRP1024, SHA1](verifier, Appendix.rfc5054("b"))
    assert client.public_value() == Appendix.rfc5054("A")
    assert server.public_value() == Appendix.rfc5054("B")
    expected = Appendix.rfc5054("<premaster secret>")
    assert client.premaster_secret(identity, password, salt, server.public_value()) == expected
    assert server.premaster_secret(client.public_value()) == expected
    random = generator(b"srp")
    verifier = SRP[SRP2048, SHA256].verifier(salt, identity, password)
    client, server = SRPClient[SRP2048, SHA256].generate(random), SRPServer[SRP2048, SHA256].generate(verifier, random)
    secret = client.premaster_secret(identity, password, salt, server.public_value())
    assert secret == server.premaster_secret(client.public_value())
    assert client.premaster_secret(identity, b"wrong", salt, server.public_value()) != secret


def test_dragonfly_peers_agree():
    random = generator(b"dragonfly")
    config = DragonflyConfig.default()
    assert config.iterations == 40
    peer = DragonflyPeer[P256, SHA256]
    alice = peer(config, b"alice", b"bob", b"password", random)
    bob = peer(config, b"bob", b"alice", b"password", random)
    confirm_a, confirm_b = alice.process(bob.commit()), bob.process(alice.commit())
    key = alice.finish(confirm_b)
    assert len(key) == 32 and key == bob.finish(confirm_a)
    with pytest.raises(CryptoError) as error:
        alice.finish(confirm_a)
    assert error.value.name == "AuthenticationFailed"


def test_identity_based_signatures_round_trip():
    random = generator(b"ibs")
    for scheme in (Hess[BLS12381, SHA256], ChaCheon[BN254, SHA256]):
        master = scheme.setup(random)
        key = scheme.extract(master, b"alice")
        assert key.identity() == b"alice"
        signature = scheme.sign(key, b"message", random)
        assert len(signature) == scheme.sizes()[2]
        scheme.verify(master.public_key(), b"alice", b"message", signature)
        with pytest.raises(CryptoError) as error:
            scheme.verify(master.public_key(), b"bob", b"message", signature)
        assert error.value.name == "InvalidSignature"
        assert scheme.master_key_new(master.secret()).public_key() == master.public_key()
    with pytest.raises(TypeError):
        ChaCheon[BN254, SHA256].extract(Hess[BN254, SHA256].setup(random), b"alice")


def test_pairing_follows_the_draft():
    for curve, name in ((BLS12381, "BLS12_381"), (BN462, "BN462")):
        values = Appendix.pairing(name)
        size = len(values["Input x value"])
        field = lambda value: value.rjust(size, b"\0")  # noqa: E731
        p = b"\x04" + field(values["Input x value"]) + field(values["Input y value"])
        q = b"".join(field(values[f"Input {part} value"]) for part in ("x'_0", "x'_1", "y'_0", "y'_1"))
        expected = b"".join(field(values[f"e_{index}"]) for index in range(12))
        assert Pairing[curve].pairing(p, q) == expected, name
        # e(-P, Q) = e(P, -Q) = e(P, Q)^-1.
        prime = int.from_bytes(bytes.fromhex(
            {
                "BLS12_381": "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
                "BN462": "240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908f41c8020ffffffffff6ff66fc6ff687f640000000002401b00840138013",
            }[name]
        ), "big")
        negate = lambda value: (prime - int.from_bytes(value, "big")).to_bytes(size, "big")  # noqa: E731
        negative_p = b"\x04" + field(values["Input x value"]) + negate(values["Input y value"])
        negative_q = q[: 2 * size] + negate(q[2 * size : 3 * size]) + negate(q[3 * size :])
        assert Pairing[curve].pairing(negative_p, q) == Pairing[curve].pairing(p, negative_q) != expected
    assert Pairing[BN254].sizes() == (65, 128, 384)
    with pytest.raises(Exception):
        Pairing[BLS12381].pairing(b"\x04" + bytes(96), bytes(192))


def test_keys_and_values_mirror_the_rust_api():
    random = generator(b"mirror")
    # RSAPrivateKey::new(public, d), and its exponent.
    group, _ = next(Wycheproof.tests("crypto/rsa/rsa_oaep_2048_sha256_mgf1sha256_test.json"))
    private = group["privateKey"]
    key = RSAPrivateKey.from_primes(*(bytes.fromhex(private[name]) for name in ("prime1", "prime2", "publicExponent")))
    d = key.d()
    assert isinstance(d, bytearray) and bytes(d) == bytes.fromhex(private["privateExponent"]).lstrip(b"\0")
    without_primes = RSAPrivateKey(key.public_key(), d)
    signature = RSAPKCS1v15[SHA256].sign(without_primes, b"message", random)
    RSAPKCS1v15[SHA256].verify(key.public_key(), b"message", signature)
    # The domain parameters and keys of DSA.
    group, _ = next(Wycheproof.tests("crypto/dsa/dsa_2048_224_sha224_p1363_test.json"))
    public = group["publicKey"]
    parameters = DSAParameters(*(bytes.fromhex(public[name]) for name in ("p", "q", "g")))
    assert parameters.p() == bytes.fromhex(public["p"]).lstrip(b"\0")
    assert parameters.q() == bytes.fromhex(public["q"]).lstrip(b"\0")
    assert parameters.g().lstrip(b"\0") == bytes.fromhex(public["g"]).lstrip(b"\0")
    from umilib.crypto.dsa import DSASigningKey

    signing = DSASigningKey.generate(parameters, random)
    assert len(signing.x()) == parameters.q_bytes() and signing.parameters() is parameters
    signature = DSA[SHA224].sign(signing, b"message")
    DSA[SHA224].verify(signing.verifying_key(), b"message", DSASignature.from_der(parameters, signature.to_der()))
    # SM2 signatures in DER.
    from umilib.crypto.sm2 import SM2Signature

    sm2 = SM2DSA[SM2, SM3]
    signing = sm2.generate(random)
    signature = SM2Signature[SM2, SM3].from_bytes(sm2.sign(signing, b"message"))
    assert SM2Signature[SM2, SM3].from_der(signature.to_der()) == signature
    with pytest.raises(CryptoError):
        SM2Signature[SM2, SM3].from_der(b"\x30\x81\x06\x02\x01\x01\x02\x01\x02")
    # The keys of another scheme are refused by the exchange of SM2.
    with pytest.raises(TypeError):
        SM2KEP.generate(SM2Role.INITIATOR, ECDSA[P256, SHA256].generate(random), b"alice", random)
    assert SM2PKE.OVERHEAD == 97
    # RFC 9180 section 5.1: an empty pre-shared key or identifier is refused, the empty pair too.
    kem = DHKEM[X25519, SHA256]
    _, recipient = kem.generate_key_pair(random)
    for psk in ((b"", b""), (b"psk", b""), (b"", b"id")):
        with pytest.raises(CryptoError) as error:
            HPKE[kem, SHA256, ChaCha20Poly1305].setup_sender(recipient, b"", psk, None, random)
        assert error.value.name == "InvalidParameter"
    with pytest.raises(CryptoError):
        kem.deserialize_private_key(bytes(31))
    # A secret key whose check fails is erased at once.
    with pytest.raises(CryptoError):
        ECDH[P256].private_key_from_bytes(bytes(32))


def test_sm9_follows_gmt_0044_5_annex_a():
    annex = GMT.read("crypto/ibs/gmt-0044.5-2016-annex-a.txt")
    scheme = SM9[SM9BN256, SM3]
    secret = annex.padded("The master signature private key ??:", 32)
    master = scheme.master_key_new(secret)
    public = b"\x04" + b"".join(annex.values("The master signature public key ????−? = ?? ?2 = (?????−?, ?????−?):", 4))
    assert master.public_key() == public
    assert scheme.sizes() == (32, 129, 97)
    message = annex.values("The hexadecimal representation of ?:", 1)[0]
    assert message == b"Chinese IBS standard"
    signature = b"".join(annex.values("The signature (ℎ, ?) of the message ?:", 2))
    scheme.verify(public, b"Alice", message, signature)
    for identity, text in ((b"Bob", message), (b"Alice", b"Chinese IBS standarD")):
        with pytest.raises(CryptoError) as error:
            scheme.verify(public, identity, text, signature)
        assert error.value.name == "InvalidSignature"
    # A signature of the key of the annex's identity verifies too.
    random = generator(b"sm9")
    key = scheme.extract(master, b"Alice")
    scheme.verify(public, b"Alice", b"another message", scheme.sign(key, b"another message", random))


HID = 0x03


def sm9_master(annex: GMT) -> SM9EncryptMasterKey:
    secret = annex.padded("The master encryption private key ??:", 32)
    master = SM9EncryptMasterKey[SM9BN256](secret)
    assert master.secret() == secret
    public = b"".join(annex.values("The master encryption public key ????−? = ?? ?1 = (?????−?,?????−?):", 2))
    assert master.public_key() == public
    return master


def sm9_user(master: SM9EncryptMasterKey, part: GMT, identity: bytes) -> SM9EncryptUserKey:
    """The key of ``identity`` with hid 03, checked against de of the part of the annex that computes it."""
    key = master.extract(SM3, identity, HID)
    assert key.key() == b"\x04" + b"".join(part.values("in ??:", 8)[4:8])
    assert (key.identity(), key.hid(), key.master()) == (identity, HID, master.public_key())
    return key


def test_sm9_key_exchange_follows_gmt_0044_5_annex_b():
    annex = GMT.read("crypto/sm9/gmt-0044.5-2016-annex-b.txt")
    master = sm9_master(annex)
    alice = sm9_user(master, annex.section("The identity ??? of the entity A: Alice", "The identity ??? of the entity B"), b"Alice")
    bob = sm9_user(master, annex.section("The identity ??? of the entity B: Bob", "The length ????"), b"Bob")
    a = annex.section("The related values in the steps A1—A4", "The related values in the steps B1—B7").values("(???,???):", 7)
    b = annex.section("The related values in the steps B1—B7", "The related values in the steps A5—A8").values("(???,???):", 49)
    exchange = SM9KEP[SM9BN256, SM3]
    assert exchange.sizes() == (32, 64, 129, 32)
    initiator = exchange(SM9Role.INITIATOR, alice, b"Bob", a[4].rjust(32, b"\0"))
    responder = exchange(SM9Role.RESPONDER, bob, b"Alice", b[4].rjust(32, b"\0"))
    assert initiator.ephemeral_public_key() == a[5] + a[6]
    assert responder.ephemeral_public_key() == b[5] + b[6]
    key_a, key_b = bytearray(16), bytearray(16)
    from_b = responder.agree(initiator.ephemeral_public_key(), key_b)
    from_a = initiator.agree(responder.ephemeral_public_key(), key_a)
    assert key_a == key_b == b[44]
    assert from_b.responder() == from_a.responder() == b[48]
    confirmation = annex.section("The related values in the step B8", "If ?2 = ??")
    assert from_a.initiator() == confirmation.value("\n?2: ")
    assert initiator.confirm(from_a, from_b.responder())
    assert responder.confirm(from_b, from_a.initiator())
    assert not responder.confirm(from_b, from_b.responder())
    with pytest.raises(CryptoError) as error:
        initiator.agree(bytes(64), key_a)
    assert error.value.name == "InvalidKey"
    # Random r: both sides agree.
    random = generator(b"sm9 exchange")
    first = exchange.generate(SM9Role.INITIATOR, alice, b"Bob", random)
    second = exchange.generate(SM9Role.RESPONDER, bob, b"Alice", random)
    first.agree(second.ephemeral_public_key(), key_a)
    second.agree(first.ephemeral_public_key(), key_b)
    assert key_a == key_b
    with pytest.raises(TypeError):
        SM9KEP[SM9BN256, SM3](SM9Role.INITIATOR, SM9EncryptMasterKey[SM9BN256].generate(random), b"Bob", bytes(32))


def test_sm9_key_encapsulation_follows_gmt_0044_5_annex_c():
    annex = GMT.read("crypto/sm9/gmt-0044.5-2016-annex-c.txt")
    master = sm9_master(annex)
    bob = sm9_user(master, annex.section("The identity ??? of the entity B: Bob", "The length of encapsulated key"), b"Bob")
    values = annex.section("The related values in the steps A1—A7", "The related values in the steps B1—B4").values("(???,???):", 33)
    kem = SM9KEM[SM9BN256, SM3]
    key = bytearray(32)
    encapsulated = kem.encapsulate_with_ephemeral(master.public_key(), b"Bob", HID, values[4].rjust(32, b"\0"), key)
    assert encapsulated == values[5] + values[6]
    assert key == values[32]
    decapsulated = bytearray(32)
    kem.decapsulate(bob, encapsulated, decapsulated)
    assert decapsulated == key
    encapsulated = kem.encapsulate(master.public_key(), b"Bob", HID, key, generator(b"sm9 kem"))
    kem.decapsulate(bob, encapsulated, decapsulated)
    assert decapsulated == key
    with pytest.raises(CryptoError) as error:
        kem.decapsulate(bob, encapsulated, bytearray())
    assert error.value.name == "InputLength"


def test_sm9_encryption_follows_gmt_0044_5_annex_d():
    annex = GMT.read("crypto/sm9/gmt-0044.5-2016-annex-d.txt")
    master = sm9_master(annex)
    bob = sm9_user(master, annex.section("The identity ??? of the entity B: Bob", "The message ? to be encrypted"), b"Bob")
    message = annex.value("The hexadecimal representation of ?:")
    assert message == b"Chinese IBE standard"
    encryption = annex.section("The related values in the steps A1—A8", "The related values in the steps B1—B5")
    r = encryption.values("(???,???):", 5)[4].rjust(32, b"\0")
    label = "a) The encryption is based on the KDF stream cipher:"
    stream = encryption.section(label, "b) The encryption").values(label, 8)[7]
    block = encryption.values("b) The encryption is based on the block cipher:", 9)[8]
    random = generator(b"sm9 encryption")
    for scheme, expected in ((SM9PKE[SM9BN256, SM3], stream), (SM9PKE[SM9BN256, SM3, SM9BlockCipher[SM4]], block)):
        ciphertext = scheme.encrypt_with_ephemeral(master.public_key(), b"Bob", HID, message, r)
        assert ciphertext == expected
        assert scheme.decrypt(bob, ciphertext) == message
        changed = bytearray(ciphertext)
        changed[70] ^= 1
        with pytest.raises(CryptoError) as error:
            scheme.decrypt(bob, changed)
        assert error.value.name == "DecryptionFailed"
        assert scheme.decrypt(bob, scheme.encrypt(master.public_key(), b"Bob", HID, message, random)) == message
    assert SM9PKE[SM9BN256, SM3] is SM9PKE[SM9BN256, SM3, SM9StreamCipher]
    assert SM9PKE[SM9BN256, SM3].overhead() == 96
    # The key of its encodings decrypts the same.
    copy = SM9EncryptUserKey[SM9BN256](b"Bob", HID, bob.key(), bob.master())
    assert SM9PKE[SM9BN256, SM3].decrypt(copy, stream) == message
    with pytest.raises(TypeError):
        SM9BlockCipher[SM3]
