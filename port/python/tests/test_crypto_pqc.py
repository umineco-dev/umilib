"""The Python classes of the post-quantum schemes (ML-KEM, ML-DSA, SLH-DSA, the hybrids of RFC 10024) and
of the lattice transforms: one group of the ACVP vectors of NIST for each function, round trips, and the
checks of the standards, through the C ABI."""

from __future__ import annotations

import json

import pytest

from umilib.crypto import CryptoError
from umilib.crypto.hybrid import HybridKEM, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768
from umilib.crypto.mldsa import MLDSA, MLDSA44, MLDSA65, MLDSA87
from umilib.crypto.mlkem import MLKEM, MLKEM512, MLKEM768, MLKEM1024
from umilib.crypto.random import HMACDRBG
from umilib.crypto.slhdsa import SLHDSA, SLHDSA_SHA2_128f, SLHDSA_SHAKE_128f
from umilib.hash.sha.v2 import SHA256, SHA512
from umilib.hash.sha.v3 import SHAKE128
from umilib.math.lattice import MLDSARing, MLKEMRing, Polynomial
from vectors import ROOT


def generator(label: bytes) -> HMACDRBG:
    return HMACDRBG[SHA256](bytes([7]) * 32, bytes([8]) * 16, label)


def groups(path: str) -> list[dict]:
    return json.loads((ROOT / path).read_text())["testGroups"]


def first_group(path: str, name: str, **fields: object) -> dict:
    return next(
        group
        for group in groups(path)
        if group["parameterSet"] == name and all(group.get(key) == value for key, value in fields.items())
    )


MLKEM_SETS = {"ML-KEM-512": MLKEM512, "ML-KEM-768": MLKEM768, "ML-KEM-1024": MLKEM1024}


def test_mlkem_follows_the_acvp_vectors():
    for name, parameters in MLKEM_SETS.items():
        scheme = MLKEM[parameters]
        test = first_group("crypto/mlkem/acvp-keygen.json", name)["tests"][0]
        key = scheme.decapsulation_key_from_seed(bytes.fromhex(test["d"] + test["z"]))
        out = bytearray(scheme.DECAPSULATION_KEY_SIZE)
        scheme.write_decapsulation_key(key, out)
        assert out.hex().upper() == test["dk"]
        assert scheme.encapsulation_key(key).to_bytes().hex().upper() == test["ek"]

        test = first_group("crypto/mlkem/acvp-encapdecap.json", name, function="encapsulation")["tests"][0]
        public = scheme.encapsulation_key_from_bytes(bytes.fromhex(test["ek"]))
        shared = bytearray(32)
        ciphertext = scheme.encapsulate_internal(public, bytes.fromhex(test["m"]), shared)
        assert ciphertext.hex().upper() == test["c"] and shared.hex().upper() == test["k"]
        decapsulated = bytearray(32)
        scheme.decapsulate(scheme.decapsulation_key_from_bytes(bytes.fromhex(test["dk"])), ciphertext, decapsulated)
        assert decapsulated == shared
    for group in groups("crypto/mlkem/acvp-encapdecap.json"):
        if group["function"] == "encapsulationKeyCheck":
            scheme = MLKEM[MLKEM_SETS[group["parameterSet"]]]
            for test in group["tests"]:
                if test["testPassed"]:
                    scheme.encapsulation_key_from_bytes(bytes.fromhex(test["ek"]))
                else:
                    with pytest.raises(CryptoError) as error:
                        scheme.encapsulation_key_from_bytes(bytes.fromhex(test["ek"]))
                    assert error.value.name == "InvalidKey"


def test_kems_round_trip():
    random = generator(b"kem")
    for scheme in (MLKEM[MLKEM768], HybridKEM[X25519MLKEM768], HybridKEM[SecP256r1MLKEM768], HybridKEM[SecP384r1MLKEM1024]):
        key = scheme.generate(random)
        public = scheme.encapsulation_key(key)
        sent, received = bytearray(scheme.SHARED_SECRET_SIZE), bytearray(scheme.SHARED_SECRET_SIZE)
        ciphertext = scheme.encapsulate(public, random, sent)
        assert len(ciphertext) == scheme.CIPHERTEXT_SIZE
        scheme.decapsulate(key, ciphertext, received)
        assert sent == received
        with pytest.raises(CryptoError) as error:
            scheme.decapsulate(key, ciphertext[1:], received)
        assert error.value.name == "InputLength"
    assert (HybridKEM[X25519MLKEM768].ENCAPSULATION_KEY_SIZE, HybridKEM[X25519MLKEM768].CIPHERTEXT_SIZE) == (1216, 1120)
    assert X25519MLKEM768.CODEPOINT == 0x11EC
    with pytest.raises(TypeError):
        MLKEM[MLDSA44]


MLDSA_SETS = {"ML-DSA-44": MLDSA44, "ML-DSA-65": MLDSA65, "ML-DSA-87": MLDSA87}
HASHES = {"SHA2-256": SHA256, "SHA2-512": SHA512, "SHAKE-128": SHAKE128}


def check_signatures(scheme: type, groups_of_tests: list[dict], verification: list[dict]) -> None:
    """The deterministic external signatures (pure, and pre-hashed with the hash functions of HASHES)
    and their verification."""
    for group in groups_of_tests:
        if not group["deterministic"] or group["signatureInterface"] != "external":
            continue
        for test in group["tests"]:
            key = scheme.signing_key_from_bytes(bytes.fromhex(test["sk"]))
            message, context = bytes.fromhex(test["message"]), bytes.fromhex(test["context"])
            if group["preHash"] == "pure":
                signature = scheme.sign_deterministic_with_context(key, message, context)
            elif test["hashAlg"] in HASHES:
                signature = scheme.sign_pre_hash_deterministic(HASHES[test["hashAlg"]], key, message, context)
            else:
                continue
            assert signature.hex().upper() == test["signature"]
    for group in verification:
        if group["signatureInterface"] != "external" or group["preHash"] != "pure":
            continue
        for test in group["tests"]:
            key = scheme.verifying_key_from_bytes(bytes.fromhex(test["pk"]))
            arguments = (key, bytes.fromhex(test["message"]), bytes.fromhex(test["context"]), bytes.fromhex(test["signature"]))
            if test["testPassed"]:
                scheme.verify_with_context(*arguments)
            else:
                with pytest.raises(CryptoError) as error:
                    scheme.verify_with_context(*arguments)
                assert error.value.name == "InvalidSignature"


def test_mldsa_follows_the_acvp_vectors():
    for name, parameters in MLDSA_SETS.items():
        scheme = MLDSA[parameters]
        test = first_group("crypto/mldsa/acvp-keygen.json", name)["tests"][0]
        key = scheme.signing_key_from_seed(bytes.fromhex(test["seed"]))
        out = bytearray(scheme.SIGNING_KEY_SIZE)
        scheme.write_signing_key(key, out)
        assert out.hex().upper() == test["sk"]
        assert scheme.verifying_key(key).to_bytes().hex().upper() == test["pk"]
        signing = [group for group in groups("crypto/mldsa/acvp-siggen-subset.json") if group["parameterSet"] == name]
        verification = [group for group in groups("crypto/mldsa/acvp-sigver.json") if group["parameterSet"] == name]
        check_signatures(scheme, signing, verification)


def test_slhdsa_follows_the_acvp_vectors():
    for name, parameters in {"SLH-DSA-SHA2-128f": SLHDSA_SHA2_128f, "SLH-DSA-SHAKE-128f": SLHDSA_SHAKE_128f}.items():
        scheme = SLHDSA[parameters]
        test = first_group("crypto/slhdsa/acvp-keygen.json", name)["tests"][0]
        key = scheme.key_gen_internal(bytes.fromhex(test["skSeed"]), bytes.fromhex(test["skPrf"]), bytes.fromhex(test["pkSeed"]))
        assert scheme.verifying_key(key).to_bytes().hex().upper() == test["pk"]
        signing = [group for group in groups("crypto/slhdsa/acvp-siggen-subset.json") if group["parameterSet"] == name]
        verification = [group for group in groups("crypto/slhdsa/acvp-sigver-subset.json") if group["parameterSet"] == name]
        check_signatures(scheme, signing, verification)


def test_context_signatures_round_trip():
    random = generator(b"signatures")
    for scheme in (MLDSA[MLDSA65], SLHDSA[SLHDSA_SHAKE_128f]):
        key = scheme.generate(random)
        public = scheme.verifying_key(key)
        signature = scheme.sign_with_context(key, b"message", b"context", random)
        scheme.verify_with_context(public, b"message", b"context", signature)
        with pytest.raises(CryptoError) as error:
            scheme.verify_with_context(public, b"message", b"other", signature)
        assert error.value.name == "InvalidSignature"
        signature = scheme.sign_pre_hash(SHA512, key, b"message", b"", random)
        scheme.verify_pre_hash(SHA512, public, b"message", b"", signature)
        with pytest.raises(CryptoError) as error:
            scheme.verify(public, b"message", signature)
        assert error.value.name == "InvalidSignature"
        scheme.verify(public, b"message", scheme.sign(key, b"message"))
        with pytest.raises(CryptoError) as error:
            scheme.sign_deterministic_with_context(key, b"message", bytes(256))
        assert error.value.name == "InvalidParameter"


def negacyclic(f: list[int], g: list[int], q: int) -> list[int]:
    """f g in Z_q[X]/(X^n + 1) by the definition."""
    n = len(f)
    product = [0] * n
    for i, a in enumerate(f):
        for j, b in enumerate(g):
            sign = 1 if i + j < n else -1
            product[(i + j) % n] = (product[(i + j) % n] + sign * a * b) % q
    return product


def test_lattice_transforms_multiply_in_the_ring():
    for ring in (MLKEMRing, MLDSARing):
        f = Polynomial[ring]([(index * 37 + 5) % ring.Q for index in range(ring.N)])
        g = Polynomial[ring]([(index * index * 11 + 3) % ring.Q for index in range(ring.N)])
        assert f.ntt().inverse_ntt() == f
        assert f.ntt().multiply_ntt(g.ntt()).inverse_ntt().coefficients == negacyclic(f.coefficients, g.coefficients, ring.Q)
    with pytest.raises(ValueError):
        Polynomial[MLKEMRing]([0] * 255)
