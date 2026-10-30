"""Tests of umilib.crypto against Python's hmac module and the NIST CAVP vectors in tests/vectors."""

import hashlib
import hmac
from pathlib import Path

import pytest

from umilib.crypto.hmac import HMAC
from umilib.crypto.random import DRBGConfig, HashDRBG, HMACDRBG, RandomError
from umilib.hash.md.v5 import MD5
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA256, SHA384, SHA512
from umilib.hash.sha.v3 import SHA3_256

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "crypto"


@pytest.mark.parametrize(("hash", "name"), [(MD5, "md5"), (SHA1, "sha1"), (SHA256, "sha256"), (SHA512, "sha512"), (SHA3_256, "sha3_256")])
def test_hmac_agrees_with_the_hmac_module(hash, name):
    for key in (b"", b"key", b"k" * 64, b"k" * 65, b"k" * 200):
        for message in (b"", b"message", b"m" * 1000):
            expected = hmac.new(key, message, name).digest()
            assert HMAC[hash].mac(key, message) == expected
            state = HMAC[hash](key)
            state.update(message[:3])
            state.update(message[3:])
            assert state.clone().verify(expected)
            assert state.clone().verify_truncated(expected[: HMAC[hash].MINIMUM_TRUNCATED_LENGTH])
            assert not state.clone().verify(expected[:-1] + bytes([expected[-1] ^ 1]))
            assert state.finalize_reset() == expected
            state.update(message)
            assert state.finalize() == expected


def test_hmac_needs_a_hash_function():
    from umilib.hash.siphash import SipHash24
    from umilib.hash.xxhash.xxh64 import XXH64

    with pytest.raises(TypeError):
        HMAC(b"key")
    with pytest.raises(TypeError):
        HMAC[int]
    for keyed_or_checksum in (SipHash24, XXH64):
        with pytest.raises(TypeError):
            HMAC[keyed_or_checksum]
        with pytest.raises(TypeError):
            HMACDRBG[keyed_or_checksum]
    assert HMAC[SHA256] is HMAC[SHA256]
    assert HMAC[SHA384].MINIMUM_TRUNCATED_LENGTH == 24


def records(path: Path):
    """The records of a CAVP DRBG file with their bracketed headers."""
    header, fields = {}, []
    fresh = False
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        if not line:
            if fields:
                yield dict(header), fields
                fields = []
            continue
        if line.startswith("["):
            if not fresh:
                header, fresh = {}, True
            inner = line[1:-1]
            key, _, value = inner.partition("=")
            header[key.strip()] = value.strip()
            continue
        fresh = False
        key, _, value = line.partition("=")
        fields.append((key.strip(), value.strip()))
    if fields:
        yield dict(header), fields


@pytest.mark.parametrize(("generator", "file"), [(HMACDRBG, "HMAC_DRBG"), (HashDRBG, "Hash_DRBG")])
def test_drbgs_follow_the_cavp_vectors(generator, file):
    checked = 0
    for mode in ("no_reseed", "pr_false", "pr_true"):
        for header, fields in records(VECTORS / "random" / f"{file}_{mode}.rsp"):
            if "SHA-256" not in header or fields[0][1] not in ("0", "1"):
                continue
            values = {}
            for key, value in fields[1:]:
                values.setdefault(key, []).append(bytes.fromhex(value))
            drbg = generator[SHA256](values["EntropyInput"][0], values["Nonce"][0], values["PersonalizationString"][0])
            out = bytearray(len(values["ReturnedBits"][0]))
            if "EntropyInputReseed" in values:
                drbg.reseed(values["EntropyInputReseed"][0], values["AdditionalInputReseed"][0])
            for index, additional in enumerate(values["AdditionalInput"]):
                if header["PredictionResistance"] == "True":
                    drbg.reseed(values["EntropyInputPR"][index], additional)
                    drbg.generate(out)
                else:
                    drbg.generate(out, additional)
            assert bytes(out) == values["ReturnedBits"][0]
            checked += 1
    assert checked >= 3 * 2 * 4


def test_drbgs_enforce_their_limits():
    with pytest.raises(RandomError) as error:
        HMACDRBG[SHA256](bytes(31))
    assert error.value.name == "EntropyLength"
    with pytest.raises(RandomError) as error:
        HMACDRBG[SHA256](bytes(32))
    assert error.value.name == "NonceLength"
    drbg = HashDRBG[SHA256].with_config(DRBGConfig(1, 16), bytes(32), bytes(16))
    with pytest.raises(OverflowError):
        DRBGConfig(-1, 16).structure()
    assert drbg.config() == DRBGConfig(1, 16)
    assert drbg.security_strength() == 256
    with pytest.raises(RandomError):
        drbg.generate(bytearray(17))
    drbg.generate(bytearray(16))
    with pytest.raises(RandomError) as error:
        drbg.generate(bytearray(1))
    assert error.value.name == "ReseedRequired"
    drbg.reseed(bytes(32))
    assert len(drbg.bytes(1)) == 1
    assert DRBGConfig(0, 1 << 40).clamped() == DRBGConfig(1, 1 << 16)
    assert DRBGConfig.default() == DRBGConfig(1 << 48, 1 << 16)
    assert HMACDRBG[SHA1](bytes(24)).security_strength() == 128
    with pytest.raises(TypeError):
        HMACDRBG(bytes(32))
    first = HMACDRBG[SHA256](bytes(32), bytes(16))
    second = HMACDRBG[SHA256](bytes(32), bytes(16))
    assert first.bytes(100) == second.bytes(100)
    assert first.next_u64() == second.next_u64()
    assert hashlib.sha256(first.bytes(32)).digest() == hashlib.sha256(second.bytes(32)).digest()
    first.uninstantiate()
    assert not first.is_instantiated() and second.is_instantiated()
    with pytest.raises(RandomError) as error:
        first.bytes(1)
    assert error.value.name == "Uninstantiated"
