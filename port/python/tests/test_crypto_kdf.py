"""Tests of the key derivation functions and CTR_DRBG of umilib.crypto against the RFCs, NIST CAVP and
Project Wycheproof, in tests/vectors."""

import pytest

from umilib.crypto import CryptoError
from umilib.crypto.aes import AES128, AES192, AES256
from umilib.crypto.argon2 import Argon2, Argon2Type
from umilib.crypto.cmac import CMAC
from umilib.crypto.concatkdf import ConcatKDF, HashFunction
from umilib.crypto.des import TDES
from umilib.crypto.hkdf import HKDF
from umilib.crypto.hmac import HMAC
from umilib.crypto.kbkdf import KBKDF, KBKDFCounter
from umilib.crypto.kdftree import KDFTree
from umilib.crypto.pbkdf2 import PBKDF2
from umilib.crypto.random import CTRDRBG, DRBGConfig, RandomError
from umilib.crypto.scrypt import Scrypt
from umilib.hash.blake.v2 import BLAKE2b
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA224, SHA256, SHA384, SHA512
from umilib.hash.streebog import Streebog256
from vectors import Record, Wycheproof

HASHES = {"SHA-1": SHA1, "SHA-256": SHA256}


def test_hkdf_follows_rfc5869_and_the_wycheproof_vectors():
    for record in Record.all("crypto/hkdf/rfc5869.txt"):
        hash = HASHES[record.field("Hash")]
        salt, ikm, info, length = record.bytes("salt"), record.bytes("IKM"), record.bytes("info"), int(record.field("L"))
        assert HKDF[hash].extract(salt, ikm) == record.bytes("PRK")
        assert HKDF[hash](record.bytes("PRK")).expand(info, length) == record.bytes("OKM")
        assert HKDF[hash].derive(salt, ikm, info, length) == record.bytes("OKM")
        assert HKDF[hash].from_secret(salt, ikm).clone().expand(info, length) == record.bytes("OKM")
    for name, hash in (("sha256", SHA256), ("sha512", SHA512)):
        for _, test in Wycheproof.tests(f"crypto/hkdf/hkdf_{name}_test.json"):
            arguments = [Wycheproof.bytes(test, key) for key in ("salt", "ikm", "info")]
            try:
                assert HKDF[hash].derive(*arguments, test["size"]) == Wycheproof.bytes(test, "okm")
                assert Wycheproof.valid(test)
            except CryptoError:
                assert not Wycheproof.valid(test)
    assert HKDF[SHA256].MAXIMUM_OUTPUT == 255 * 32
    with pytest.raises(CryptoError) as error:
        HKDF[SHA256](bytes(31))
    assert error.value.name == "KeyLength"
    with pytest.raises(TypeError):
        HKDF[AES128]


def test_pbkdf2_follows_rfc6070_and_the_wycheproof_vectors():
    for record in Record.all("crypto/pbkdf2/rfc6070.txt"):
        iterations = int(record.field("c"))
        if iterations <= 4096:
            expected = record.bytes("DK")
            assert PBKDF2[SHA1].derive(record.bytes("P"), record.bytes("S"), iterations, len(expected)) == expected
    for name, hash in (("sha224", SHA224), ("sha384", SHA384)):
        for _, test in Wycheproof.tests(f"crypto/pbkdf2/pbkdf2_hmac{name}_test.json"):
            if test["iterationCount"] > 4096:
                continue
            try:
                out = PBKDF2[hash].derive(Wycheproof.bytes(test, "password"), Wycheproof.bytes(test, "salt"), test["iterationCount"], test["dkLen"])
                assert Wycheproof.valid(test) and out == Wycheproof.bytes(test, "dk")
            except CryptoError:
                assert not Wycheproof.valid(test)
    assert PBKDF2[SHA1].MAXIMUM_OUTPUT == (2**32 - 1) * 20
    with pytest.raises(CryptoError):
        PBKDF2[SHA256].derive(b"p", b"s", 0, 32)


def test_scrypt_follows_rfc7914():
    checked = 0
    for record in Record.all("crypto/scrypt/rfc7914.txt"):
        if record.field("Function") == "Salsa20/8":
            words = [int.from_bytes(record.bytes("Input")[index : index + 4], "little") for index in range(0, 64, 4)]
            output = b"".join(word.to_bytes(4, "little") for word in Scrypt.salsa20_8(words))
            assert output == record.bytes("Output")
        elif record.field("Function") == "scrypt" and record.field("N") != "1048576":
            n, r, p = int(record.field("N")), int(record.field("r")), int(record.field("p"))
            scrypt = Scrypt(n, r, p)
            assert (scrypt.n(), scrypt.r(), scrypt.p(), scrypt.memory()) == (n, r, p, 128 * r * (n + p))
            assert scrypt.derive(record.bytes("P"), record.bytes("S"), len(record.bytes("DK"))) == record.bytes("DK")
        else:
            continue
        checked += 1
    assert checked == 4
    with pytest.raises(CryptoError):
        Scrypt(3, 1, 1)


def test_argon2_follows_rfc9106():
    for record in Record.all("crypto/argon2/rfc9106.txt"):
        argon2 = Argon2(Argon2Type[record.field("Type")], int(record.field("Memory")), int(record.field("Passes")), int(record.field("Lanes")))
        assert argon2.variant() == Argon2Type[record.field("Type")]
        assert (argon2.blocks(), argon2.memory_bytes()) == (32, 32 * 1024)
        tag = argon2.derive(
            record.bytes("Password"),
            record.bytes("Salt"),
            record.bytes("Secret"),
            record.bytes("Associated"),
            len(record.bytes("Tag")),
        )
        assert tag == record.bytes("Tag")
    # Section 3.3: H' of at most 64 bytes is BLAKE2b of LE32(T) and the input.
    blake = BLAKE2b(64)
    blake.update((64).to_bytes(4, "little") + b"umilib")
    expected = bytearray(64)
    blake.finalize_into(expected)
    assert Argon2.variable_hash([b"umi", b"lib"], 64) == bytes(expected)
    with pytest.raises(CryptoError):
        Argon2(Argon2Type.Argon2id, 7, 1, 1)


PRFS = {
    "CMAC_AES128": CMAC[AES128],
    "CMAC_AES192": CMAC[AES192],
    "CMAC_AES256": CMAC[AES256],
    "CMAC_TDES2": CMAC[TDES],
    "CMAC_TDES3": CMAC[TDES],
    "HMAC_SHA1": HMAC[SHA1],
    "HMAC_SHA224": HMAC[SHA224],
    "HMAC_SHA256": HMAC[SHA256],
    "HMAC_SHA384": HMAC[SHA384],
    "HMAC_SHA512": HMAC[SHA512],
}
LOCATIONS = {"BEFORE_ITER": KBKDFCounter.BeforeIteration, "AFTER_ITER": KBKDFCounter.AfterIteration, "AFTER_FIXED": KBKDFCounter.AfterFixed}


@pytest.mark.parametrize(("file", "mode"), [
    ("KDFCTR_gen.rsp", "Counter"),
    ("KDFFeedback_gen_NOzeroiv.rsp", "Feedback"),
    ("KDFFeedback_gen_nocounter.rsp", "Feedback"),
    ("KDFDblPipeline_gen_withCounter.rsp", "Pipeline"),
])
def test_kbkdf_follows_the_cavp_vectors(file, mode):
    checked = 0
    for record in Record.all(f"crypto/kbkdf/{file}")[::7]:
        bits = int(record.header.get("RLEN", "32_BITS").removesuffix("_BITS"))
        kbkdf = KBKDF[PRFS[record.header["PRF"]]](record.bytes("KI"), bits)
        length = int(record.field("L")) // 8
        location = LOCATIONS.get(record.header.get("CTRLOCATION", ""), KBKDFCounter.Absent)
        if mode == "Counter":
            if record.header["CTRLOCATION"] == "BEFORE_FIXED":
                before, after = b"", record.bytes("FixedInputData")
            elif record.header["CTRLOCATION"] == "AFTER_FIXED":
                before, after = record.bytes("FixedInputData"), b""
            else:
                before, after = record.bytes("DataBeforeCtrData"), record.bytes("DataAfterCtrData")
            out = kbkdf.counter(before, after, length)
        elif mode == "Feedback":
            iv = record.bytes("IV") if record.get("IV") else b""
            out = kbkdf.feedback(iv, record.bytes("FixedInputData"), location, length)
        else:
            out = kbkdf.double_pipeline(record.bytes("FixedInputData"), location, length)
        assert out == record.bytes("KO"), (record.header, record.field("COUNT"))
        checked += 1
    assert checked > 50
    with pytest.raises(TypeError):
        KBKDF[SHA256]
    with pytest.raises(CryptoError):
        KBKDF[HMAC[SHA256]](b"key", 12)


def test_kdf_tree_follows_rfc7836_appendix_b():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    tree = KDFTree[HMAC[Streebog256]](key, 1)
    label, seed = bytes.fromhex("26bdb878"), bytes.fromhex("af21434145656378")
    assert tree.derive(label, seed, 32) == bytes.fromhex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
    assert tree.derive(label, seed, 64) == bytes.fromhex(
        "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b"
        "074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
    )
    with pytest.raises(CryptoError):
        KDFTree[HMAC[Streebog256]](key, 5)


CIPHERS = {"AES-128": AES128, "AES-192": AES192, "AES-256": AES256}


@pytest.mark.parametrize("mode", ["no_reseed", "pr_false", "pr_true"])
def test_ctr_drbg_follows_the_cavp_vectors(mode):
    checked = 0
    for record in Record.all(f"crypto/random/CTR_DRBG_{mode}.rsp")[::5]:
        group = next(key for key in record.header if " df" in key)
        cipher = CIPHERS.get(group[:7])
        if cipher is None:
            continue
        entropy, nonce, personalization = record.bytes("EntropyInput"), record.bytes("Nonce"), record.bytes("PersonalizationString")
        if group.endswith("use df"):
            drbg = CTRDRBG[cipher](entropy, nonce, personalization)
        else:
            drbg = CTRDRBG[cipher].instantiate_without_derivation(DRBGConfig.default(), entropy, personalization)
        expected = record.bytes("ReturnedBits")
        out = bytearray(len(expected))
        if record.get("EntropyInputReseed"):
            drbg.reseed(record.bytes("EntropyInputReseed"), record.bytes("AdditionalInputReseed"))
        entropy_pr = record.values("EntropyInputPR")
        for index, additional in enumerate(record.values("AdditionalInput")):
            if record.header["PredictionResistance"] == "True":
                drbg.reseed(bytes.fromhex(entropy_pr[index]), bytes.fromhex(additional))
                drbg.generate(out)
            else:
                drbg.generate(out, bytes.fromhex(additional))
        assert bytes(out) == expected
        assert drbg.security_strength() == int(group[4:7])
        checked += 1
    assert checked > 200
    with pytest.raises(TypeError):
        CTRDRBG[TDES]
    with pytest.raises(RandomError) as error:
        CTRDRBG[AES128].instantiate_without_derivation(DRBGConfig.default(), bytes(31))
    assert error.value.name == "EntropyLength"


def test_concatkdf_follows_rfc_7518_appendix_c_and_sp_800_56c():
    import base64
    import hashlib
    import hmac

    z = bytes([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196])
    other_info = bytes([0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128])
    derived = ConcatKDF[HashFunction[SHA256]].hash().derive(z, other_info, 16)
    assert base64.urlsafe_b64encode(derived).rstrip(b"=") == b"VqqN6vgjbSBcIijNcacQGg"
    # Option 2 of SP 800-56C Rev. 2: K(i) = HMAC(salt, [i]_32 || Z || FixedInfo).
    salt = b"salt of the KDF"
    expected = b"".join(hmac.new(salt, i.to_bytes(4, "big") + z + other_info, hashlib.sha512).digest() for i in (1, 2))[:100]
    assert ConcatKDF[HMAC[SHA512]](salt).derive(z, other_info, 100) == expected
    with pytest.raises(TypeError):
        ConcatKDF[SHA256]
