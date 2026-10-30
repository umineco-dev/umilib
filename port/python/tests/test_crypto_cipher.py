"""Tests of the block ciphers and the modes of umilib.crypto against the NIST CAVP files, the RFCs and
Project Wycheproof, in tests/vectors."""

import pytest

from umilib.crypto import CryptoError
from umilib.crypto.aes import AES128, AES192, AES256, AESBitslice
from umilib.crypto.aria import ARIA128, ARIA192, ARIA256
from umilib.crypto.camellia import Camellia128, Camellia192, Camellia256
from umilib.crypto.des import DES, TDES
from umilib.crypto.gost.kuznyechik import Kuznyechik
from umilib.crypto.gost.magma import Magma
from umilib.crypto.idea import IDEA
from umilib.crypto.mode import PKCS7
from umilib.crypto.mode.cbc import CBC
from umilib.crypto.mode.cfb import CFB, CFB1, CFB8
from umilib.crypto.mode.ctr import CTR
from umilib.crypto.mode.ecb import ECB
from umilib.crypto.mode.kw import KW, KWP
from umilib.crypto.mode.ofb import OFB
from umilib.crypto.mode.xts import XTS
from umilib.crypto.rc2 import RC2
from umilib.crypto.seed import SEED
from umilib.crypto.sm4 import SM4
from umilib.hash.sha.v2 import SHA256
from vectors import ROOT, Record, Wycheproof

AES = {16: AES128, 24: AES192, 32: AES256}
ARIA = {16: ARIA128, 24: ARIA192, 32: ARIA256}
CAMELLIA = {16: Camellia128, 24: Camellia192, 32: Camellia256}


def check_block(cipher, key: bytes, plaintext: bytes, ciphertext: bytes) -> None:
    state = cipher(key)
    block = bytearray(plaintext)
    state.encrypt_blocks(block)
    assert bytes(block) == ciphertext
    state.clone().decrypt_blocks(block)
    assert bytes(block) == plaintext


@pytest.mark.parametrize("size", [128, 192, 256])
def test_aes_follows_the_aesavs_known_answers(size):
    checked = 0
    for kind in ("GFSbox", "KeySbox", "VarKey", "VarTxt"):
        for record in Record.all(f"crypto/aes/ECB{kind}{size}.rsp"):
            if "ENCRYPT" in record.header:
                check_block(AES[size // 8], record.bytes("KEY"), record.bytes("PLAINTEXT"), record.bytes("CIPHERTEXT"))
                checked += 1
    assert checked == {128: 284, 192: 350, 256: 405}[size]
    assert (AES[size // 8].BLOCK_SIZE, AES[size // 8].MINIMUM_KEY_SIZE) == (16, size // 8)


def test_block_ciphers_follow_their_specifications():
    # RFC 8891 A.3 to A.5, RFC 7801 5.5 and 5.6.
    check_block(
        Magma,
        bytes.fromhex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        bytes.fromhex("fedcba9876543210"),
        bytes.fromhex("4ee901e5c2d8ca3d"),
    )
    check_block(
        Kuznyechik,
        bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
        bytes.fromhex("1122334455667700ffeeddccbbaa9988"),
        bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd"),
    )
    for record in Record.all("crypto/seed/rfc4269.txt"):
        if record.field("Name").startswith("B."):
            check_block(SEED, record.bytes("Key"), record.bytes("Plaintext"), record.bytes("Ciphertext"))
    for record in Record.all("crypto/sm4/draft-ribose-cfrg-sm4.txt"):
        if record.field("Mode") == "SM4" and record.get("Key") and record.get("Iterations") is None:
            check_block(SM4, record.bytes("Key"), record.bytes("Plaintext"), record.bytes("Ciphertext"))
    for record in Record.all("crypto/rc2/rfc2268.txt"):
        cipher = RC2(record.bytes("Key"), int(record.field("EffectiveBits")))
        block = bytearray(record.bytes("Plaintext"))
        cipher.encrypt_block(block)
        assert bytes(block) == record.bytes("Ciphertext")
    for record in Record.all("crypto/des/TECBvartext.rsp"):
        if "ENCRYPT" in record.header:
            check_block(DES, record.bytes("KEYs"), record.bytes("PLAINTEXT"), record.bytes("CIPHERTEXT"))
    for record in Record.all("crypto/des/TECBMMT3.rsp"):
        if "ENCRYPT" in record.header:
            key = record.bytes("KEY1") + record.bytes("KEY2") + record.bytes("KEY3")
            check_block(TDES, key, record.bytes("PLAINTEXT"), record.bytes("CIPHERTEXT"))
    # The NESSIE vectors of IDEA: "Set n, vector# m:" followed by "name=value" lines.
    vectors: list[dict[str, str]] = []
    for line in (ROOT / "crypto/idea/Idea-128-64.verified.test-vectors").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("Set "):
            vectors.append({})
        elif vectors and "=" in line:
            name, _, value = line.partition("=")
            vectors[-1][name] = value
    checked = 0
    for vector in vectors:
        check_block(IDEA, bytes.fromhex(vector["key"]), bytes.fromhex(vector["plain"]), bytes.fromhex(vector["cipher"]))
        checked += 1
    assert checked > 700
    assert DES.is_weak(bytes.fromhex("0101010101010101"))
    assert not DES.is_weak(bytes.fromhex("0123456789abcdef"))


def test_block_ciphers_check_their_inputs():
    with pytest.raises(CryptoError) as error:
        AES128(bytes(15))
    assert error.value.name == "KeyLength"
    with pytest.raises(CryptoError) as error:
        TDES(bytes(8) * 2 + bytes([1]) * 8)
    assert error.value.name == "InvalidParameter"
    with pytest.raises(CryptoError) as error:
        AES128(bytes(16)).encrypt_blocks(bytearray(17))
    assert error.value.name == "InputLength"
    with pytest.raises(ValueError):
        AES128(bytes(16)).encrypt_block(bytearray(8))
    # AESRound of the AEGIS draft.
    record = next(record for record in Record.all("crypto/aegis/draft-irtf-cfrg-aegis-aead.txt") if record.field("Group") == "AESRound")
    blocks = bytearray(record.bytes("in"))
    AESBitslice.round(blocks, record.bytes("rk"))
    assert bytes(blocks) == record.bytes("out")


MODES = {"CBC": CBC, "CFB128": CFB, "CFB8": CFB8, "CFB1": CFB1, "OFB": OFB}


def bits(text: str) -> tuple[bytearray, int]:
    """A CFB1 field: a string of bits, most significant first."""
    data = bytearray((len(text) + 7) // 8)
    for index, character in enumerate(text):
        if character == "1":
            data[index // 8] |= 0x80 >> (index % 8)
    return data, len(text)


@pytest.mark.parametrize(("prefix", "directory"), [("ECB", "../aes"), ("CBC", "cbc"), ("CFB128", "cfb"), ("CFB8", "cfb"), ("CFB1", "cfb"), ("OFB", "ofb")])
def test_modes_follow_the_cavp_multiblock_tests(prefix, directory):
    checked = 0
    for size in (128, 192, 256):
        for record in Record.all(f"crypto/mode/{directory}/{prefix}MMT{size}.rsp"):
            encrypt = "ENCRYPT" in record.header
            source, target = ("PLAINTEXT", "CIPHERTEXT") if encrypt else ("CIPHERTEXT", "PLAINTEXT")
            cipher = AES[size // 8]
            key = record.bytes("KEY")
            if prefix == "ECB":
                data = bytearray(record.bytes(source))
                mode = ECB[cipher](key)
                mode.encrypt(data) if encrypt else mode.decrypt(data)
                assert bytes(data) == record.bytes(target)
            elif prefix == "CFB1":
                data, length = bits(record.field(source))
                mode = CFB1[cipher](key, record.bytes("IV"))
                mode.encrypt_bits(data, length) if encrypt else mode.decrypt_bits(data, length)
                assert data == bits(record.field(target))[0]
            else:
                data = bytearray(record.bytes(source))
                mode = MODES[prefix][cipher](key, record.bytes("IV"))
                if prefix == "OFB":
                    mode.apply_keystream(data)
                else:
                    mode.encrypt(data) if encrypt else mode.decrypt(data)
                assert bytes(data) == record.bytes(target)
            checked += 1
    assert checked >= 60


def test_ctr_follows_sp800_38a_appendix_f5_and_stops_before_repeating():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    initial = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    data = bytearray.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    CTR[AES128](key, initial).apply_keystream(data)
    assert bytes(data) == bytes.fromhex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff")
    ctr = CTR[AES128].with_counter_bits(key, bytes(16), 2)
    assert ctr.remaining_bytes() == 64
    ctr.apply_keystream(bytearray(64))
    with pytest.raises(CryptoError) as error:
        ctr.apply_keystream(bytearray(1))
    assert error.value.name == "LimitExceeded"
    assert CTR[AES128](key, initial).remaining_bytes() is None


def test_xts_follows_the_cavp_vectors():
    checked = 0
    for name in ("XTSGenAES128", "XTSGenAES256"):
        for record in Record.all(f"crypto/mode/xts/{name}.rsp")[:40]:
            if int(record.field("DataUnitLen")) % 8:
                continue
            key = record.bytes("Key")
            tweak = record.bytes("i") if record.get("i") else XTS.tweak_of(int(record.field("DataUnitSeqNumber")))
            encrypt = "ENCRYPT" in record.header
            source, target = ("PT", "CT") if encrypt else ("CT", "PT")
            xts = XTS[AES[len(key) // 2]](key[: len(key) // 2], key[len(key) // 2 :])
            data = bytearray(record.bytes(source))
            xts.encrypt(tweak, data) if encrypt else xts.decrypt(tweak, data)
            assert bytes(data) == record.bytes(target)
            checked += 1
    assert checked > 40
    assert XTS.tweak_of(0x0102) == bytes([2, 1]) + bytes(14)
    with pytest.raises(CryptoError):
        XTS[AES128](bytes(16), bytes(16))
    with pytest.raises(TypeError):
        XTS[DES]


@pytest.mark.parametrize(("path", "ciphers"), [
    ("crypto/mode/cbc/aes_cbc_pkcs5_test.json", AES),
    ("crypto/aria/aria_cbc_pkcs5_test.json", ARIA),
    ("crypto/camellia/camellia_cbc_pkcs5_test.json", CAMELLIA),
])
def test_cbc_with_pkcs7_follows_the_wycheproof_vectors(path, ciphers):
    for _, test in Wycheproof.tests(path):
        key, iv = Wycheproof.bytes(test, "key"), Wycheproof.bytes(test, "iv")
        message, ciphertext = Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "ct")
        cipher = ciphers[len(key)]
        if Wycheproof.valid(test):
            data = bytearray(message)
            PKCS7.pad(data, 16)
            CBC[cipher](key, iv).encrypt(data)
            assert bytes(data) == ciphertext
        data = bytearray(ciphertext)
        try:
            CBC[cipher](key, iv).decrypt(data)
            PKCS7.unpad(data, 16)
            assert Wycheproof.valid(test) and bytes(data) == message
        except CryptoError:
            assert not Wycheproof.valid(test)


def test_modes_need_a_block_cipher_class():
    with pytest.raises(TypeError):
        CBC[SHA256]
    with pytest.raises(TypeError):
        CBC(bytes(16), bytes(16))
    assert CBC[AES128] is CBC[AES128]
    assert CBC[AES128].__name__ == "CBC[AES128]"
    with pytest.raises(CryptoError) as error:
        CBC[AES128](bytes(16), bytes(8))
    assert error.value.name == "NonceLength"
    # A copy continues from the same chaining value.
    cbc = CBC[TDES](bytes(range(24)), bytes(8))
    first, second = bytearray(8), bytearray(8)
    copy = cbc.clone()
    cbc.encrypt(first)
    copy.encrypt(second)
    assert first == second


@pytest.mark.parametrize(
    "file, mode, cipher",
    [
        ("KW_AE_128.txt", KW, AES128), ("KW_AD_256.txt", KW, AES256), ("KWP_AE_192.txt", KWP, AES192),
        ("KWP_AD_128.txt", KWP, AES128), ("TKW_AE.txt", KW, TDES), ("TKW_AD.txt", KW, TDES),
    ],
)  # fmt: skip
def test_key_wrapping_follows_the_kwvs_vectors(file, mode, cipher):
    """SP 800-38F: KW, KWP and TKW against the vectors of NIST KWVS, every fifth record."""
    for record in Record.all(f"crypto/mode/kw/{file}")[::5]:
        state = mode[cipher](record.bytes("K"))
        if record.get("FAIL") is not None:
            with pytest.raises(CryptoError):
                state.unwrap(record.bytes("C"))
            continue
        assert state.wrap(record.bytes("P")) == record.bytes("C")
        assert state.unwrap(record.bytes("C")) == record.bytes("P")


def test_kwp_is_defined_for_128_bit_blocks_only():
    with pytest.raises(Exception):
        KWP[TDES](bytes(24))
