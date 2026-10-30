"""Tests of the MACs and stream ciphers of umilib.crypto against NIST CAVP, the RFCs, the drafts and
Project Wycheproof, in tests/vectors."""

import pytest

from umilib.crypto import CryptoError
from umilib.crypto.aegis import AEGISMAC128L, AEGISMAC128X, AEGISMAC256X
from umilib.crypto.aes import AES128, AES192, AES256
from umilib.crypto.chacha20 import ChaCha20, XChaCha20
from umilib.crypto.cmac import CMAC
from umilib.crypto.des import TDES
from umilib.crypto.poly1305 import Poly1305
from umilib.crypto.rc4 import RC4
from vectors import Record, Wycheproof

AES = {16: AES128, 24: AES192, 32: AES256}


def test_cmac_follows_the_cavp_vectors_and_rfc4493():
    checked = 0
    for file in ("AES128", "AES256", "TDES3"):
        for record in Record.all(f"crypto/cmac/CMACGen{file}.rsp"):
            message = record.bytes("Msg")[: int(record.field("Mlen"))]
            tag_length = int(record.field("Tlen"))
            if file.startswith("AES"):
                cmac = CMAC[AES[len(record.bytes("Key"))]]
                key = record.bytes("Key")
            else:
                cmac = CMAC[TDES]
                key = record.bytes("Key1") + record.bytes("Key2") + record.bytes("Key3")
            assert cmac.mac(key, message)[:tag_length] == record.bytes("Mac")
            state = cmac(key)
            state.update(message)
            assert state.verify_truncated_with_minimum(record.bytes("Mac"), tag_length)
            checked += 1
    assert checked == 288
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert CMAC[AES128].mac(key, b"") == bytes.fromhex("bb1d6929e95937287fa37d129b756746")
    state = CMAC[AES128](key)
    full = state.clone().finalize()
    assert state.clone().verify(full)
    assert state.clone().verify_truncated(full[:8])
    assert not state.verify_truncated(full[:7])


def test_cmac_follows_the_wycheproof_vectors():
    for group, test in Wycheproof.tests("crypto/cmac/aes_cmac_test.json"):
        key = Wycheproof.bytes(test, "key")
        if len(key) not in AES:
            assert not Wycheproof.valid(test)
            continue
        tag = CMAC[AES[len(key)]].mac(key, Wycheproof.bytes(test, "msg"))[: group["tagSize"] // 8]
        assert (tag == Wycheproof.bytes(test, "tag")) == Wycheproof.valid(test), test["tcId"]


def test_poly1305_follows_rfc8439():
    checked = 0
    for record in Record.all("crypto/chacha20/rfc8439.txt"):
        if record.field("Section") != "A.3":
            continue
        key = record.bytes("OneTimeKey") if record.get("OneTimeKey") else bytes.fromhex(record.field("R") + record.field("S"))
        assert Poly1305.mac(key, record.bytes("Text")) == record.bytes("Tag")
        state = Poly1305(key)
        state.update(record.bytes("Text"))
        assert state.verify(record.bytes("Tag"))
        checked += 1
    assert checked == 11


def test_aegis_mac_follows_the_draft():
    checked = 0
    for record in Record.all("crypto/aegis/draft-irtf-cfrg-aegis-aead.txt"):
        group = record.field("Group")
        if not group.startswith("AEGISMAC"):
            continue
        degree = 2 if group.endswith("X2") else 4 if group.endswith("X4") else 1
        family = AEGISMAC128X if group.startswith("AEGISMAC-128") else AEGISMAC256X
        key, nonce, data = record.bytes("key"), record.bytes("nonce"), record.bytes("data")
        assert family[degree, 16].mac(key, nonce, data) == record.bytes("tag128")
        assert family[degree, 32].mac(key, nonce, data) == record.bytes("tag256")
        checked += 1
    assert checked == 6
    assert AEGISMAC128L[16] is AEGISMAC128X[1, 16]


def test_rc4_follows_rfc6229():
    for record in Record.all("crypto/rc4/rfc6229.txt"):
        stream = bytearray(4112)
        RC4(record.bytes("Key")).apply_keystream(stream)
        for name, value in record.fields:
            if name.startswith("Offset"):
                offset = int(name[len("Offset"):])
                assert bytes(stream[offset : offset + 16]) == bytes.fromhex(value)
    with pytest.raises(CryptoError):
        RC4(b"")


def test_chacha20_follows_rfc8439():
    assert ChaCha20.quarter_round([0x11111111, 0x01020304, 0x9B8D6F43, 0x01234567] + [0] * 12, 0, 1, 2, 3)[:4] == [
        0xEA2A92F4,
        0xCB1CF8CE,
        0x4581472E,
        0x5881C4BB,
    ]
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    state = ChaCha20.initial_state(key, 0, bytes.fromhex("000000000001020304050607"))
    assert ChaCha20.block(state)[:32] == bytes.fromhex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")
    rounds = ChaCha20.rounds(state)
    assert ChaCha20.block(state) == b"".join(((a + b) & 0xFFFFFFFF).to_bytes(4, "little") for a, b in zip(rounds, state))
    checked = 0
    for record in Record.all("crypto/chacha20/rfc8439.txt"):
        if record.field("Section") not in ("A.1", "A.2"):
            continue
        if record.field("Section") == "A.1":
            data, expected = bytearray(64), record.bytes("Keystream")
        else:
            data, expected = bytearray(record.bytes("Plaintext")), record.bytes("Ciphertext")
        ChaCha20(record.bytes("Key"), record.bytes("Nonce"), int(record.field("Counter"))).apply_keystream(data)
        assert bytes(data) == expected
        checked += 1
    assert checked == 8
    near_end = ChaCha20(key, bytes(12), 0xFFFFFFFF)
    assert near_end.remaining_bytes() == 64
    with pytest.raises(CryptoError) as error:
        near_end.apply_keystream(bytearray(65))
    assert error.value.name == "LimitExceeded"


def test_xchacha20_follows_the_draft():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    subkey = XChaCha20.hchacha20(key, bytes.fromhex("000000090000004a0000000031415927"))
    assert subkey == bytes.fromhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    for record in Record.all("crypto/chacha20/draft-irtf-cfrg-xchacha.txt"):
        key, nonce = record.bytes("Key"), record.bytes("Nonce")
        if record.field("Section") == "A.1":
            derived, inner = XChaCha20.derive(key, nonce)
            assert inner[:4] == record.bytes("Fixed") and inner[4:] == nonce[16:]
            continue
        counter = int(record.field("Counter"))
        stream = bytearray(len(record.bytes("Plaintext")))
        XChaCha20(key, nonce, counter).apply_keystream(stream)
        assert bytes(stream) == record.bytes("Keystream")
        data = bytearray(record.bytes("Plaintext"))
        XChaCha20.with_64_bit_counter(key, nonce, counter).apply_keystream(data)
        assert bytes(data) == record.bytes("Ciphertext")
