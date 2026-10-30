"""Tests of umilib.hash against Python's hashlib, zlib and binascii, which serve as independent oracles,
and against the official vectors in tests/vectors."""

import binascii
import hashlib
import json
import random
import threading
import zlib
from pathlib import Path

import pytest

from umilib.ffi import FFIError
from umilib.hash import Digest, HashError
from umilib.hash.blake.v2 import (
    BLAKE2b,
    BLAKE2b256,
    BLAKE2b512,
    BLAKE2bParameters,
    BLAKE2bp,
    BLAKE2s,
    BLAKE2s256,
    BLAKE2sParameters,
    BLAKE2Xb,
)
from umilib.hash import CryptographicDigest
from umilib.hash.blake.v3 import BLAKE3
from umilib.hash.crc import CRC, CRCCatalogue, CRCParameters, CRCTable
from umilib.hash.md.v4 import MD4
from umilib.hash.md.v5 import MD5
from umilib.hash.ripemd import RIPEMD160
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256
from umilib.hash.sha.v3 import (
    CSHAKE128,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
    KeccakF1600,
    ParallelHash128,
    TupleHash128,
)
from umilib.hash.siphash import HalfSipHash24, SipHash24, SipHash128_24
from umilib.hash.sm3 import SM3
from umilib.hash.streebog import Streebog256
from umilib.hash.xxhash.xxh3 import XXH3_64, XXH3_128
from umilib.hash.xxhash.xxh32 import XXH32
from umilib.hash.xxhash.xxh64 import XXH64

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors"
GENERATOR = random.Random(20261024)
MESSAGES = [b"", b"abc", bytes(range(256)) * 9] + [GENERATOR.randbytes(length) for length in (1, 55, 56, 63, 64, 127, 128, 129, 1000)]

HASHLIB = [
    (MD5, "md5"),
    (SHA1, "sha1"),
    (SHA224, "sha224"),
    (SHA256, "sha256"),
    (SHA384, "sha384"),
    (SHA512, "sha512"),
    (SHA512_224, "sha512_224"),
    (SHA512_256, "sha512_256"),
    (SHA3_224, "sha3_224"),
    (SHA3_256, "sha3_256"),
    (SHA3_384, "sha3_384"),
    (SHA3_512, "sha3_512"),
    (BLAKE2b512, "blake2b"),
    (BLAKE2s256, "blake2s"),
]


@pytest.mark.parametrize(("digest", "name"), HASHLIB, ids=[name for _, name in HASHLIB])
def test_digests_agree_with_hashlib(digest: type[Digest], name: str):
    if name not in hashlib.algorithms_available:
        pytest.skip(f"hashlib lacks {name}")
    for message in MESSAGES:
        expected = hashlib.new(name, message).digest()
        assert digest.digest(message) == expected
        state = digest()
        for start in range(0, len(message), 37):
            state.update(message[start : start + 37])
        copy = state.clone()
        assert state.finalize_reset() == expected
        state.update(bytearray(message))
        assert state.finalize() == expected
        assert copy.finalize() == expected
    assert digest.OUTPUT_SIZE == hashlib.new(name).digest_size
    assert digest.BLOCK_SIZE == hashlib.new(name).block_size


def test_finalize_releases_the_state():
    state = SHA256()
    state.update(b"abc")
    state.finalize()
    with pytest.raises(FFIError) as error:
        state.update(b"more")
    assert error.value.name == "Closed"


def test_other_digests_follow_their_specifications():
    # RFC 1320, the RIPEMD page, the SM3 draft appendix A and RFC 6986 example 2 (reversed byte order).
    assert MD4.digest(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert RIPEMD160.digest(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert SM3.digest(b"abc").hex() == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    # RFC 6986 writes M1 and its hash with the last byte first.
    expected = bytes.fromhex("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")[::-1]
    assert Streebog256.digest(b"012345678901234567890123456789012345678901234567890123456789012") == expected


def test_shake_and_sp800185_follow_their_specifications():
    for message in MESSAGES:
        assert SHAKE128.digest_xof(message, 100) == hashlib.shake_128(message).digest(100)
        assert SHAKE256.digest_xof(message, 300) == hashlib.shake_256(message).digest(300)
        reader = SHAKE256.new()
        reader.update(message)
        reader = reader.finalize_xof()
        pieces = reader.read(7) + reader.clone().read(13)
        assert pieces == hashlib.shake_256(message).digest(20)
    # cSHAKE with empty name and customization is SHAKE.
    assert CSHAKE128.digest_xof(b"abc", 32) == hashlib.shake_128(b"abc").digest(32)
    # SP 800-185 samples: cSHAKE128 sample 1, TupleHash128 sample 1.
    cshake = CSHAKE128(b"", b"Email Signature")
    cshake.update(bytes([0, 1, 2, 3]))
    assert cshake.finalize_xof().read(32).hex() == "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"
    tuple_hash = TupleHash128()
    tuple_hash.push(bytes([0, 1, 2]))
    tuple_hash.push(bytes(range(0x10, 0x16)))
    assert tuple_hash.finalize(32).hex() == "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1"
    # ParallelHash128 sample 1: blocks of 8 bytes over 00..07 10..17 20..27.
    parallel = ParallelHash128(8)
    parallel.update(bytes([*range(8), *range(0x10, 0x18), *range(0x20, 0x28)]))
    assert parallel.block_size() == 8
    assert parallel.finalize(32).hex() == "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5"
    with pytest.raises(HashError):
        ParallelHash128(0)
    assert KeccakF1600.permute([0] * 25)[0] == 0xF1258F7940E1DDE7


def test_blake2_agrees_with_hashlib_for_every_parameter():
    for message in MESSAGES[:6]:
        for size in (1, 20, 32, 64):
            for key in (b"", b"k" * 17, bytes(64)):
                expected = hashlib.blake2b(message, digest_size=size, key=key).digest()
                state = BLAKE2b.with_key(key, size)
                state.update(message)
                out = bytearray(size)
                state.finalize_into(out)
                assert bytes(out) == expected
        salt, person = b"salt" * 4, b"person" + bytes(10)
        expected = hashlib.blake2b(message, digest_size=48, salt=salt, person=person, fanout=3, depth=7, leaf_size=5, node_offset=9, node_depth=2, inner_size=17).digest()
        parameters = BLAKE2bParameters(48)
        parameters.salt, parameters.personal = salt, person
        parameters.fanout, parameters.depth, parameters.leaf_length = 3, 7, 5
        parameters.node_offset, parameters.node_depth, parameters.inner_length = 9, 2, 17
        assert BLAKE2bParameters.from_bytes(parameters.to_bytes()) == parameters
        state = BLAKE2b.with_parameters(parameters)
        state.update(message)
        out = bytearray(48)
        state.finalize_into(out)
        assert bytes(out) == expected
        expected = hashlib.blake2s(message, digest_size=20, key=b"key", salt=b"12345678").digest()
        parameters = BLAKE2sParameters(20)
        parameters.key_length, parameters.salt = 3, b"12345678"
        state = BLAKE2s.with_parameters(parameters, b"key")
        state.update(message)
        out = bytearray(20)
        state.finalize_into(out)
        assert bytes(out) == expected
    assert BLAKE2b256.with_key(b"key").finalize() == hashlib.blake2b(digest_size=32, key=b"key").digest()
    with pytest.raises(HashError) as error:
        BLAKE2b.new(65)
    assert error.value.name == "OutputLength"


def test_blake2_known_answers():
    entries = json.loads((VECTORS / "hash" / "blake" / "v2" / "blake2-kat.json").read_text())
    for entry in entries[::37]:
        data, key, expected = (bytes.fromhex(entry[name]) for name in ("in", "key", "out"))
        out = bytearray(len(expected))
        if entry["hash"] == "blake2bp":
            state = BLAKE2bp.with_key(key, len(expected))
        elif entry["hash"] == "blake2xb":
            state = BLAKE2Xb.with_key(key, len(expected))
        elif entry["hash"] in ("blake2b", "blake2s"):
            state = (BLAKE2b if entry["hash"] == "blake2b" else BLAKE2s).with_key(key, len(expected))
        else:
            continue
        state.update(data)
        state.finalize_into(out)
        assert bytes(out) == expected, entry


def test_blake3_follows_the_official_vectors():
    document = json.loads((VECTORS / "hash" / "blake" / "v3" / "test_vectors.json").read_text())
    key, context = document["key"].encode(), document["context_string"].encode()
    for case in document["cases"]:
        data = bytes(index % 251 for index in range(case["input_len"]))
        expected = bytes.fromhex(case["hash"])
        assert BLAKE3.digest(data) == expected[:32]
        assert BLAKE3.digest_xof(data, len(expected)) == expected
        keyed = BLAKE3.with_key(key)
        keyed.update(data)
        assert keyed.finalize_xof().read(len(expected)) == bytes.fromhex(case["keyed_hash"])
        assert BLAKE3.keyed_hash(key, data) == bytes.fromhex(case["keyed_hash"])[:32]
        derived = BLAKE3.with_context(context)
        derived.update(data)
        reader = derived.finalize_xof()
        reader.set_position(40)
        assert reader.read(10) == bytes.fromhex(case["derive_key"])[40:50]
        assert reader.position() == 50
        assert BLAKE3.derive_key(context, data) == bytes.fromhex(case["derive_key"])[:32]
    with pytest.raises(HashError):
        BLAKE3.with_key(b"short")


def test_blake2x_reads_node_by_node():
    for size in (1, 64, 65, 200):
        state = BLAKE2Xb.with_key(b"key", size)
        state.update(b"message")
        whole = bytearray(size)
        state.clone().finalize_into(whole)
        reader = state.finalize_xof()
        assert reader.read(size // 2) + reader.read(size - size // 2) == bytes(whole)


def test_siphash_follows_the_reference():
    key = bytes(range(16))
    assert SipHash24.hash(key, bytes(range(15))) == (0xA129CA6149BE45E5).to_bytes(8, "little")
    with pytest.raises(TypeError):
        SipHash24.digest(b"")
    state = SipHash24(key)
    state.update(bytes(range(15)))
    assert state.finish() == 0xA129CA6149BE45E5
    assert SipHash24.KEY_SIZE == 16 and HalfSipHash24.KEY_SIZE == 8 and SipHash128_24.OUTPUT_SIZE == 16
    with pytest.raises(HashError):
        SipHash24(bytes(15))


def test_xxhash_follows_the_reference():
    lines = (VECTORS / "hash" / "xxhash" / "xxhash.txt").read_text().splitlines()
    secrets = {line.split()[1]: bytes.fromhex(line.split()[2]) for line in lines if line.startswith("secret ")}
    state, data = 0x9E3779B9, bytearray()
    for _ in range(12000):
        state = (state * 1664525 + 1013904223) % (1 << 32)
        data.append(state >> 24)
    for line in lines[::7]:
        if line.startswith(("#", "secret")):
            continue
        function, length, key, _, value = line.split()
        if int(length) > len(data):
            continue
        message = bytes(data[: int(length)])
        if function == "xxh32":
            assert XXH32.hash(int(key, 16), message) == int(value, 16)
        elif function == "xxh64":
            assert XXH64.hash(int(key, 16), message) == int(value, 16)
        else:
            kind = XXH3_64 if function == "xxh3_64" else XXH3_128
            hasher = kind.with_secret(secrets[key]) if key in secrets else kind.with_seed(int(key, 16))
            hasher.update(message)
            assert hasher.value() == int(value, 16), line
            assert hasher.finalize() == int(value, 16).to_bytes(kind.OUTPUT_SIZE, "big")
    assert XXH3_128.hash(0, b"") == 0x99AA06D3014798D86001C324468D497F
    with pytest.raises(HashError):
        XXH3_64.with_secret(bytes(135))


def test_crc_agrees_with_zlib_and_binascii():
    for message in MESSAGES:
        assert CRC.checksum(CRCCatalogue.CRC32_ISO_HDLC, message) == zlib.crc32(message)
        assert CRC.checksum(CRCCatalogue.CRC16_XMODEM, message) == binascii.crc_hqx(message, 0)
    assert CRCCatalogue.CRC32_ISO_HDLC is CRCCatalogue.CRC32_ISO_HDLC
    names = CRCCatalogue.names()
    assert len(names) == 113 and "CRC-82/DARC" in names
    for name in names:
        table = CRCCatalogue.find(name)
        parameters = table.parameters()
        assert parameters.name == name
        assert CRC.checksum(table, b"123456789") == parameters.check
    custom = CRCTable(CRCParameters("", 82, 0x0308C0111011401440411, 0, True, True, 0, 0x09EA83F625023801FD612, 0))
    state = CRC(custom)
    # The computation has its own copy of the table.
    custom.close()
    state.update(b"1234")
    state.update(b"56789")
    assert state.value() == 0x09EA83F625023801FD612
    with pytest.raises(HashError):
        CRCTable(CRCParameters("", 0, 0, 0, False, False, 0, 0, 0))
    # A wrong check value is a mistyped algorithm.
    with pytest.raises(HashError):
        CRCTable(CRCParameters("", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0x12345678, 0))
    with pytest.raises(OverflowError):
        CRCTable(CRCParameters("", (1 << 32) + 8, 7, 0, False, False, 0, 0, 0))
    with CRCCatalogue.find("CRC-16/ARC") as table:
        crc = CRC(table)
    crc.update(b"123456789")
    assert crc.value() == 0xBB3D
    with pytest.raises(FFIError):
        CRCCatalogue.find("CRC-1/NONE")


def test_hash_states_can_be_shared_by_threads():
    state = SHA256()
    def work() -> None:
        for _ in range(200):
            state.update(b"x")
    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert state.finalize() == hashlib.sha256(b"x" * 800).digest()


def test_ascon_hashes_follow_the_reference_known_answers():
    from umilib.hash.ascon import AsconCXOF128, AsconHash256, AsconPermutation, AsconXOF128
    from vectors import Record

    for record in Record.all("hash/ascon/LWC_HASH_KAT_128_256.txt")[::13]:
        message = record.bytes("Msg")
        assert AsconHash256.digest(message) == record.bytes("MD")
        state = AsconHash256()
        state.update(message[:3])
        state.update(message[3:])
        assert state.finalize() == record.bytes("MD")
    for record in Record.all("hash/ascon/LWC_XOF_KAT_128_512.txt")[::13]:
        expected = record.bytes("MD")
        assert AsconXOF128.digest_xof(record.bytes("Msg"), len(expected)) == expected
        state = AsconXOF128()
        state.update(record.bytes("Msg"))
        reader = state.finalize_xof()
        assert reader.read(7) + reader.read(len(expected) - 7) == expected
    for record in Record.all("hash/ascon/LWC_CXOF_KAT_128_512.txt")[::13]:
        expected = record.bytes("MD")
        state = AsconCXOF128(record.bytes("Z"))
        state.update(record.bytes("Msg"))
        assert state.finalize_xof().read(len(expected)) == expected
    with pytest.raises(HashError):
        AsconCXOF128(bytes(257))
    # Table 12 of SP 800-232: Ascon-p[12] of the IV of Ascon-Hash256 and zeros.
    assert AsconPermutation.permute([0x0000_0801_00CC_0002, 0, 0, 0, 0], 12) == [
        0x9B1E5494E934D681,
        0x4BC3A01E333751D2,
        0xAE65396C6B34B81A,
        0x3C7FD4A4D56A4DB3,
        0x1A5C464906C5976D,
    ]


def test_adler32_follows_rfc1950():
    import zlib

    from umilib.hash.adler32 import Adler32

    assert Adler32.digest(b"") == (1).to_bytes(4, "big")
    data = bytes(range(256)) * 300
    assert Adler32.digest(data) == zlib.adler32(data).to_bytes(4, "big")
