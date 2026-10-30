"""Tests of the AEADs of umilib.crypto against the Project Wycheproof vectors in tests/vectors: GCM, CCM,
GCM-SIV and SIV over the ciphers C can name, ChaCha20-Poly1305, XChaCha20-Poly1305, AEGIS and
Ascon-AEAD128."""

import pytest

from umilib.crypto import CryptoError
from umilib.crypto.aegis import AEGIS128L, AEGIS128X, AEGIS128XState, AEGIS256, AEGIS256X
from umilib.crypto.aes import AES128, AES192, AES256
from umilib.crypto.aria import ARIA128, ARIA192, ARIA256
from umilib.crypto.ascon import AsconAEAD128
from umilib.crypto.camellia import Camellia128, Camellia192, Camellia256
from umilib.crypto.chacha20poly1305 import ChaCha20Poly1305, XChaCha20Poly1305
from umilib.crypto.des import DES
from umilib.crypto.mode.ccm import CCM
from umilib.crypto.mode.gcm import GCM
from umilib.crypto.mode.gcmsiv import GCMSIV
from umilib.crypto.mode.siv import SIV
from umilib.crypto.seed import SEED
from umilib.crypto.sm4 import SM4
from vectors import Wycheproof

FAMILIES = {
    "aes": {16: AES128, 24: AES192, 32: AES256},
    "aria": {16: ARIA128, 24: ARIA192, 32: ARIA256},
    "camellia": {16: Camellia128, 24: Camellia192, 32: Camellia256},
    "seed": {16: SEED},
    "sm4": {16: SM4},
}


def check(path: str, create, zeroes: bool = False) -> int:
    """Runs the Wycheproof AEAD file ``path`` with the AEAD ``create`` makes for a group and a test
    (``None`` if it refuses them); a failed decryption leaves the ciphertext, or zeros for AEGIS."""
    count = 0
    for group, test in Wycheproof.tests(path):
        count += 1
        iv, aad = Wycheproof.bytes(test, "iv"), Wycheproof.bytes(test, "aad")
        message, ciphertext, tag = Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "ct"), Wycheproof.bytes(test, "tag")
        try:
            aead = create(group, test)
        except (CryptoError, TypeError):
            assert not Wycheproof.valid(test), test["tcId"]
            continue
        buffer = bytearray(ciphertext)
        try:
            aead.decrypt_in_place(iv, aad, buffer, tag)
            assert Wycheproof.valid(test), test["tcId"]
            assert bytes(buffer) == message
            sealed = bytearray(message)
            assert aead.encrypt_in_place(iv, aad, sealed) == tag
            assert bytes(sealed) == ciphertext
        except CryptoError as error:
            assert not Wycheproof.valid(test), (test["tcId"], error.name)
            if error.name == "AuthenticationFailed":
                assert bytes(buffer) == (bytes(len(buffer)) if zeroes else ciphertext)
    return count


@pytest.mark.parametrize(("path", "family"), [
    ("crypto/mode/gcm/aes_gcm_test.json", "aes"),
    ("crypto/aria/aria_gcm_test.json", "aria"),
    ("crypto/seed/seed_gcm_test.json", "seed"),
    ("crypto/sm4/sm4_gcm_test.json", "sm4"),
])
def test_gcm_follows_the_wycheproof_vectors(path, family):
    def create(group, test):
        cipher = FAMILIES[family].get(len(Wycheproof.bytes(test, "key")))
        if cipher is None:
            raise TypeError("no cipher with this key size")
        return GCM[cipher, group["tagSize"] // 8](Wycheproof.bytes(test, "key"))

    assert check(path, create) > 50


@pytest.mark.parametrize(("path", "family"), [
    ("crypto/mode/ccm/aes_ccm_test.json", "aes"),
    ("crypto/aria/aria_ccm_test.json", "aria"),
    ("crypto/camellia/camellia_ccm_test.json", "camellia"),
    ("crypto/seed/seed_ccm_test.json", "seed"),
    ("crypto/sm4/sm4_ccm_test.json", "sm4"),
])
def test_ccm_follows_the_wycheproof_vectors(path, family):
    def create(group, test):
        cipher = FAMILIES[family].get(len(Wycheproof.bytes(test, "key")))
        if cipher is None:
            raise TypeError("no cipher with this key size")
        return CCM[cipher, group["tagSize"] // 8](Wycheproof.bytes(test, "key"))

    assert check(path, create) > 50


def test_gcmsiv_and_siv_follow_the_wycheproof_vectors():
    def gcmsiv(group, test):
        key = Wycheproof.bytes(test, "key")
        if len(key) not in FAMILIES["aes"]:
            raise TypeError("no cipher with this key size")
        return GCMSIV[FAMILIES["aes"][len(key)]](key)

    assert check("crypto/mode/gcmsiv/aes_gcm_siv_test.json", gcmsiv) == 202

    def siv(group, test):
        key = Wycheproof.bytes(test, "key")
        half = len(key) // 2
        if len(key) % 2 or half not in FAMILIES["aes"]:
            raise TypeError("no cipher with this key size")
        return SIV[FAMILIES["aes"][half]](key[:half], key[half:])

    assert check("crypto/mode/siv/aead_aes_siv_cmac_test.json", siv) == 900
    # The deterministic form: V followed by the ciphertext, with the associated data as one component.
    for group, test in Wycheproof.tests("crypto/mode/siv/aes_siv_cmac_test.json"):
        key, aad = Wycheproof.bytes(test, "key"), Wycheproof.bytes(test, "aad")
        message, sealed = Wycheproof.bytes(test, "msg"), Wycheproof.bytes(test, "ct")
        try:
            state = siv(group, test)
        except TypeError:
            assert not Wycheproof.valid(test)
            continue
        if len(sealed) < 16:
            assert not Wycheproof.valid(test)
            continue
        buffer = bytearray(sealed[16:])
        try:
            state.decrypt_vector_in_place([aad], buffer, sealed[:16])
            assert Wycheproof.valid(test) and bytes(buffer) == message
            buffer = bytearray(message)
            assert state.encrypt_vector_in_place([aad], buffer) + bytes(buffer) == sealed
        except CryptoError:
            assert not Wycheproof.valid(test)
    state = SIV[AES128](bytes(16), bytes([1]) * 16)
    assert state.decrypt(b"n", b"a", state.encrypt(b"n", b"a", b"plaintext")) == b"plaintext"
    with pytest.raises(CryptoError) as error:
        state.encrypt_vector_in_place([b""] * 127, bytearray(4))
    assert error.value.name == "InvalidParameter"


@pytest.mark.parametrize(("path", "aead", "count"), [
    ("crypto/chacha20poly1305/chacha20_poly1305_test.json", ChaCha20Poly1305, 325),
    ("crypto/chacha20poly1305/xchacha20_poly1305_test.json", XChaCha20Poly1305, 315),
])
def test_chacha20_poly1305_follows_the_wycheproof_vectors(path, aead, count):
    assert check(path, lambda group, test: aead(Wycheproof.bytes(test, "key"))) == count


def test_aegis_follows_the_wycheproof_vectors_and_its_draft():
    assert check("crypto/aegis/aegis128L_test.json", lambda group, test: AEGIS128L[group["tagSize"] // 8](Wycheproof.bytes(test, "key")), True) == 479
    assert check("crypto/aegis/aegis256_test.json", lambda group, test: AEGIS256[group["tagSize"] // 8](Wycheproof.bytes(test, "key")), True) == 472
    assert AEGIS128L[16] is AEGIS128X[1, 16]
    # Section 7: the key stream is the encryption of zeros.
    key, nonce = bytes([3]) * 16, bytes([4]) * 16
    assert AEGIS128XState[2].stream(key, nonce, 100) == AEGIS128X[2, 16](key).encrypt(nonce, b"", bytes(100))[:100]
    with pytest.raises(TypeError):
        AEGIS256X[3, 16]
    with pytest.raises(TypeError):
        AEGIS128X[1, 24]


def test_ascon_aead128_follows_the_wycheproof_vectors():
    count = check(
        "crypto/ascon/ascon_sp800_232_aead128_test.json",
        lambda group, test: AsconAEAD128[group["tagSize"] // 8](Wycheproof.bytes(test, "key")),
    )
    assert count == 252
    with pytest.raises(TypeError):
        AsconAEAD128[3]
    sealed = AsconAEAD128[8](bytes(16), bytes([9]) * 16).encrypt(bytes(16), b"", b"message")
    assert len(sealed) == 7 + 8


def test_aeads_check_their_choices():
    with pytest.raises(TypeError):
        GCM[DES]
    with pytest.raises(TypeError):
        GCM[AES128, 5]
    gcm = GCM[AES128](bytes(16))
    assert (gcm.nonce_size(), gcm.tag_size()) == (12, 16)
    sealed = gcm.encrypt(bytes(12), b"aad", b"data")
    assert gcm.clone().decrypt(bytes(12), b"aad", sealed) == b"data"
    with pytest.raises(CryptoError) as error:
        gcm.decrypt(bytes(12), b"other", sealed)
    assert error.value.name == "AuthenticationFailed"
    with pytest.raises(CryptoError) as error:
        gcm.decrypt(bytes(12), b"aad", b"short")
    assert error.value.name == "InputLength"


def test_subscripts_take_classes_and_integers_once():
    from array import array

    from umilib.crypto import MAC
    from umilib.crypto.aegis import AEGISMAC128X
    from umilib.crypto.chacha20 import ChaCha20
    from umilib.crypto.hmac import HMAC
    from umilib.crypto.random import HMACDRBG
    from umilib.hash.sha.v2 import SHA256, SHA512

    # Sizes are integers, as the constant parameters of Rust: 16.0 and True are not 16 and 1.
    for subscript in (lambda: GCM[AES128, 16.0], lambda: AsconAEAD128[16.0], lambda: AEGIS128X[True, 16], lambda: CCM[AES128]):
        with pytest.raises(TypeError):
            subscript()
    assert GCM[AES128] is GCM[AES128, 16]
    assert GCM[AES128].__module__ == "umilib.crypto.mode.gcm"
    # A specialized class cannot be specialized again.
    for subscript in (lambda: GCM[AES128][AES128], lambda: HMACDRBG[SHA256][SHA512], lambda: HMAC[SHA256][SHA512]):
        with pytest.raises(TypeError):
            subscript()
    with pytest.raises(TypeError):
        GCM[(AES128,)]
    # The Rust types are distinct: no type is a subclass of another family's.
    assert not issubclass(XChaCha20Poly1305, ChaCha20Poly1305)
    assert not issubclass(AEGIS256X, AEGIS128X)
    assert not issubclass(AEGISMAC128X[1, 16], AEGIS128X)
    assert isinstance(HMAC[SHA256](b"key"), MAC) and HMAC[SHA256](b"key").output_size() == 32
    # In place operations take buffers of bytes, by their length in bytes.
    key, nonce = bytes(32), bytes(12)
    words = array("I", [1, 2, 3, 4])
    view = memoryview(words)
    with pytest.raises(TypeError):
        ChaCha20(key, nonce).apply_keystream(view)
    data = bytearray(view.cast("B"))
    ChaCha20(key, nonce).apply_keystream(view.cast("B"))
    ChaCha20(key, nonce).apply_keystream(data)
    assert bytes(view.cast("B")) == bytes(data) != bytes(array("I", [1, 2, 3, 4]))
    with pytest.raises(TypeError):
        ChaCha20(key, nonce).apply_keystream(b"")
    # A key in a memoryview of wider items is read as its bytes.
    assert HMAC[SHA256].mac(memoryview(array("I", [7] * 8)), b"m") == HMAC[SHA256].mac(bytes(array("I", [7] * 8)), b"m")
    # Words are checked, not wrapped.
    with pytest.raises(OverflowError):
        ChaCha20.rounds([2**32] + [0] * 15)
    with pytest.raises(OverflowError):
        ChaCha20.rounds([-1] + [0] * 15)
