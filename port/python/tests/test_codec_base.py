"""Tests of umilib.codec.base: the RFC 4648 vectors, and agreement with the
independent implementations in Python's standard ``base64`` module."""

import base64
import random
from pathlib import Path

import pytest

from umilib.codec.base import Alphabet, AlphabetRange, BaseError, BitEncoding, Padding
from umilib.ffi import FFIError
from umilib.codec.base.base16 import Base16
from umilib.codec.base.base32 import Base32
from umilib.codec.base.base58 import Base58
from umilib.codec.base.base64 import Base64
from umilib.codec.base.base85 import Base85

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors" / "codec" / "base"


def rfc4648(name: str) -> list[tuple[bytes, str]]:
    prefix = f'{name}("'
    vectors = []
    for line in (VECTORS / "rfc4648.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(prefix):
            data, text = line[len(prefix):].split('") = "')
            vectors.append((data.encode(), text.rstrip('"')))
    return vectors


@pytest.mark.parametrize(("name", "encoding"), [("BASE16", "Base16.UPPER"), ("BASE32", "Base32.STANDARD"), ("BASE32-HEX", "Base32.HEX"), ("BASE64", "Base64.STANDARD")])
def test_rfc4648_vectors(name, encoding):
    encoding = eval(encoding)  # noqa: S307 - names from the parameter list above
    vectors = rfc4648(name)
    assert len(vectors) == 7
    for data, text in vectors:
        assert encoding.encode(data) == text
        assert encoding.decode(text) == data


def test_agreement_with_the_standard_library():
    generator = random.Random(1)
    for length in range(0, 80):
        data = bytes(generator.randrange(256) for _ in range(length))
        assert Base16.UPPER.encode(data) == base64.b16encode(data).decode()
        assert Base32.STANDARD.encode(data) == base64.b32encode(data).decode()
        assert Base32.HEX.encode(data) == base64.b32hexencode(data).decode()
        assert Base64.STANDARD.encode(data) == base64.b64encode(data).decode()
        assert Base64.URL_SAFE.encode(data) == base64.urlsafe_b64encode(data).decode()
        assert Base85.ASCII85.encode(data) == base64.a85encode(data).decode()
        assert Base85.ASCII85_ADOBE.encode(data) == base64.a85encode(data, adobe=True).decode()
        assert Base85.RFC1924.encode(data) == base64.b85encode(data).decode()
        for encoding in (Base16.LOWER, Base32.STANDARD_NO_PADDING, Base64.URL_SAFE_NO_PADDING, Base58.BITCOIN, Base85.ASCII85):
            assert encoding.decode(encoding.encode(data)) == data


def test_errors_are_raised_with_their_variant():
    for text, name in (("Zh==", "NonCanonical"), ("Zg=", "InvalidLength"), ("Zg=a", "InvalidCharacter"), ("Zm9\n", "InvalidCharacter")):
        with pytest.raises(BaseError) as error:
            Base64.STANDARD.decode(text)
        assert error.value.name == name, text
    with pytest.raises(BaseError) as error:
        Base58.BITCOIN.with_maximum_length(2).decode("222")
    assert error.value.name == "InputTooLong"
    with pytest.raises(BaseError) as error:
        Base85.Z85.encode(b"abc")
    assert error.value.name == "InvalidLength"


def test_slices_and_lengths():
    output = bytearray(8)
    assert Base64.STANDARD.encode_to_slice(b"fo", output) == 4
    assert output[:4] == b"Zm8="
    decoded = bytearray(3)
    assert Base64.STANDARD.decode_to_slice(b"Zm8=", decoded) == 2
    assert decoded[:2] == b"fo"
    assert Base64.STANDARD.maximum_encoded_length(3) == 4
    assert Base64.STANDARD.maximum_encoded_length((1 << 64) - 1) is None
    assert Base64.STANDARD.maximum_decoded_length(4) == 3
    assert Base64.STANDARD.try_encode(b"f") == "Zg=="


def test_engine_and_alphabets():
    engine = Base32.STANDARD.encoding
    assert (engine.bits, engine.padding, engine.padding_character) == (5, Padding.Required, ord("="))
    assert (engine.group_characters(), engine.group_bytes()) == (8, 5)
    assert [engine.is_valid_remainder(r) for r in range(8)] == [True, False, True, False, True, True, False, True]
    custom = BitEncoding(Base64.URL_SAFE_ALPHABET, 6, Padding.Forbidden)
    assert custom.encode(bytes([0xFB, 0xFF])) == "-_8"
    assert custom.alphabet == Base64.URL_SAFE_ALPHABET
    assert Base64.new(Base64.STANDARD_ALPHABET, Padding.Indifferent).decode("Zg") == b"f"
    assert Base32.new(Base32.STANDARD_ALPHABET_ANY_CASE, Padding.Required).decode("my======") == b"f"
    assert Base16.new(Base16.UPPER.encoding.alphabet).encode(b"\xab") == "AB"
    alphabet = Base64.STANDARD_ALPHABET
    assert alphabet.size() == 64 and alphabet.encode(63) == ord("/") and alphabet.decode(ord("-")) is None
    assert alphabet.ranges[0] == AlphabetRange.new(ord("A"), 26, 0)
    assert Alphabet.mask_in(5, 3, 4) == 0xFF and Alphabet.mask_in(7, 3, 4) == 0
    assert AlphabetRange.decode_only(1, 2, 3).canonical is False


def test_base58_and_base85_details():
    assert Base58.BITCOIN.encode(bytes([0, 0, 1])) == "112"
    assert Base58.RIPPLE.encode(bytes([0, 0, 1])) == "rrp"
    assert Base58.DEFAULT_MAXIMUM_LENGTH == 4096
    Base58.BITCOIN.check_length(4096)
    with pytest.raises(BaseError):
        Base58.BITCOIN.check_length(4097)
    assert Base85.Z85.encode(bytes([0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B])) == "HelloWorld"
    assert Base85.ASCII85.zero_group == ord("z") and Base85.Z85.zero_group is None
    assert Base85.ASCII85.partial_groups and not Base85.Z85.partial_groups
    assert Base85.ASCII85.ignore_whitespace
    assert Base85.ASCII85_ADOBE.delimiter_lengths() == (2, 2)
    assert Base85.ASCII85.delimiters is None
    assert Base85.WHITESPACE == b" \t\n\x0c\r\x00"


def test_alphabets_of_closed_encodings_are_not_used():
    encoding = Base64.STANDARD.encoding
    alphabet = encoding.alphabet
    assert alphabet.size() == 64 and encoding.is_valid()
    encoding.close()
    with pytest.raises(FFIError) as error:
        alphabet.size()
    assert error.value.name == "Closed"
    with pytest.raises(FFIError):
        Base64.new(alphabet, Padding.Required)
    with pytest.raises(FFIError):
        BitEncoding(Base64.STANDARD_ALPHABET, 6, Padding.Required, ord("A"))
