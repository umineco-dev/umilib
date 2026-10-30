"""Tests of umilib.codec.pem: the examples of RFC 7468 and the three grammars."""

import ssl
from pathlib import Path

import pytest

from umilib.codec.base import BaseError
from umilib.codec.pem import PEMConfig, PEMDocument, PEMError, PEMLabel, PEMLineEnding, PEMStrictness

RFC = (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "codec" / "pem" / "rfc7468.txt").read_text(encoding="utf-8")


def test_rfc7468_examples():
    documents = PEMDocument.decode_all(RFC)
    assert len(documents) == 14
    assert documents[0].label() == PEMLabel.CERTIFICATE
    for document in documents:
        assert document.data()[0] == 0x30
        assert PEMDocument.decode(document.encode(), PEMConfig(PEMStrictness.Strict)).data() == document.data()
    # Python's ssl module decodes certificates independently.
    first = documents[0].encode()
    assert ssl.PEM_cert_to_DER_cert(first) == documents[0].data()
    assert ssl.DER_cert_to_PEM_cert(documents[0].data()).replace("\n", "") == first.replace("\n", "")


def test_grammars_and_errors():
    short = "-----BEGIN X-----\nAQID\nBAUG\n-----END X-----\n"
    with pytest.raises(PEMError) as error:
        PEMDocument.decode(short, PEMConfig(PEMStrictness.Strict))
    assert error.value.name == "InvalidLine"
    assert PEMDocument.decode(short).data() == bytes([1, 2, 3, 4, 5, 6])
    assert PEMDocument.decode("-----BEGIN X-----AQ ID-----END X-----", PEMConfig(PEMStrictness.Lax)).data() == bytes([1, 2, 3])
    with pytest.raises(PEMError) as error:
        PEMDocument.decode("-----BEGIN A-----\nAQ==\n-----END B-----\n")
    assert error.value.name == "LabelMismatch"
    assert PEMDocument.decode("-----BEGIN A-----\nAQ==\n-----END B-----\n", PEMConfig(require_matching_label=False)).data() == b"\x01"
    with pytest.raises(BaseError):
        PEMDocument.decode("-----BEGIN X-----\nBB==\n-----END X-----\n")
    with pytest.raises(PEMError) as error:
        PEMDocument.decode("nothing")
    assert error.value.name == "NotFound"


def test_documents_and_settings():
    document = PEMDocument.new(PEMLabel.PRIVATE_KEY, bytearray(range(70)))
    assert document.encode().splitlines()[1] == document.encode().splitlines()[1][:64]
    assert "\r\n" in document.encode_with(PEMLineEnding.CRLF)
    assert PEMLineEnding.CRLF.as_str() == "\r\n"
    data = document.into_data()
    assert data == bytearray(range(70)) and document.pointer is None
    with pytest.raises(PEMError):
        PEMDocument.new("A--B", b"")
    assert PEMLabel.is_valid("X.509 CERTIFICATE") and not PEMLabel.is_valid("-A")
    config = PEMConfig(maximum_length=10)
    assert config.settings() == (PEMStrictness.Standard, True, 10)
    config.strictness = PEMStrictness.Lax
    assert config.strictness == PEMStrictness.Lax and config.maximum_length == 10
    with pytest.raises(PEMError) as error:
        PEMDocument.decode("-----BEGIN X-----\n-----END X-----\n", config)
    assert error.value.name == "TooLong"
    found = PEMDocument.decode_next("x\n-----BEGIN A-----\nAQ==\n-----END A-----\nrest", 0)
    assert found is not None and found[0].label() == "A" and found[1] == len("x\n-----BEGIN A-----\nAQ==\n-----END A-----\n")
    assert PEMDocument.decode_next("rest", 0) is None
