"""Tests of umilib.codec.asn1, with the examples of ITU-T X.690."""

import re
import ssl
from pathlib import Path

import pytest

from umilib.codec.asn1 import ASN1Error, ASN1Integer, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag, TagClass
from umilib.codec.asn1.ber import BERReader
from umilib.codec.asn1.der import DERReader, DERWriter

RFC = (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "codec" / "pem" / "rfc7468.txt").read_text(encoding="utf-8")


def test_sequence_example_of_section_8_9():
    writer = DERWriter()

    def fields(inner):
        inner.write_ia5_string("Smith")
        inner.write_boolean(True)

    writer.write_sequence(fields)
    data = writer.into_bytes()
    assert data == bytes([0x30, 0x0A, 0x16, 0x05]) + b"Smith" + bytes([0x01, 0x01, 0xFF])
    sequence = DERReader(data).read_sequence()
    assert sequence.read_ia5_string() == "Smith" and sequence.read_boolean() is True
    sequence.finish()


def test_tagging_examples_of_section_8_14():
    writer = DERWriter()
    writer.write_explicit(2, lambda inner: inner.write_element(Tag.application(3, False), b"Jones"))
    assert writer.as_bytes() == bytes([0xA2, 0x07, 0x43, 0x05]) + b"Jones"
    reader = DERReader(writer.as_bytes()).read_explicit(2)
    assert reader.read_expected(Tag.application(3, False)).as_visible_string() == "Jones"


def test_integers_and_identifiers():
    for value, content in [(0, b"\x00"), (128, b"\x00\x80"), (-129, b"\xff\x7f"), (256, b"\x01\x00")]:
        assert ASN1Integer.encode_i128(value) == content
        assert ASN1Integer(content).as_i128() == value
    with pytest.raises(ASN1Error):
        ASN1Integer(b"\x00\x7f")
    assert ASN1Integer(b"\x00\xc0\x01").magnitude() == b"\xc0\x01"
    oid = ObjectIdentifier.from_arcs([2, 999, 3])
    assert oid.as_bytes() == b"\x88\x37\x03" and str(oid) == "2.999.3" and oid.arcs() == [2, 999, 3]
    assert ObjectIdentifier.parse("1.2.840.113549") == ObjectIdentifier.new(b"\x2a\x86\x48\x86\xf7\x0d")
    with pytest.raises(ASN1Error):
        ObjectIdentifier.parse("1.40")


def test_bit_strings_and_ber():
    bits = DERReader(bytes([0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0])).read_bit_string()
    assert (bits.unused_bits(), bits.bit_length(), bits.bit(4)) == (4, 44, True)
    constructed = bytes([0x23, 0x80, 0x03, 0x03, 0x00, 0x0A, 0x3B, 0x03, 0x05, 0x04, 0x5F, 0x29, 0x1C, 0xD0, 0x00, 0x00])
    element = BERReader(constructed).read_element()
    assert element.indefinite and element.as_bit_string() == bits
    assert BERReader.to_der(constructed) == bytes([0x03, 0x07, 0x04, 0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0])
    with pytest.raises(ASN1Error) as error:
        DERReader(bytes([0x01, 0x01, 0x01])).read_boolean()
    assert error.value.name == "NonCanonical"
    assert BERReader(bytes([0x01, 0x01, 0x01])).read_element().as_boolean() is True
    assert BitString(4, b"\x0f").with_zero_padding().data == b"\x00"
    assert BERReader.is_string_type(4) and not BERReader.is_string_type(16)


def test_times_and_strings():
    time = ASN1Time.new(1985, 11, 6, 21, 6, 27, 300_000_000)
    assert time.encode_generalized_time() == b"19851106210627.3Z"
    assert ASN1Time.decode_generalized_time(b"19851106210627.3Z") == time
    assert ASN1Time.decode_utc_time_ber(b"9105062345-0700") == ASN1Time(1991, 5, 7, 6, 45)
    with pytest.raises(ASN1Error):
        ASN1Time.new(2023, 2, 29, 0, 0, 0, 0)
    assert ASN1Time.is_leap_year(2000) and not ASN1Time.is_leap_year(1900)
    assert ASN1Time.days_in_month(2024, 2) == 29
    assert ASN1Time.from_unix_seconds(951868800) == ASN1Time(2000, 3, 1)
    assert ASN1Time(2000, 3, 1).to_unix_seconds() == 951868800
    assert ASN1String.is_printable(b"A b") and not ASN1String.is_printable(b"a@b")
    assert ASN1String.decode_bmp(ASN1String.encode_bmp("Aあ")) == "Aあ"
    writer = DERWriter()
    with pytest.raises(ASN1Error):
        writer.write_printable_string("a@b")


def test_set_of_is_sorted():
    writer = DERWriter()

    def components(inner):
        for value in (3, 1, 256):
            inner.write_integer_i128(value)

    writer.write_set_of(components)
    assert writer.as_bytes() == bytes([0x31, 0x0A, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x01, 0x00])
    assert DERReader.compare_encodings(b"\x02\x01\x03", b"\x02\x01\x01") == 1
    with pytest.raises(ASN1Error):
        DERReader.validate(bytes([0x31, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01]))


def test_certificate_matches_python_ssl():
    pem = re.search(r"-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n", RFC, re.S).group(0)
    der = ssl.PEM_cert_to_DER_cert(pem)
    DERReader.validate(der)
    certificate = DERReader(der).read_sequence()
    tbs = certificate.read_sequence()
    assert tbs.read_explicit(0).read_integer().as_i64() == 2
    assert tbs.read_integer().as_i64() == 0
    assert str(certificate.read_sequence().read_object_identifier()) == "1.2.840.10045.4.3.2"
    assert certificate.read_bit_string().unused_bits() == 0
    certificate.finish()
    element = DERReader(der).peek()
    assert element.tag == Tag.SEQUENCE and element.tag.tag_class == TagClass.Universal and element.encoding == der
    assert Tag.decode(b"\xa3", 0) == (Tag.context(3, True), 1) and Tag.context(3, True).encode() == b"\xa3"
    assert DERWriter.encode_length(256) == b"\x82\x01\x00"
    assert DERReader.decode_length(b"\x81\x05", 0, False) == (5, 2)


def test_set_order_reals_and_times_follow_x690():
    from umilib.codec.asn1 import ASN1Real

    # SET components by tag (section 10.3): [0] constructed before [1] primitive.
    tag_order = bytes([0x31, 0x06, 0xA0, 0x02, 0x05, 0x00, 0x81, 0x00])
    DERReader.validate(tag_order)
    assert BERReader.to_der(bytes([0x31, 0x05, 0x9F, 0x1F, 0x00, 0xA5, 0x00])) == bytes([0x31, 0x05, 0xA5, 0x00, 0x9F, 0x1F, 0x00])
    assert Tag.context(0, True).compare_order(Tag.context(1, False)) == -1
    assert Tag.REAL == Tag.universal(9, False) and Tag.RELATIVE_OID.number == 13
    with pytest.raises(ASN1Error):
        DERReader.validate(bytes([0x10, 0x00]))
    assert BERReader.must_be_constructed(16) and not BERReader.must_be_constructed(4)
    # REAL (sections 8.5 and 11.3): base 16 becomes base 2, decimal becomes NR3.
    assert ASN1Real.to_der(bytes([0xA0, 0x01, 0x01])) == bytes([0x80, 0x04, 0x01])
    assert ASN1Real.to_der(b"\x021.5") == b"\x0315.E-1"
    ASN1Real.validate_der(bytes([0x80, 0x00, 0x01]))
    with pytest.raises(ASN1Error) as error:
        ASN1Real.validate_der(bytes([0x80, 0x00, 0x04]))
    assert error.value.name == "NonCanonical"
    ObjectIdentifier.validate_subidentifiers(bytes([0xC2, 0x7B, 0x03, 0x02]))
    with pytest.raises(ASN1Error):
        ObjectIdentifier.validate_subidentifiers(bytes([0x80, 0x01]))
    # GeneralizedTime fractions are kept exactly.
    assert ASN1Time.generalized_time_ber_to_der(b"2024010112.5Z") == b"20240101123000Z"
    assert ASN1Time.generalized_time_ber_to_der(b"20240101000000.00000000010Z") == b"20240101000000.0000000001Z"
    with pytest.raises(ASN1Error) as error:
        ASN1Time.decode_generalized_time(b"20240101000000.0000000001Z")
    assert error.value.name == "OutOfRange"
    element = DERReader(bytes([0x0D, 0x02, 0x80, 0x01])).read_element()
    with pytest.raises(ASN1Error):
        DERReader.validate_shallow(element)
