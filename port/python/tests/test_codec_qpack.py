"""Tests of umilib.codec.qpack against the examples of RFC 9204 Appendix B and its rules."""

import pytest

from umilib.codec.hpack import HPACKField
from umilib.codec.qpack import QPACKDecoder, QPACKDecoderConfig, QPACKEncoder, QPACKEncoderConfig, QPACKError

F = HPACKField


def test_a_literal_with_a_static_name_of_appendix_b_1():
    # RFC 9204 B.1: Required Insert Count 0, a literal of the static name :path.
    assert QPACKDecoder().decode(0, bytes.fromhex("0000510b2f696e6465782e68746d6c")).fields == [F(b":path", b"/index.html")]


def test_the_dynamic_table_of_appendix_b_2():
    # RFC 9204 B.2: the encoder stream sets the capacity and inserts two entries; the section refers to them.
    decoder = QPACKDecoder(QPACKDecoderConfig(maximum_table_capacity=220))
    section = bytes.fromhex("03811011")
    assert decoder.decode(4, section).blocked, "the entries have not arrived"
    decoder.receive_encoder_stream(bytes.fromhex("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468"))
    decoded = decoder.decode(4, section)
    assert decoded.fields == [F(b":authority", b"www.example.com"), F(b":path", b"/sample/path")]
    # A Section Acknowledgment of stream 4 (RFC 9204 §4.4.1), after an Insert Count Increment of the
    # two entries or none, as the decoder chooses (§2.2.2.3).
    assert decoder.take_instructions() in (bytes.fromhex("84"), bytes.fromhex("0284"))


def test_an_encoder_and_a_decoder():
    encoder = QPACKEncoder(QPACKEncoderConfig(maximum_table_capacity=4096))
    decoder = QPACKDecoder()
    encoder.set_peer_settings(4096, 16)
    fields = [F(b":method", b"GET"), F(b":authority", b"example.com"), F(b"x-custom", b"value"), F(b"cookie", b"a=b", sensitive=True)]
    for stream in (0, 4, 8):
        section = encoder.encode(stream, fields)
        decoder.receive_encoder_stream(encoder.take_instructions())
        decoded = decoder.decode(stream, section)
        assert not decoded.blocked and decoded.fields == fields
        encoder.receive_decoder_stream(decoder.take_instructions())


def test_errors():
    with pytest.raises(QPACKError) as error:
        QPACKDecoder().decode(0, bytes.fromhex("0000ff"))
    assert error.value.name == "DecompressionFailed"
    with pytest.raises(QPACKError) as error:
        # A capacity above the decoder's maximum (RFC 9204 §4.3.1).
        QPACKDecoder(QPACKDecoderConfig(maximum_table_capacity=0)).receive_encoder_stream(bytes.fromhex("3fbd01"))
    assert error.value.name == "EncoderStream"
    with pytest.raises(QPACKError) as error:
        # An Insert Count Increment of 0 (RFC 9204 §4.4.3).
        QPACKEncoder().receive_decoder_stream(bytes.fromhex("00"))
    assert error.value.name == "DecoderStream"
