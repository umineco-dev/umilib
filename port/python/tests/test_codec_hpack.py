"""Tests of umilib.codec.hpack against the examples of RFC 7541 Appendix C and its rules."""

import pytest

from umilib.codec.hpack import HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKEncoderConfig, HPACKError, HPACKField

F = HPACKField

# RFC 7541 C.3 (without Huffman) and C.4 (with Huffman): three requests on one connection.
REQUESTS = [
    [F(b":method", b"GET"), F(b":scheme", b"http"), F(b":path", b"/"), F(b":authority", b"www.example.com")],
    [F(b":method", b"GET"), F(b":scheme", b"http"), F(b":path", b"/"), F(b":authority", b"www.example.com"), F(b"cache-control", b"no-cache")],
    [F(b":method", b"GET"), F(b":scheme", b"https"), F(b":path", b"/index.html"), F(b":authority", b"www.example.com"), F(b"custom-key", b"custom-value")],
]
C3 = ["828684410f7777772e6578616d706c652e636f6d", "828684be58086e6f2d6361636865", "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"]
C4 = ["828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf", "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"]


@pytest.mark.parametrize("blocks", [C3, C4])
def test_the_requests_of_appendix_c(blocks):
    decoder = HPACKDecoder()
    for block, fields in zip(blocks, REQUESTS):
        assert decoder.decode(bytes.fromhex(block)) == fields


def test_the_responses_of_appendix_c_5():
    # RFC 7541 C.5: a table of 256 bytes, whose entries are evicted.
    decoder = HPACKDecoder(HPACKDecoderConfig(maximum_table_size=256))
    first = bytes.fromhex(
        "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d"
    )
    assert decoder.decode(first) == [
        F(b":status", b"302"), F(b"cache-control", b"private"), F(b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        F(b"location", b"https://www.example.com"),
    ]  # fmt: skip
    assert decoder.decode(bytes.fromhex("4803333037c1c0bf")) == [
        F(b":status", b"307"), F(b"cache-control", b"private"), F(b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        F(b"location", b"https://www.example.com"),
    ]  # fmt: skip


@pytest.mark.parametrize("huffman", [False, True])
def test_round_trips(huffman):
    encoder = HPACKEncoder(HPACKEncoderConfig(huffman=huffman))
    decoder = HPACKDecoder()
    for fields in REQUESTS * 2 + [[F(b"authorization", b"secret", sensitive=True)]]:
        assert decoder.decode(encoder.encode(fields)) == fields
    # A field never indexed (RFC 7541 §6.2.3) stays one: its first byte is 0001xxxx.
    block = encoder.encode([F(b"authorization", b"secret", sensitive=True)])
    assert block[0] & 0xF0 == 0x10


def test_table_size_updates():
    # RFC 7541 §4.2: a lower limit must be confirmed by an update at the start of the next block.
    encoder, decoder = HPACKEncoder(limit=4096), HPACKDecoder()
    decoder.set_limit(0)
    with pytest.raises(HPACKError) as error:
        decoder.decode(bytes.fromhex("82"))
    assert error.value.name == "InvalidTableSizeUpdate"
    encoder.set_limit(0)
    block = encoder.encode(REQUESTS[0])
    assert block[0] == 0x20, "a size update to 0"
    assert decoder.decode(block) == REQUESTS[0]


@pytest.mark.parametrize(
    "block, name",
    [
        ("80", "InvalidIndex"),  # index 0 (§6.1)
        ("bf", "InvalidIndex"),  # an empty dynamic table
        ("410f7777", "Truncated"),
        ("ff8080808080808080808080", "IntegerOverflow"),
        ("4185ffffffffff", "InvalidHuffman"),  # EOS (§5.2)
    ],
)
def test_errors(block, name):
    with pytest.raises(HPACKError) as error:
        HPACKDecoder().decode(bytes.fromhex(block))
    assert error.value.name == name


def test_limits():
    decoder = HPACKDecoder(HPACKDecoderConfig(maximum_string_length=4))
    with pytest.raises(HPACKError) as error:
        decoder.decode(bytes.fromhex("410f7777772e6578616d706c652e636f6d"))
    assert error.value.name == "StringTooLong"
    small = HPACKDecoder(HPACKDecoderConfig(maximum_field_list_size=100))
    with pytest.raises(HPACKError) as error:
        small.decode(bytes.fromhex(C3[0]))
    assert error.value.name == "FieldListTooLarge"
    # The block was decoded all the same: the table is in step for the next (RFC 9113 §6.5.2).
    assert small.decode(bytes.fromhex("be")) == [F(b":authority", b"www.example.com")]
