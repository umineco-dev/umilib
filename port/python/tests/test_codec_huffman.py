"""Tests of umilib.codec.huffman: canonical codes against RFC 1951 section 3.2.2, decoding tables,
Vitter's trees, and the two stream formats through the streaming interface."""

import pytest

from umilib.bytes import BitOrder
from umilib.codec import CompressionError, Flush
from umilib.codec.huffman import HuffmanError
from umilib.codec.huffman.adaptive import AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor, AdaptiveHuffmanTree
from umilib.codec.huffman.canonical import (
    CanonicalHuffmanCompressor,
    CanonicalHuffmanConfig,
    CanonicalHuffmanDecompressor,
    HuffmanCode,
    HuffmanTable,
)

DATA = b"".join(bytes([index % 7 + 97]) * (index % 13) for index in range(2000)) + bytes(range(256))


def test_canonical_codes_follow_rfc1951():
    code = HuffmanCode.from_lengths([3, 3, 3, 3, 3, 2, 4, 4])
    assert [format(code.code(symbol), f"0{code.length(symbol)}b") for symbol in range(8)] == [
        "010", "011", "100", "101", "110", "00", "1110", "1111",
    ]
    assert code.is_complete() and code.maximum_length() == 4 and code.symbols() == 8
    assert code.lengths() == bytes([3, 3, 3, 3, 3, 2, 4, 4])
    assert code.reversed_code(6) == 0b0111
    with pytest.raises(HuffmanError) as error:
        HuffmanCode.from_lengths([1, 1, 1])
    assert error.value.name == "InvalidLengths"
    assert HuffmanCode.lengths_from_frequencies([1, 1, 2], 15) == bytes([2, 2, 1])
    assert HuffmanCode.from_frequencies([5, 0, 5], 15).lengths() == bytes([1, 0, 1])
    table = HuffmanTable(code, BitOrder.MostSignificantFirst)
    assert table.peek_bits() == 4
    assert table.decode(0b1110) == (6, 4)
    assert HuffmanTable(code, BitOrder.LeastSignificantFirst).decode(0b0111) == (6, 4)
    with pytest.raises(HuffmanError) as error:
        HuffmanTable(HuffmanCode.from_lengths([1, 0, 2]), BitOrder.LeastSignificantFirst).decode(0b11)
    assert error.value.name == "InvalidCode"


def test_vitter_trees_code_and_update():
    tree = AdaptiveHuffmanTree(258)
    assert tree.symbols() == 258
    # Before any symbol the code is the index: 4 - 2 in 8 bits, most significant bit first.
    assert tree.code(4) == (0b0100_0000, 8)
    copy = tree.clone()
    tree.update(4)
    # The leaf of 4 is the right child of the root: one bit, 1.
    assert tree.code(4) == (1, 1)
    assert copy.code(4) == (0b0100_0000, 8)
    with pytest.raises(Exception):
        tree.update(258)


def stream(compressor, data: bytes, piece: int, room: int) -> bytes:
    out = bytearray()
    output = bytearray(room)
    for start in range(0, len(data) + 1, piece):
        chunk = data[start:start + piece]
        flush = Flush.Finish if start + piece >= len(data) else Flush.None_
        while True:
            progress = compressor.compress(chunk, output, flush)
            chunk = chunk[progress.consumed:]
            out += output[:progress.produced]
            if progress.finished:
                return bytes(out)
            if not chunk and flush != Flush.Finish and progress.produced < room:
                break
    raise AssertionError("the stream did not finish")


@pytest.mark.parametrize("pair", [
    (lambda: CanonicalHuffmanCompressor(CanonicalHuffmanConfig(100)), CanonicalHuffmanDecompressor),
    (lambda: CanonicalHuffmanCompressor(), CanonicalHuffmanDecompressor),
    (AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor),
])
def test_streams_round_trip(pair):
    compressor, decompressor = pair[0](), pair[1]()
    whole = compressor.compress_to_vec(DATA)
    assert decompressor.decompress_to_vec(whole, len(DATA)) == DATA
    compressor.reset()
    assert stream(compressor, DATA, 333, 17) == whole
    # In pieces, with outputs of 5 bytes, stopping at the end of the stream.
    decompressor.reset()
    out, position, output = bytearray(), 0, bytearray(5)
    extended = whole + b"after"
    while True:
        progress = decompressor.decompress(extended[position:position + 3], output)
        position += progress.consumed
        out += output[:progress.produced]
        if progress.finished:
            break
    assert bytes(out) == DATA and position == len(whole)
    decompressor.reset()
    with pytest.raises(CompressionError) as error:
        decompressor.decompress_to_vec(whole, len(DATA) - 1)
    assert error.value.name == "LimitExceeded"
    decompressor.reset()
    with pytest.raises(CompressionError) as error:
        decompressor.decompress_to_vec(whole[:-1], len(DATA))
    assert error.value.name == "UnexpectedEnd"
    # A copy continues the stream of the original.
    compressor.reset()
    compressor.compress(DATA[:500], bytearray(4096))
    copy = compressor.clone()
    assert copy.compress_to_vec(DATA[500:]) == compressor.compress_to_vec(DATA[500:])


def test_canonical_streams_follow_their_format():
    # An empty stream: the last-block bit, 257 lengths of 4 bits (END alone of length 1), END (0), padding.
    stream_bits = "1" + "0000" * 256 + "1000" + "0"
    stream_bits += "0" * (-len(stream_bits) % 8)
    expected = bytes(int(stream_bits[index:index + 8][::-1], 2) for index in range(0, len(stream_bits), 8))
    assert CanonicalHuffmanCompressor().compress_to_vec(b"") == expected
    assert len(CanonicalHuffmanCompressor().compress_to_vec(DATA)) < len(DATA) * 3 // 4
    assert len(AdaptiveHuffmanCompressor().compress_to_vec(DATA)) < len(DATA) * 3 // 4
    with pytest.raises(CompressionError) as error:
        CanonicalHuffmanCompressor(CanonicalHuffmanConfig(0))
    assert error.value.name == "InvalidParameter"
