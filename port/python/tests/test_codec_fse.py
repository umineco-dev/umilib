"""Tests of umilib.codec.fse: the decoding tables of RFC 8878 Appendix A, table descriptions, and the inverse
relation of the encoding and decoding tables (section 4.1)."""

import pytest

from umilib.codec import CompressionError
from umilib.codec.fse import FSEDecodingTable, FSEDistribution, FSEEncodingTable
from umilib.ffi import FFIError

# Section 3.1.1.3.2.2.3: the predefined distribution of the offset codes.
OFFSETS = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]


def test_decoding_tables_follow_appendix_a():
    distribution = FSEDistribution(5, OFFSETS)
    assert distribution.accuracy_log == 5
    assert distribution.probabilities == OFFSETS
    table = FSEDecodingTable(distribution)
    assert table.accuracy_log == 5
    # Appendix A.3: states 0 to 3, 6 and 31 (symbol, number of bits, base).
    assert [table.entry(state) for state in (0, 1, 2, 3, 6, 31)] == [
        (0, 5, 0), (6, 4, 0), (9, 5, 0), (15, 5, 0), (7, 4, 0), (24, 5, 0),
    ]
    assert distribution.spread()[31] == 24
    with pytest.raises(FFIError) as error:
        table.entry(32)
    assert error.value.name == "InvalidArgument"
    assert FSEDecodingTable.single(7).entry(0) == (7, 0, 0)


def test_descriptions_round_trip_and_refuse_invalid_ones():
    distribution = FSEDistribution.normalize([10, 0, 0, 0, 0, 3, 1, 50], 6)
    total = sum(1 if probability == -1 else probability for probability in distribution.probabilities)
    assert total == 64
    description = distribution.write()
    read, used = FSEDistribution.read(description + b"\xaa", 9, 256)
    assert used == len(description)
    assert read.probabilities == distribution.probabilities
    with pytest.raises(CompressionError) as error:
        FSEDistribution.read(description[:1], 9, 256)
    assert error.value.name == "InvalidData"
    with pytest.raises(CompressionError) as error:
        FSEDistribution(5, [16, 15])
    assert error.value.name == "InvalidParameter"
    with pytest.raises(CompressionError) as error:
        FSEDistribution.normalize([0, 7], 5)
    assert error.value.name == "InvalidParameter"


def test_encoding_tables_invert_decoding_tables():
    distribution = FSEDistribution(5, OFFSETS)
    decoding, encoding = FSEDecodingTable(distribution), FSEEncodingTable(distribution)
    assert encoding.accuracy_log == 5
    for symbol, probability in enumerate(OFFSETS):
        assert decoding.entry(encoding.initial_state(symbol) - 32)[0] == symbol
        for state in range(32, 64):
            bits, previous = encoding.transition(state, symbol)
            entry_symbol, entry_bits, baseline = decoding.entry(previous - 32)
            assert (entry_symbol, entry_bits) == (symbol, bits)
            assert baseline + (state & ((1 << bits) - 1)) == state - 32
