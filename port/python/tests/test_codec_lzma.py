"""Tests of umilib.codec.lzma against Python's lzma module (liblzma), both ways: .lzma files and raw
LZMA2 streams that liblzma makes decompress here, and those made here decompress with liblzma."""

import lzma

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.lzma import (
    LZMA2Compressor,
    LZMA2Decompressor,
    LZMA2DecompressorConfig,
    LZMACompressor,
    LZMAConfig,
    LZMADecompressor,
    LZMADecompressorConfig,
    LZMAFormat,
    LZMAProperties,
)
from vectors import ROOT

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
REPETITIVE = (ROOT / "codec/deflate/repetitive.bin").read_bytes()
RANDOM = (ROOT / "codec/deflate/random.bin").read_bytes()


@pytest.mark.parametrize("level", [0, 3, 6, 9])
def test_lzma_files_interoperate_with_liblzma(level):
    for data in (b"", b"a", TEXT, REPETITIVE, RANDOM):
        stream = LZMACompressor(LZMAConfig(level=level)).compress_to_vec(data)
        assert lzma.decompress(stream, format=lzma.FORMAT_ALONE) == data
        reference = lzma.compress(data, format=lzma.FORMAT_ALONE, preset=level)
        assert LZMADecompressor().decompress_to_vec(reference, len(data)) == data
    properties = LZMAProperties(0, 2, 0)
    stream = LZMACompressor(LZMAConfig(level=5, properties=properties, dictionary_size=1 << 16, uncompressed_size=len(TEXT))).compress_to_vec(TEXT)
    assert lzma.decompress(stream, format=lzma.FORMAT_ALONE) == TEXT
    with pytest.raises(CompressionError) as error:
        LZMADecompressor(LZMADecompressorConfig(1 << 16)).decompress_to_vec(lzma.compress(TEXT, format=lzma.FORMAT_ALONE), len(TEXT))
    assert error.value.name == "LimitExceeded"
    with pytest.raises(CompressionError):
        LZMACompressor().compress(b"data", bytearray(64), Flush.Sync)


@pytest.mark.parametrize("level", [0, 6, 9])
def test_lzma2_streams_interoperate_with_liblzma(level):
    for data in (b"", TEXT, REPETITIVE, RANDOM, RANDOM + TEXT + RANDOM):
        compressor = LZMA2Compressor(LZMAConfig(level=level))
        stream = compressor.compress_to_vec(data)
        filters = [{"id": lzma.FILTER_LZMA2, "dict_size": compressor.dictionary_size()}]
        assert lzma.decompress(stream, format=lzma.FORMAT_RAW, filters=filters) == data
        reference = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": level, "dict_size": 1 << 20}])
        assert LZMA2Decompressor(LZMA2DecompressorConfig(1 << 20)).decompress_to_vec(reference, len(data)) == data
    assert LZMAFormat.lzma2_dictionary_size(22) == 8 << 20


def test_lzma2_sync_flushes_reach_liblzma():
    compressor = LZMA2Compressor(LZMAConfig(dictionary_size=1 << 20))
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    out = bytearray(1 << 20)
    for start in range(0, len(TEXT), 7000):
        piece = TEXT[start:start + 7000]
        progress = compressor.compress(piece, out, Flush.Sync)
        assert progress.consumed == len(piece)
        assert decompressor.decompress(bytes(out[:progress.produced])) == piece
