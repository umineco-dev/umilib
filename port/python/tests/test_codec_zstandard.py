"""Tests of umilib.codec.zstandard against Python's compression.zstd (libzstd), both ways."""

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.zstandard import (
    ZstandardCompressor,
    ZstandardConfig,
    ZstandardDecompressor,
    ZstandardDecompressorConfig,
    ZstandardDictionary,
)
from vectors import ROOT

zstd = pytest.importorskip("compression.zstd")

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
REPETITIVE = (ROOT / "codec/deflate/repetitive.bin").read_bytes()
RANDOM = (ROOT / "codec/deflate/random.bin").read_bytes()


@pytest.mark.parametrize("level", [1, 3, 9, 19])
def test_frames_interoperate_with_libzstd(level):
    for data in (b"", b"a", TEXT, REPETITIVE, RANDOM, bytes(200000)):
        stream = ZstandardCompressor(ZstandardConfig(level=level)).compress_to_vec(data)
        assert zstd.decompress(stream) == data
        assert ZstandardDecompressor().decompress_to_vec(zstd.compress(data, level=level), len(data)) == data


def test_dictionaries_and_flushes_interoperate_with_libzstd():
    trained = (ROOT / "codec/zstandard/dictionary.trained").read_bytes()
    ours = ZstandardDictionary(trained)
    theirs = zstd.ZstdDict(trained)
    assert ours.identifier == theirs.dict_id
    stream = ZstandardCompressor(ZstandardConfig(dictionary=ours)).compress_to_vec(TEXT)
    assert zstd.decompress(stream, zstd_dict=theirs) == TEXT
    reference = zstd.compress(TEXT, zstd_dict=theirs)
    assert ZstandardDecompressor(ZstandardDecompressorConfig(dictionary=ours)).decompress_to_vec(reference, len(TEXT)) == TEXT
    with pytest.raises(CompressionError) as error:
        ZstandardDecompressor().decompress_to_vec(reference, len(TEXT))
    assert error.value.name == "MissingDictionary"
    # After each flush, libzstd recovers everything so far.
    compressor = ZstandardCompressor()
    decompressor = zstd.ZstdDecompressor()
    out = bytearray(1 << 20)
    for start in range(0, len(TEXT), 9000):
        piece = TEXT[start:start + 9000]
        progress = compressor.compress(piece, out, Flush.Sync)
        assert progress.consumed == len(piece)
        assert decompressor.decompress(bytes(out[:progress.produced])) == piece
