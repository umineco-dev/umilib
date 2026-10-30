"""Tests of umilib.codec.lz4: the frames of the lz4 tool, the block format and round trips."""

import pytest

from umilib.codec import CompressionError
from umilib.codec.lz4 import LZ4Block, LZ4BlockSize, LZ4Compressor, LZ4Config, LZ4Decompressor, LZ4DecompressorConfig
from vectors import ROOT

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
RANDOM = (ROOT / "codec/deflate/random.bin").read_bytes()


def test_frames_of_the_lz4_tool():
    for name in ("text.level1", "text.level9", "text.nocrc"):
        assert LZ4Decompressor().decompress_to_vec((ROOT / f"codec/lz4/{name}.lz4").read_bytes(), len(TEXT)) == TEXT
    frames = (ROOT / "codec/lz4/frames.lz4").read_bytes()
    assert LZ4Decompressor().decompress_to_vec(frames, len(TEXT) + len(RANDOM)) == TEXT + RANDOM
    single = LZ4Decompressor(LZ4DecompressorConfig(multiple_frames=False))
    assert single.decompress_to_vec(frames, len(TEXT)) == TEXT
    legacy = (ROOT / "codec/lz4/text.legacy.lz4").read_bytes()
    with pytest.raises(CompressionError) as error:
        LZ4Decompressor().decompress_to_vec(legacy, len(TEXT))
    assert error.value.name == "LimitExceeded"
    assert LZ4Decompressor(LZ4DecompressorConfig(maximum_block_size=8 << 20)).decompress_to_vec(legacy, len(TEXT)) == TEXT


def test_blocks_and_frames_round_trip():
    for level in (0, 1, 9, 12):
        block = LZ4Block.compress(TEXT, level)
        assert LZ4Block.decompress(block, len(TEXT)) == TEXT
    assert LZ4Block.compress(b"") == b"\x00"
    config = LZ4Config(level=9, block_size=LZ4BlockSize.Maximum256KiB, independent_blocks=False, block_checksum=True,
                       content_size=len(TEXT), dictionary=b"the quick brown fox", dictionary_identifier=3)
    stream = LZ4Compressor(config).compress_to_vec(TEXT)
    decompressor = LZ4Decompressor(LZ4DecompressorConfig(dictionary=b"the quick brown fox", dictionary_identifier=3))
    assert decompressor.decompress_to_vec(stream, len(TEXT)) == TEXT
    with pytest.raises(CompressionError) as error:
        LZ4Decompressor().decompress_to_vec(stream, len(TEXT))
    assert error.value.name == "MissingDictionary"
