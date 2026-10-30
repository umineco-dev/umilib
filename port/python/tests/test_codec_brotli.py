"""Tests of umilib.codec.brotli: the streams of the brotli tool, round trips, and (when the brotli
command line utility is installed) both ways with it."""

import shutil
import subprocess

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.brotli import BrotliCompressor, BrotliConfig, BrotliDecompressor, BrotliDecompressorConfig
from vectors import ROOT

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
REPETITIVE = (ROOT / "codec/deflate/repetitive.bin").read_bytes()
RANDOM = (ROOT / "codec/deflate/random.bin").read_bytes()


def test_streams_of_the_brotli_tool_decompress():
    for name, data in (("text.quality11", TEXT), ("text.window10", TEXT), ("repetitive.quality11", REPETITIVE),
                       ("random.quality5", RANDOM), ("empty", b"")):
        stream = (ROOT / f"codec/brotli/{name}.br").read_bytes()
        assert BrotliDecompressor().decompress_to_vec(stream, len(data)) == data


def test_streams_round_trip_and_check_parameters():
    assert BrotliConfig().level == 6 and BrotliConfig().window_bits == 22
    assert BrotliDecompressorConfig().maximum_window_bits == 24
    for level, window_bits in ((0, 10), (5, 16), (11, 24)):
        for data in (b"", b"a", TEXT, REPETITIVE, RANDOM):
            stream = BrotliCompressor(BrotliConfig(level=level, window_bits=window_bits)).compress_to_vec(data)
            assert BrotliDecompressor().decompress_to_vec(stream, len(data)) == data
    for config in (BrotliConfig(level=12), BrotliConfig(window_bits=25)):
        with pytest.raises(CompressionError) as error:
            BrotliCompressor(config)
        assert error.value.name == "InvalidParameter"
    stream = BrotliCompressor(BrotliConfig(window_bits=24)).compress_to_vec(TEXT)
    with pytest.raises(CompressionError) as error:
        BrotliDecompressor(BrotliDecompressorConfig(maximum_window_bits=16)).decompress_to_vec(stream, len(TEXT))
    assert error.value.name == "LimitExceeded"
    # A sync flush makes everything so far decompressible.
    compressor = BrotliCompressor()
    out = bytearray(1 << 16)
    progress = compressor.compress(TEXT, out, Flush.Sync)
    assert progress.consumed == len(TEXT) and not progress.finished
    decompressor = BrotliDecompressor()
    room = bytearray(len(TEXT) + 1)
    result = decompressor.decompress(bytes(out[:progress.produced]), room)
    assert bytes(room[:result.produced]) == TEXT and not result.finished


@pytest.mark.skipif(shutil.which("brotli") is None, reason="the brotli command line utility is not installed")
def test_streams_interoperate_with_the_brotli_tool():
    for data in (b"", b"a", TEXT, REPETITIVE, RANDOM, bytes(200000)):
        for level in (0, 6, 11):
            stream = BrotliCompressor(BrotliConfig(level=level)).compress_to_vec(data)
            assert subprocess.run(["brotli", "-dc"], input=stream, capture_output=True, check=True).stdout == data
        for quality in ("0", "5", "11"):
            theirs = subprocess.run(["brotli", "-c", "-q", quality], input=data, capture_output=True, check=True).stdout
            assert BrotliDecompressor().decompress_to_vec(theirs, len(data)) == data
