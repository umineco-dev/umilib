"""Tests of umilib.codec.lz77, lz78, lzss and rle: the examples of their specifications (Apple TN1023,
the streams of Okumura's lzss.c) and round trips through the streaming interface."""

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.lz77 import LZ77Compressor, LZ77Config, LZ77Decompressor
from umilib.codec.lz78 import LZ78Compressor, LZ78Config, LZ78Decompressor, LZ78DecompressorConfig
from umilib.codec.lzss import LZSSCompressor, LZSSConfig, LZSSDecompressor
from umilib.codec.rle import PackBitsCompressor, PackBitsDecompressor
from vectors import ROOT

DATA = b"".join(bytes([index % 5 + 97]) * (index % 9) for index in range(3000)) + bytes(range(256)) * 3


def test_packbits_follows_tn1023():
    lines = (ROOT / "codec/rle/tn1023.txt").read_text(encoding="utf-8").splitlines()
    unpacked = bytes.fromhex(lines[0].split(": ")[1])
    packed = bytes.fromhex(lines[1].split(": ")[1])
    assert PackBitsCompressor().compress_to_vec(unpacked) == packed
    assert PackBitsDecompressor().decompress_to_vec(packed, len(unpacked)) == unpacked


def test_lzss_reads_and_writes_the_streams_of_the_reference():
    for suffix, config in (("11-4", LZSSConfig()), ("10-5", LZSSConfig(10, 5))):
        for name in ("text", "binary", "spaces", "one"):
            data = (ROOT / f"codec/lzss/{name}.bin").read_bytes()
            stream = (ROOT / f"codec/lzss/{name}.{suffix}.lzss").read_bytes()
            assert LZSSDecompressor(config).decompress_to_vec(stream, len(data)) == data
            assert LZSSCompressor(config).compress_to_vec(data) == stream
    assert (LZSSConfig().position_bits, LZSSConfig().length_bits) == (11, 4)
    with pytest.raises(CompressionError) as error:
        LZSSCompressor().compress(b"data", bytearray(16), Flush.Sync)
    assert error.value.name == "InvalidParameter"
    with pytest.raises(CompressionError):
        LZSSDecompressor(LZSSConfig(4, 2))


@pytest.mark.parametrize("make", [
    lambda: (LZ77Compressor(), LZ77Decompressor()),
    lambda: (LZ77Compressor(LZ77Config(1)), LZ77Decompressor()),
    lambda: (LZ78Compressor(), LZ78Decompressor()),
    lambda: (LZ78Compressor(LZ78Config(4)), LZ78Decompressor(LZ78DecompressorConfig(4))),
    lambda: (LZSSCompressor(), LZSSDecompressor()),
    lambda: (PackBitsCompressor(), PackBitsDecompressor()),
])
def test_streams_round_trip(make):
    compressor, decompressor = make()
    stream = compressor.compress_to_vec(DATA)
    assert len(stream) < len(DATA)
    assert decompressor.decompress_to_vec(stream, len(DATA)) == DATA
    # In pieces of 7 bytes into outputs of 11, then the end of the input.
    decompressor.reset()
    out, position, output = bytearray(), 0, bytearray(11)
    while True:
        progress = decompressor.decompress(stream[position:position + 7], output)
        position += progress.consumed
        out += output[:progress.produced]
        if progress.finished:
            break
        if progress.consumed == 0 and progress.produced == 0:
            assert position == len(stream)
            decompressor.finish()
            break
    assert bytes(out) == DATA


def test_decompressors_check_their_limits():
    stream = LZ78Compressor(LZ78Config(16)).compress_to_vec(DATA)
    with pytest.raises(CompressionError) as error:
        LZ78Decompressor(LZ78DecompressorConfig(12)).decompress_to_vec(stream, len(DATA))
    assert error.value.name == "LimitExceeded"
    with pytest.raises(CompressionError) as error:
        LZ77Decompressor().decompress_to_vec(LZ77Compressor().compress_to_vec(DATA)[:-1], len(DATA))
    assert error.value.name == "UnexpectedEnd"
    decompressor = PackBitsDecompressor()
    decompressor.decompress(bytes([5, 1]), bytearray(10))
    with pytest.raises(CompressionError) as error:
        decompressor.finish()
    assert error.value.name == "UnexpectedEnd"
