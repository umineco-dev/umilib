"""Tests of umilib.codec.deflate, zlib and gzip against Python's zlib and gzip modules, both ways:
what zlib makes decompresses here, and what is made here decompresses with zlib."""

import gzip
import zlib

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.deflate import DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig
from umilib.codec.gzip import GzipCompressor, GzipConfig, GzipDecompressor, GzipDecompressorConfig, GzipHeader
from umilib.codec.zlib import ZlibCompressor, ZlibDecompressor
from vectors import ROOT

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
REPETITIVE = (ROOT / "codec/deflate/repetitive.bin").read_bytes()
DICTIONARY = (ROOT / "codec/deflate/dictionary.bin").read_bytes()


@pytest.mark.parametrize("level", range(10))
def test_deflate_interoperates_with_zlib(level):
    for data in (b"", b"a", TEXT, REPETITIVE):
        stream = DeflateCompressor(DeflateConfig(level)).compress_to_vec(data)
        assert zlib.decompress(stream, -15) == data
        reference = zlib.compressobj(level, zlib.DEFLATED, -15)
        assert DeflateDecompressor().decompress_to_vec(reference.compress(data) + reference.flush(), len(data)) == data
        assert zlib.decompress(ZlibCompressor(DeflateConfig(level)).compress_to_vec(data)) == data
        assert ZlibDecompressor().decompress_to_vec(zlib.compress(data, level), len(data)) == data


def test_sync_flushes_and_dictionaries_interoperate_with_zlib():
    compressor = DeflateCompressor()
    decompressor = zlib.decompressobj(-15)
    out = bytearray(1 << 16)
    for start in range(0, len(TEXT), 5000):
        piece = TEXT[start:start + 5000]
        progress = compressor.compress(piece, out, Flush.Sync)
        assert progress.consumed == len(piece)
        # After a sync flush, zlib recovers everything so far.
        assert decompressor.decompress(bytes(out[:progress.produced])) == piece
    stream = ZlibCompressor(dictionary=DICTIONARY).compress_to_vec(TEXT)
    assert zlib.decompressobj(zdict=DICTIONARY).decompress(stream) == TEXT
    reference = zlib.compressobj(9, zlib.DEFLATED, 15, 9, zlib.Z_DEFAULT_STRATEGY, DICTIONARY)
    stream = reference.compress(TEXT) + reference.flush()
    assert ZlibDecompressor(dictionary=DICTIONARY).decompress_to_vec(stream, len(TEXT)) == TEXT
    with pytest.raises(CompressionError) as error:
        ZlibDecompressor().decompress_to_vec(stream, len(TEXT))
    assert error.value.name == "MissingDictionary"
    small = DeflateCompressor(DeflateConfig(6, 9)).compress_to_vec(REPETITIVE)
    assert DeflateDecompressor(DeflateDecompressorConfig(9)).decompress_to_vec(small, len(REPETITIVE)) == REPETITIVE


def test_gzip_interoperates_with_python():
    header = GzipHeader(text=True, modification_time=1761350400, operating_system=3, extra=b"AB\x02\x00xy", name=b"text.bin", comment=b"made by umilib", header_checksum=True)
    stream = GzipCompressor(GzipConfig(DeflateConfig(9), header)).compress_to_vec(TEXT)
    assert gzip.decompress(stream) == TEXT
    decompressor = GzipDecompressor()
    assert decompressor.decompress_to_vec(stream, len(TEXT)) == TEXT
    read = decompressor.header()
    assert (read.name, read.comment, read.extra, read.modification_time, read.header_checksum) == (header.name, header.comment, header.extra, header.modification_time, True)
    assert decompressor.members() == 1
    two = gzip.compress(TEXT, mtime=0) + gzip.compress(REPETITIVE, 1, mtime=0)
    assert GzipDecompressor().decompress_to_vec(two, len(TEXT) + len(REPETITIVE)) == TEXT + REPETITIVE
    single = GzipDecompressor(GzipDecompressorConfig(multiple_members=False))
    assert single.decompress_to_vec(two, len(TEXT)) == TEXT
    corrupt = bytearray(stream)
    corrupt[-5] ^= 1
    with pytest.raises(CompressionError) as error:
        GzipDecompressor().decompress_to_vec(bytes(corrupt), len(TEXT))
    assert error.value.name == "ChecksumMismatch"


def test_streams_after_the_last_block():
    # Two raw streams of zlib back to back: the second refers to the first's history once resumed.
    first = zlib.compressobj(wbits=-15)
    head = first.compress(b"Hello, Hello") + first.flush()
    from umilib.codec.deflate import DeflateDecompressor

    decompressor = DeflateDecompressor()
    out = bytearray(64)
    progress = decompressor.decompress(head, out)
    assert progress.finished and bytes(out[: progress.produced]) == b"Hello, Hello"
    decompressor.resume()
    progress = decompressor.decompress(bytes.fromhex("f300110000"), out)
    assert progress.finished and bytes(out[: progress.produced]) == b"Hello"
