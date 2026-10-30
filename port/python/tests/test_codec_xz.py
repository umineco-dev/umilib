"""Tests of umilib.codec.xz and umilib.codec.filter against Python's lzma module (liblzma), both ways."""

import lzma
import shutil
import subprocess

import pytest

from umilib.codec import CompressionError, Flush
from umilib.codec.filter import FilterChain
from umilib.codec.filter.bcj import BCJArchitecture, BCJFilter
from umilib.codec.filter.delta import DeltaFilter
from umilib.codec.xz import XZCheck, XZCompressor, XZConfig, XZDecompressor, XZDecompressorConfig, XZFilter
from vectors import ROOT

TEXT = (ROOT / "codec/deflate/text.bin").read_bytes()
RANDOM = (ROOT / "codec/deflate/random.bin").read_bytes()
BCJ = (ROOT / "codec/xz/bcj.bin").read_bytes()

# The BCJ filters of Python's lzma module (ARM64 and RISC-V only in newer versions).
PYTHON_BCJ = {
    BCJArchitecture.X86: "FILTER_X86",
    BCJArchitecture.PowerPC: "FILTER_POWERPC",
    BCJArchitecture.IA64: "FILTER_IA64",
    BCJArchitecture.ARM: "FILTER_ARM",
    BCJArchitecture.ARMThumb: "FILTER_ARMTHUMB",
    BCJArchitecture.SPARC: "FILTER_SPARC",
}

CHECKS = {XZCheck.None_: lzma.CHECK_NONE, XZCheck.CRC32: lzma.CHECK_CRC32, XZCheck.CRC64: lzma.CHECK_CRC64,
          XZCheck.SHA256: lzma.CHECK_SHA256}


@pytest.mark.parametrize("check", list(XZCheck))
def test_streams_interoperate_with_liblzma(check):
    for data in (b"", b"a", TEXT, RANDOM, bytes(100000)):
        stream = XZCompressor(XZConfig(check=check)).compress_to_vec(data)
        assert lzma.decompress(stream, format=lzma.FORMAT_XZ) == data
        theirs = lzma.compress(data, format=lzma.FORMAT_XZ, check=CHECKS[check])
        decompressor = XZDecompressor()
        assert decompressor.decompress_to_vec(theirs, len(data)) == data
        assert decompressor.check() == check and decompressor.streams() == 1


@pytest.mark.parametrize("architecture", list(PYTHON_BCJ))
def test_bcj_filters_interoperate_with_liblzma(architecture):
    python_filter = getattr(lzma, PYTHON_BCJ[architecture])
    alignment = architecture.alignment
    for start_offset in (0, alignment * 1024):
        config = XZConfig(filters=[XZFilter.delta(3), XZFilter.bcj(architecture, start_offset)], block_size=5000)
        stream = XZCompressor(config).compress_to_vec(BCJ)
        assert lzma.decompress(stream, format=lzma.FORMAT_XZ) == BCJ
        filters = [{"id": lzma.FILTER_DELTA, "dist": 3}, {"id": python_filter, "start_offset": start_offset},
                   {"id": lzma.FILTER_LZMA2, "preset": 6}]
        theirs = lzma.compress(BCJ, format=lzma.FORMAT_XZ, filters=filters)
        assert XZDecompressor().decompress_to_vec(theirs, len(BCJ)) == BCJ


@pytest.mark.skipif(shutil.which("xz") is None, reason="the xz command line utility is not installed")
def test_arm64_and_riscv_filters_interoperate_with_xz():
    for architecture, option in ((BCJArchitecture.ARM64, "--arm64"), (BCJArchitecture.RISCV, "--riscv")):
        for start_offset in (0, architecture.alignment * 2048):
            config = XZConfig(filters=[XZFilter.bcj(architecture, start_offset)])
            stream = XZCompressor(config).compress_to_vec(BCJ)
            assert subprocess.run(["xz", "-dc"], input=stream, capture_output=True, check=True).stdout == BCJ
            command = ["xz", "-c", "-T1", f"{option}=start={start_offset}", "--lzma2"]
            theirs = subprocess.run(command, input=BCJ, capture_output=True, check=True).stdout
            assert XZDecompressor().decompress_to_vec(theirs, len(BCJ)) == BCJ


def test_filters_convert_in_place():
    for architecture in BCJArchitecture:
        data = bytearray(BCJ)
        encoder = BCJFilter(architecture, architecture.alignment * 4)
        assert encoder.architecture == architecture and encoder.start_offset == architecture.alignment * 4
        done = encoder.encode(data)
        assert len(data) - done <= encoder.lookahead and data != bytearray(BCJ)
        assert BCJFilter(architecture, architecture.alignment * 4).decode(data) == done
        assert data == bytearray(BCJ)
    delta = DeltaFilter(1)
    data = bytearray([5, 7, 7, 1])
    assert delta.encode(data) == 4 and data == bytearray([5, 2, 0, 0xFA])
    with pytest.raises(CompressionError) as error:
        DeltaFilter(0)
    assert error.value.name == "InvalidParameter"
    with pytest.raises(CompressionError):
        BCJFilter(BCJArchitecture.ARM, 2)
    # A chain encodes in order and decodes in reverse.
    chain = FilterChain([DeltaFilter(2), BCJFilter(BCJArchitecture.X86)])
    encoded = bytearray()
    for start in range(0, len(BCJ), 1000):
        chain.extend(BCJ[start:start + 1000])
        chain.encode(False)
        ready = chain.ready()
        encoded.extend(ready)
        chain.consume(len(ready))
    chain.encode(True)
    encoded.extend(chain.ready())
    chain = FilterChain([DeltaFilter(2), BCJFilter(BCJArchitecture.X86)])
    chain.extend(encoded)
    chain.decode(True)
    assert chain.ready() == BCJ


def test_streams_check_their_fields_and_limits():
    stream = XZCompressor().compress_to_vec(TEXT)
    corrupt = bytearray(stream)
    corrupt[-20] ^= 1
    with pytest.raises(CompressionError):
        XZDecompressor().decompress_to_vec(bytes(corrupt), len(TEXT))
    theirs = lzma.compress(TEXT, format=lzma.FORMAT_XZ, preset=9)
    with pytest.raises(CompressionError) as error:
        XZDecompressor(XZDecompressorConfig(maximum_dictionary_size=1 << 20)).decompress_to_vec(theirs, len(TEXT))
    assert error.value.name == "LimitExceeded"
    unsupported = (ROOT / "codec/xz/xz-utils/unsupported-check.xz").read_bytes()
    with pytest.raises(CompressionError) as error:
        XZDecompressor().decompress_to_vec(unsupported, 100)
    assert error.value.name == "Unsupported"
    # Two Streams with padding; one Stream leaves what follows.
    double = theirs + bytes(4) + XZCompressor().compress_to_vec(b"more")
    decompressor = XZDecompressor()
    assert decompressor.decompress_to_vec(double, len(TEXT) + 4) == TEXT + b"more"
    assert decompressor.streams() == 2
    single = XZDecompressor(XZDecompressorConfig(multiple_streams=False))
    out = bytearray(len(TEXT) + 10)
    progress = single.decompress(double, out)
    assert progress.finished and progress.consumed == len(theirs)
    # A sync flush makes the data so far decodable by liblzma's streaming decoder.
    for filters in ([], [XZFilter.bcj(BCJArchitecture.X86)]):
        compressor = XZCompressor(XZConfig(filters=filters))
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        output = bytearray(1 << 16)
        recovered = b""
        for start in range(0, len(TEXT), 7000):
            piece = TEXT[start:start + 7000]
            progress = compressor.compress(piece, output, Flush.Sync)
            assert progress.consumed == len(piece)
            recovered += decoder.decompress(bytes(output[:progress.produced]))
            assert recovered == TEXT[:start + len(piece)]
    with pytest.raises(CompressionError) as error:
        XZCompressor(XZConfig(filters=[XZFilter(XZFilter.LZMA2, 1 << 20)]))
    assert error.value.name == "InvalidParameter"
