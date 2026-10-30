"""Run-length encoding: PackBits. Mirrors ``umilib::codec::rle``."""

from __future__ import annotations

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle


class PackBitsCompressor(Compressor):
    """Compresses into PackBits."""

    PREFIX = "umilib_codec_rle_pack_bits_compressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


class PackBitsDecompressor(Decompressor):
    """Decompresses PackBits, whose streams end with their input (see ``finish``)."""

    PREFIX = "umilib_codec_rle_pack_bits_decompressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


__all__ = ["PackBitsCompressor", "PackBitsDecompressor"]
