"""LZ77: the triples of the original algorithm in a format of umilib. Mirrors ``umilib::codec::lz77``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class LZ77Config:
    """The parameters of an :class:`LZ77Compressor`."""

    def __init__(self, chain_limit: int | None = None) -> None:
        if chain_limit is None:
            chain_limit = Library.default().value("umilib_codec_lz77_lz77_config_default_chain_limit", ctypes.c_size_t)
        #: The most candidates examined for each match (1 or more).
        self.chain_limit = chain_limit


class LZ77Compressor(Compressor):
    """Compresses into the LZ77 format of umilib."""

    PREFIX = "umilib_codec_lz77_lz77_compressor"

    def __init__(self, config: LZ77Config | None = None) -> None:
        config = config or LZ77Config()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.chain_limit))


class LZ77Decompressor(Decompressor):
    """Decompresses the LZ77 format of umilib."""

    PREFIX = "umilib_codec_lz77_lz77_decompressor"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new"))


__all__ = ["LZ77Compressor", "LZ77Config", "LZ77Decompressor"]
