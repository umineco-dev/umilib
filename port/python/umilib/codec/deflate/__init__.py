"""Deflate (RFC 1951): raw streams. Mirrors ``umilib::codec::deflate``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Bytes, Handle, Library


class DeflateConfig:
    """The parameters of a :class:`DeflateCompressor`: ``level`` 0 to 9 and ``window_bits`` 8 to 15."""

    def __init__(self, level: int | None = None, window_bits: int | None = None) -> None:
        defaults = (ctypes.c_uint32(), ctypes.c_uint32())
        Library.default().call("umilib_codec_deflate_deflate_config_default", ctypes.byref(defaults[0]), ctypes.byref(defaults[1]))
        self.level = defaults[0].value if level is None else level
        self.window_bits = defaults[1].value if window_bits is None else window_bits


class DeflateDecompressorConfig:
    """The limits of a :class:`DeflateDecompressor`: the window kept, 2^``window_bits`` bytes (8 to 15)."""

    def __init__(self, window_bits: int = 15) -> None:
        self.window_bits = window_bits


class DeflateCompressor(Compressor):
    """Compresses into raw Deflate streams."""

    PREFIX = "umilib_codec_deflate_deflate_compressor"

    def __init__(self, config: DeflateConfig | None = None) -> None:
        config = config or DeflateConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.level, config.window_bits))

    def set_dictionary(self, dictionary: bytes | bytearray | memoryview) -> None:
        """Makes ``dictionary`` the history before the data, before the first compression."""
        data, length = Bytes.readable(dictionary)
        self.library.call(f"{self.PREFIX}_set_dictionary", self.handle, data, length)


class DeflateDecompressor(Decompressor):
    """Decompresses raw Deflate streams."""

    PREFIX = "umilib_codec_deflate_deflate_decompressor"

    def __init__(self, config: DeflateDecompressorConfig | None = None) -> None:
        config = config or DeflateDecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.window_bits))

    def set_dictionary(self, dictionary: bytes | bytearray | memoryview) -> None:
        """Makes ``dictionary`` the history before the data, before the first decompression."""
        data, length = Bytes.readable(dictionary)
        self.library.call(f"{self.PREFIX}_set_dictionary", self.handle, data, length)

    def resume(self) -> None:
        """After the last block (BFINAL), goes on with the blocks that follow at the next byte, the
        history kept (RFC 7692 §7.2.1)."""
        self.library.call(f"{self.PREFIX}_resume", self.handle)


__all__ = ["DeflateCompressor", "DeflateConfig", "DeflateDecompressor", "DeflateDecompressorConfig"]
