"""Brotli (RFC 7932). Mirrors ``umilib::codec::brotli``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class BrotliDefaults:
    @staticmethod
    def read() -> tuple:
        values = (ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32())
        Library.default().call("umilib_codec_brotli_brotli_config_defaults", *(ctypes.byref(value) for value in values))
        return tuple(value.value for value in values)


class BrotliConfig:
    """The parameters of a :class:`BrotliCompressor`: ``level`` 0 to 11 and WBITS ``window_bits`` 10 to 24."""

    def __init__(self, level: int | None = None, window_bits: int | None = None) -> None:
        defaults = BrotliDefaults.read()
        self.level = defaults[0] if level is None else level
        self.window_bits = defaults[1] if window_bits is None else window_bits


class BrotliDecompressorConfig:
    """The limits of a :class:`BrotliDecompressor`: the largest WBITS a stream may ask for (10 to 24)."""

    def __init__(self, maximum_window_bits: int | None = None) -> None:
        defaults = BrotliDefaults.read()
        self.maximum_window_bits = defaults[2] if maximum_window_bits is None else maximum_window_bits


class BrotliCompressor(Compressor):
    """Compresses into a Brotli stream."""

    PREFIX = "umilib_codec_brotli_brotli_compressor"

    def __init__(self, config: BrotliConfig | None = None) -> None:
        config = config or BrotliConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.level, config.window_bits))


class BrotliDecompressor(Decompressor):
    """Decompresses a Brotli stream (the input after it is not consumed)."""

    PREFIX = "umilib_codec_brotli_brotli_decompressor"

    def __init__(self, config: BrotliDecompressorConfig | None = None) -> None:
        config = config or BrotliDecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.maximum_window_bits))


__all__ = ["BrotliCompressor", "BrotliConfig", "BrotliDecompressor", "BrotliDecompressorConfig"]
