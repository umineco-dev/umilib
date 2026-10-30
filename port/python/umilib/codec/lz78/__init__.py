"""LZ78: the pairs of the original algorithm in a format of umilib. Mirrors ``umilib::codec::lz78``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class LZ78Config:
    """The parameters of an :class:`LZ78Compressor`."""

    def __init__(self, dictionary_bits: int | None = None) -> None:
        defaults = (ctypes.c_uint32(), ctypes.c_uint32())
        Library.default().call("umilib_codec_lz78_lz78_config_defaults", ctypes.byref(defaults[0]), ctypes.byref(defaults[1]))
        #: The base-2 logarithm of the most phrases of the dictionary (1 to 24).
        self.dictionary_bits = defaults[0].value if dictionary_bits is None else dictionary_bits


class LZ78DecompressorConfig:
    """The limits of an :class:`LZ78Decompressor`."""

    def __init__(self, maximum_dictionary_bits: int | None = None) -> None:
        defaults = (ctypes.c_uint32(), ctypes.c_uint32())
        Library.default().call("umilib_codec_lz78_lz78_config_defaults", ctypes.byref(defaults[0]), ctypes.byref(defaults[1]))
        #: The largest dictionary a stream may ask for, as a base-2 logarithm.
        self.maximum_dictionary_bits = defaults[1].value if maximum_dictionary_bits is None else maximum_dictionary_bits


class LZ78Compressor(Compressor):
    """Compresses into the LZ78 format of umilib."""

    PREFIX = "umilib_codec_lz78_lz78_compressor"

    def __init__(self, config: LZ78Config | None = None) -> None:
        config = config or LZ78Config()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.dictionary_bits))


class LZ78Decompressor(Decompressor):
    """Decompresses the LZ78 format of umilib."""

    PREFIX = "umilib_codec_lz78_lz78_decompressor"

    def __init__(self, config: LZ78DecompressorConfig | None = None) -> None:
        config = config or LZ78DecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.maximum_dictionary_bits))


__all__ = ["LZ78Compressor", "LZ78Config", "LZ78Decompressor", "LZ78DecompressorConfig"]
