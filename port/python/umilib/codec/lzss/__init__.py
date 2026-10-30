"""LZSS in the format of Haruhiko Okumura's lzss.c. Mirrors ``umilib::codec::lzss``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class LZSSConfig:
    """The parameters EI (``position_bits``) and EJ (``length_bits``), which streams do not record;
    by default those of the reference, 11 and 4."""

    def __init__(self, position_bits: int | None = None, length_bits: int | None = None) -> None:
        defaults = (ctypes.c_uint32(), ctypes.c_uint32())
        Library.default().call("umilib_codec_lzss_lzss_config_default", ctypes.byref(defaults[0]), ctypes.byref(defaults[1]))
        self.position_bits = defaults[0].value if position_bits is None else position_bits
        self.length_bits = defaults[1].value if length_bits is None else length_bits


class LZSSCompressor(Compressor):
    """Compresses into the LZSS format; a sync flush raises ``InvalidParameter``."""

    PREFIX = "umilib_codec_lzss_lzss_compressor"

    def __init__(self, config: LZSSConfig | None = None) -> None:
        config = config or LZSSConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.position_bits, config.length_bits))


class LZSSDecompressor(Decompressor):
    """Decompresses the LZSS format, whose streams end with their input (see ``finish``)."""

    PREFIX = "umilib_codec_lzss_lzss_decompressor"

    def __init__(self, config: LZSSConfig | None = None) -> None:
        config = config or LZSSConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.position_bits, config.length_bits))


__all__ = ["LZSSCompressor", "LZSSConfig", "LZSSDecompressor"]
