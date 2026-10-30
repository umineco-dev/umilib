"""LZMA and LZMA2: .lzma files and raw LZMA2 streams. Mirrors ``umilib::codec::lzma``."""

from __future__ import annotations

import ctypes
import dataclasses

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class LZMADefaults:
    """The defaults of the configurations, read from the library."""

    @staticmethod
    def read() -> tuple:
        values = (ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_size_t(), ctypes.c_size_t())
        Library.default().call("umilib_codec_lzma_lzma_config_defaults", *(ctypes.byref(value) for value in values))
        return tuple(value.value for value in values)


@dataclasses.dataclass
class LZMAProperties:
    """lc, lp and pb."""

    literal_context_bits: int = 3
    literal_position_bits: int = 0
    position_bits: int = 2


@dataclasses.dataclass
class LZMAConfig:
    """The parameters of the compressors: the level 0 to 9, the properties, the dictionary size
    (``None`` for the level's) and, for .lzma files, the size of the data (``None``: an end marker)."""

    level: int = 6
    properties: LZMAProperties = dataclasses.field(default_factory=LZMAProperties)
    dictionary_size: int | None = None
    uncompressed_size: int | None = None


class LZMADecompressorConfig:
    """The limits of an :class:`LZMADecompressor`."""

    def __init__(self, maximum_dictionary_size: int | None = None) -> None:
        self.maximum_dictionary_size = LZMADefaults.read()[4] if maximum_dictionary_size is None else maximum_dictionary_size


class LZMA2DecompressorConfig:
    """The dictionary size of the raw LZMA2 streams an :class:`LZMA2Decompressor` reads."""

    def __init__(self, dictionary_size: int | None = None) -> None:
        self.dictionary_size = LZMADefaults.read()[5] if dictionary_size is None else dictionary_size


class LZMAFormat:
    @staticmethod
    def lzma2_dictionary_size(byte: int) -> int:
        """The dictionary size of the LZMA2 properties byte ``byte`` (0 to 40)."""
        return Library.default().value("umilib_codec_lzma_lzma_format_lzma2_dictionary_size", ctypes.c_uint64, byte)


class LZMACompressor(Compressor):
    """Compresses into .lzma files; a sync flush raises ``InvalidParameter``."""

    PREFIX = "umilib_codec_lzma_lzma_compressor"

    def __init__(self, config: LZMAConfig | None = None) -> None:
        config = config or LZMAConfig()
        properties = config.properties
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.level, properties.literal_context_bits, properties.literal_position_bits,
            properties.position_bits, config.dictionary_size is not None, config.dictionary_size or 0,
            config.uncompressed_size is not None, config.uncompressed_size or 0,
        ))


class LZMADecompressor(Decompressor):
    """Decompresses .lzma files."""

    PREFIX = "umilib_codec_lzma_lzma_decompressor"

    def __init__(self, config: LZMADecompressorConfig | None = None) -> None:
        config = config or LZMADecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.maximum_dictionary_size))


class LZMA2Compressor(Compressor):
    """Compresses into raw LZMA2 streams."""

    PREFIX = "umilib_codec_lzma_lzma2_compressor"

    def __init__(self, config: LZMAConfig | None = None) -> None:
        config = config or LZMAConfig()
        properties = config.properties
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.level, properties.literal_context_bits, properties.literal_position_bits,
            properties.position_bits, config.dictionary_size is not None, config.dictionary_size or 0,
        ))

    def dictionary_size(self) -> int:
        """The dictionary size the decompressor needs."""
        return self.library.value(f"{self.PREFIX}_dictionary_size", ctypes.c_size_t, self.handle)


class LZMA2Decompressor(Decompressor):
    """Decompresses raw LZMA2 streams."""

    PREFIX = "umilib_codec_lzma_lzma2_decompressor"

    def __init__(self, config: LZMA2DecompressorConfig | None = None) -> None:
        config = config or LZMA2DecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.dictionary_size))


__all__ = [
    "LZMA2Compressor", "LZMA2Decompressor", "LZMA2DecompressorConfig", "LZMACompressor", "LZMAConfig",
    "LZMADecompressor", "LZMADecompressorConfig", "LZMAFormat", "LZMAProperties",
]
