"""The .xz file format. Mirrors ``umilib::codec::xz``."""

from __future__ import annotations

import ctypes
import dataclasses
import enum

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Handle, Library


class XZCheck(enum.IntEnum):
    """The Check of the Blocks of a Stream (the values are the Check IDs)."""

    None_ = 0x00
    CRC32 = 0x01
    CRC64 = 0x04
    SHA256 = 0x0A


@dataclasses.dataclass(frozen=True)
class XZFilter:
    """A filter of a .xz chain: its Filter ID (0x03 Delta, 0x04 to 0x0B BCJ, 0x21 LZMA2) and its value
    (the distance of Delta, the start offset of BCJ, the dictionary size of LZMA2)."""

    id: int
    value: int = 0

    DELTA = 0x03
    X86 = 0x04
    POWER_PC = 0x05
    IA64 = 0x06
    ARM = 0x07
    ARM_THUMB = 0x08
    SPARC = 0x09
    ARM64 = 0x0A
    RISCV = 0x0B
    LZMA2 = 0x21

    @staticmethod
    def delta(distance: int) -> XZFilter:
        return XZFilter(XZFilter.DELTA, distance)

    @staticmethod
    def bcj(architecture: int, start_offset: int = 0) -> XZFilter:
        """The BCJ filter of ``architecture`` (a :class:`~umilib.codec.filter.bcj.BCJArchitecture`)."""
        return XZFilter(XZFilter.X86 + int(architecture), start_offset)


class XZDefaults:
    @staticmethod
    def read() -> tuple:
        values = (ctypes.c_uint32(), ctypes.c_uint8(), ctypes.c_uint64(), ctypes.c_bool())
        Library.default().call("umilib_codec_xz_xz_config_defaults", *(ctypes.byref(value) for value in values))
        return tuple(value.value for value in values)


class XZConfig:
    """The parameters of an :class:`XZCompressor`: the LZMA2 ``level`` (0 to 9) and ``dictionary_size``
    (``None`` for the level's), the ``check``, the ``filters`` before LZMA2, and the ``block_size``
    (``None`` for one Block)."""

    def __init__(self, level: int | None = None, dictionary_size: int | None = None, check: XZCheck | None = None,
                 filters: list[XZFilter] | None = None, block_size: int | None = None) -> None:
        defaults = XZDefaults.read()
        self.level = defaults[0] if level is None else level
        self.dictionary_size = dictionary_size
        self.check = XZCheck(defaults[1]) if check is None else check
        self.filters = list(filters or [])
        self.block_size = block_size


class XZDecompressorConfig:
    """The limits of an :class:`XZDecompressor`: the largest LZMA2 dictionary, and whether the input
    is a file of Streams (otherwise one Stream)."""

    def __init__(self, maximum_dictionary_size: int | None = None, multiple_streams: bool | None = None) -> None:
        defaults = XZDefaults.read()
        self.maximum_dictionary_size = defaults[2] if maximum_dictionary_size is None else maximum_dictionary_size
        self.multiple_streams = defaults[3] if multiple_streams is None else multiple_streams


class XZCompressor(Compressor):
    """Compresses into a .xz Stream."""

    PREFIX = "umilib_codec_xz_xz_compressor"

    def __init__(self, config: XZConfig | None = None) -> None:
        config = config or XZConfig()
        library = Library.default()
        flags_type = library.type("umilib_codec_xz_XZFilterFlags")
        flags = (flags_type * max(1, len(config.filters)))()
        for index, filter in enumerate(config.filters):
            flags[index].id = filter.id
            flags[index].value = filter.value
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.level, config.dictionary_size or 0, int(config.check), config.block_size or 0,
            flags if config.filters else None, len(config.filters),
        ))


class XZDecompressor(Decompressor):
    """Decompresses .xz files (by default Streams and Stream Padding ending with the input)."""

    PREFIX = "umilib_codec_xz_xz_decompressor"

    def __init__(self, config: XZDecompressorConfig | None = None) -> None:
        config = config or XZDecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.maximum_dictionary_size, config.multiple_streams))

    def streams(self) -> int:
        """The Streams read completely."""
        return self.status()[0]

    def check(self) -> XZCheck:
        """The Check of the current (or last) Stream."""
        return XZCheck(self.status()[1])

    def status(self) -> tuple[int, int]:
        streams, check = ctypes.c_uint64(), ctypes.c_uint8()
        self.library.call("umilib_codec_xz_xz_decompressor_streams", self.handle, ctypes.byref(streams), ctypes.byref(check))
        return streams.value, check.value


__all__ = ["XZCheck", "XZCompressor", "XZConfig", "XZDecompressor", "XZDecompressorConfig", "XZFilter"]
