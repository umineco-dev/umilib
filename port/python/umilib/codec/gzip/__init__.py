"""gzip (RFC 1952): files of members. Mirrors ``umilib::codec::gzip``."""

from __future__ import annotations

import ctypes
import dataclasses

from umilib.codec import Compressor, Decompressor
from umilib.codec.deflate import DeflateConfig, DeflateDecompressorConfig
from umilib.ffi import Buffer, Bytes, Handle, Library


@dataclasses.dataclass
class GzipHeader:
    """The header of a gzip member."""

    text: bool = False
    modification_time: int = 0
    extra_flags: int = 0
    operating_system: int = 255
    extra: bytes | None = None
    name: bytes | None = None
    comment: bytes | None = None
    header_checksum: bool = False


@dataclasses.dataclass
class GzipConfig:
    """The parameters of a :class:`GzipCompressor`."""

    deflate: DeflateConfig = dataclasses.field(default_factory=DeflateConfig)
    header: GzipHeader = dataclasses.field(default_factory=GzipHeader)


class GzipDecompressorConfig:
    """The limits of a :class:`GzipDecompressor`: the members, the longest field and the window
    of the Deflate data (2^``deflate.window_bits`` bytes)."""

    def __init__(
        self, multiple_members: bool | None = None, maximum_field: int | None = None, deflate: DeflateDecompressorConfig | None = None,
    ) -> None:
        defaults = (ctypes.c_bool(), ctypes.c_size_t(), ctypes.c_uint32())
        Library.default().call("umilib_codec_gzip_gzip_decompressor_config_default", *(ctypes.byref(default) for default in defaults))
        self.multiple_members = defaults[0].value if multiple_members is None else multiple_members
        self.maximum_field = defaults[1].value if maximum_field is None else maximum_field
        self.deflate = DeflateDecompressorConfig(defaults[2].value) if deflate is None else deflate


class GzipCompressor(Compressor):
    """Compresses into a gzip member."""

    PREFIX = "umilib_codec_gzip_gzip_compressor"

    def __init__(self, config: GzipConfig | None = None) -> None:
        config = config or GzipConfig()
        header = config.header
        fields = [Bytes.readable(field) if field is not None else (None, 0) for field in (header.extra, header.name, header.comment)]
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.deflate.level, header.modification_time, header.operating_system, header.text,
            header.header_checksum, *fields[0], *fields[1], *fields[2],
        ))


class GzipDecompressor(Decompressor):
    """Decompresses gzip files (by default of any number of members, ending with the input)."""

    PREFIX = "umilib_codec_gzip_gzip_decompressor"

    def __init__(self, config: GzipDecompressorConfig | None = None) -> None:
        config = config or GzipDecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.multiple_members, config.maximum_field, config.deflate.window_bits))

    def header(self) -> GzipHeader:
        """The header of the member being read, or of the last one."""
        text, time, extra_flags, system, checksum, members = (ctypes.c_bool(), ctypes.c_uint32(), ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_size_t())
        self.library.call(f"{self.PREFIX}_header", self.handle, *(ctypes.byref(value) for value in (text, time, extra_flags, system, checksum, members)))
        fields = [self.library.optional(f"{self.PREFIX}_header_field", Buffer, self.handle, field) for field in range(3)]
        return GzipHeader(text.value, time.value, extra_flags.value, system.value, fields[0], fields[1], fields[2], checksum.value)

    def members(self) -> int:
        """The number of members read completely."""
        values = (ctypes.c_bool(), ctypes.c_uint32(), ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_size_t())
        self.library.call(f"{self.PREFIX}_header", self.handle, *(ctypes.byref(value) for value in values))
        return values[5].value


__all__ = ["GzipCompressor", "GzipConfig", "GzipDecompressor", "GzipDecompressorConfig", "GzipHeader"]
