"""LZ4: the block format and the frame format. Mirrors ``umilib::codec::lz4``."""

from __future__ import annotations

import ctypes
import enum

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Bytes, Handle, Library


class LZ4BlockSize(enum.IntEnum):
    """The block maximum sizes of a frame, valued as their codes in the frame format."""

    Maximum64KiB = 4
    Maximum256KiB = 5
    Maximum1MiB = 6
    Maximum4MiB = 7


class LZ4Block:
    """The block format: blocks carry no sizes."""

    @staticmethod
    def compress(data: bytes, level: int = 1) -> bytes:
        """The block of ``data`` with no history, encoded at ``level`` (0 to 12)."""
        pointer, length = Bytes.readable(data)
        return Library.default().output("umilib_codec_lz4_lz4_block_compress", pointer, length, level)

    @staticmethod
    def decompress(block: bytes, limit: int) -> bytes:
        """The data of the whole ``block``, of at most ``limit`` bytes."""
        pointer, length = Bytes.readable(block)
        return Library.default().output("umilib_codec_lz4_lz4_block_decompress", pointer, length, limit)


class LZ4Defaults:
    """The defaults of the configurations, read from the library."""

    @staticmethod
    def read() -> tuple:
        values = (ctypes.c_uint32(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_bool(), ctypes.c_bool(), ctypes.c_size_t(), ctypes.c_bool())
        Library.default().call("umilib_codec_lz4_lz4_config_defaults", *(ctypes.byref(value) for value in values))
        return tuple(value.value for value in values)


class LZ4Config:
    """The parameters of an :class:`LZ4Compressor`."""

    def __init__(self, level: int | None = None, block_size: LZ4BlockSize | None = None, independent_blocks: bool | None = None,
                 block_checksum: bool | None = None, content_checksum: bool | None = None, content_size: int | None = None,
                 dictionary: bytes | None = None, dictionary_identifier: int | None = None) -> None:
        defaults = LZ4Defaults.read()
        self.level = defaults[0] if level is None else level
        self.block_size = LZ4BlockSize(defaults[1]) if block_size is None else block_size
        self.independent_blocks = defaults[2] if independent_blocks is None else independent_blocks
        self.block_checksum = defaults[3] if block_checksum is None else block_checksum
        self.content_checksum = defaults[4] if content_checksum is None else content_checksum
        self.content_size = content_size
        self.dictionary = dictionary
        self.dictionary_identifier = dictionary_identifier


class LZ4DecompressorConfig:
    """The limits of an :class:`LZ4Decompressor`."""

    def __init__(self, maximum_block_size: int | None = None, multiple_frames: bool | None = None,
                 dictionary: bytes | None = None, dictionary_identifier: int | None = None) -> None:
        defaults = LZ4Defaults.read()
        self.maximum_block_size = defaults[5] if maximum_block_size is None else maximum_block_size
        self.multiple_frames = defaults[6] if multiple_frames is None else multiple_frames
        self.dictionary = dictionary
        self.dictionary_identifier = dictionary_identifier


class LZ4Compressor(Compressor):
    """Compresses into an LZ4 frame."""

    PREFIX = "umilib_codec_lz4_lz4_compressor"

    def __init__(self, config: LZ4Config | None = None) -> None:
        config = config or LZ4Config()
        dictionary, length = Bytes.readable(config.dictionary) if config.dictionary is not None else (None, 0)
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.level, int(config.block_size), config.independent_blocks, config.block_checksum,
            config.content_checksum, config.content_size is not None, config.content_size or 0, dictionary, length,
            config.dictionary_identifier is not None, config.dictionary_identifier or 0,
        ))


class LZ4Decompressor(Decompressor):
    """Decompresses LZ4 frames (by default a series of frames ending with the input)."""

    PREFIX = "umilib_codec_lz4_lz4_decompressor"

    def __init__(self, config: LZ4DecompressorConfig | None = None) -> None:
        config = config or LZ4DecompressorConfig()
        dictionary, length = Bytes.readable(config.dictionary) if config.dictionary is not None else (None, 0)
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.maximum_block_size, config.multiple_frames, dictionary, length,
            config.dictionary_identifier is not None, config.dictionary_identifier or 0,
        ))


__all__ = ["LZ4Block", "LZ4BlockSize", "LZ4Compressor", "LZ4Config", "LZ4Decompressor", "LZ4DecompressorConfig"]
