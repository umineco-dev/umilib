"""Zstandard (RFC 8878). Mirrors ``umilib::codec::zstandard``."""

from __future__ import annotations

import ctypes

from umilib.codec import Compressor, Decompressor
from umilib.ffi import Bytes, Handle, Library


class ZstandardDefaults:
    @staticmethod
    def read() -> tuple:
        values = (ctypes.c_uint32(), ctypes.c_bool(), ctypes.c_uint64(), ctypes.c_bool())
        Library.default().call("umilib_codec_zstandard_zstandard_config_defaults", *(ctypes.byref(value) for value in values))
        return tuple(value.value for value in values)


class ZstandardDictionary(Handle):
    """A dictionary: formatted (with an identifier and tables) or raw content."""

    FREE = "umilib_codec_zstandard_zstandard_dictionary_free"

    def __init__(self, data: bytes) -> None:
        pointer, length = Bytes.readable(data)
        super().__init__(Handle.create("umilib_codec_zstandard_zstandard_dictionary_new", pointer, length))

    @property
    def identifier(self) -> int:
        """The identifier; 0 for raw content."""
        return self.library.value("umilib_codec_zstandard_zstandard_dictionary_identifier", ctypes.c_uint32, self.handle)


class ZstandardConfig:
    """The parameters of a :class:`ZstandardCompressor`."""

    def __init__(self, level: int | None = None, window_log: int | None = None, content_checksum: bool | None = None,
                 content_size: int | None = None, dictionary: ZstandardDictionary | None = None) -> None:
        defaults = ZstandardDefaults.read()
        self.level = defaults[0] if level is None else level
        self.window_log = window_log
        self.content_checksum = defaults[1] if content_checksum is None else content_checksum
        self.content_size = content_size
        self.dictionary = dictionary


class ZstandardDecompressorConfig:
    """The limits of a :class:`ZstandardDecompressor`."""

    def __init__(self, maximum_window: int | None = None, multiple_frames: bool | None = None,
                 dictionary: ZstandardDictionary | None = None) -> None:
        defaults = ZstandardDefaults.read()
        self.maximum_window = defaults[2] if maximum_window is None else maximum_window
        self.multiple_frames = defaults[3] if multiple_frames is None else multiple_frames
        self.dictionary = dictionary


class ZstandardCompressor(Compressor):
    """Compresses into a Zstandard frame."""

    PREFIX = "umilib_codec_zstandard_zstandard_compressor"

    def __init__(self, config: ZstandardConfig | None = None) -> None:
        config = config or ZstandardConfig()
        super().__init__(Handle.create(
            f"{self.PREFIX}_new", config.level, config.window_log is not None, config.window_log or 0, config.content_checksum,
            config.content_size is not None, config.content_size or 0, config.dictionary,
        ))


class ZstandardDecompressor(Decompressor):
    """Decompresses Zstandard frames (by default a series of frames ending with the input)."""

    PREFIX = "umilib_codec_zstandard_zstandard_decompressor"

    def __init__(self, config: ZstandardDecompressorConfig | None = None) -> None:
        config = config or ZstandardDecompressorConfig()
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.maximum_window, config.multiple_frames, config.dictionary))


__all__ = ["ZstandardCompressor", "ZstandardConfig", "ZstandardDecompressor", "ZstandardDecompressorConfig", "ZstandardDictionary"]
