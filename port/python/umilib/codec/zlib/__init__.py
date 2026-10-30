"""zlib (RFC 1950): Deflate streams with a header and an Adler-32 checksum. Mirrors ``umilib::codec::zlib``."""

from __future__ import annotations

from umilib.codec import Compressor, Decompressor
from umilib.codec.deflate import DeflateConfig, DeflateDecompressorConfig
from umilib.ffi import Bytes, Handle


class ZlibCompressor(Compressor):
    """Compresses into zlib streams, with the preset ``dictionary`` if given."""

    PREFIX = "umilib_codec_zlib_zlib_compressor"

    def __init__(self, config: DeflateConfig | None = None, dictionary: bytes | None = None) -> None:
        config = config or DeflateConfig()
        data, length = Bytes.readable(dictionary) if dictionary is not None else (None, 0)
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.level, config.window_bits, data, length))


class ZlibDecompressor(Decompressor):
    """Decompresses zlib streams, giving the preset ``dictionary`` to the streams that name it."""

    PREFIX = "umilib_codec_zlib_zlib_decompressor"

    def __init__(self, config: DeflateDecompressorConfig | None = None, dictionary: bytes | None = None) -> None:
        config = config or DeflateDecompressorConfig()
        data, length = Bytes.readable(dictionary) if dictionary is not None else (None, 0)
        super().__init__(Handle.create(f"{self.PREFIX}_new", config.window_bits, data, length))


__all__ = ["ZlibCompressor", "ZlibDecompressor"]
