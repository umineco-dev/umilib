"""Base16 (hexadecimal), RFC 4648 section 8. Mirrors ``umilib::codec::base::base16``."""

from __future__ import annotations

import ctypes  # noqa: F401

from umilib.codec.base import Alphabet, BitEncoding, Encoding, Padding, Preset
from umilib.ffi import Handle


class Base16(Encoding):
    FREE = "umilib_codec_base_base16_base16_free"
    PREFIX = "umilib_codec_base_base16_base16"

    UPPER = Preset(lambda: Base16(Handle.create("umilib_codec_base_base16_base16_upper")))
    LOWER = Preset(lambda: Base16(Handle.create("umilib_codec_base_base16_base16_lower")))


    def __init__(self, pointer: int) -> None:
        super().__init__(pointer)

    @property
    def encoding(self) -> BitEncoding:
        """A copy of the :class:`BitEncoding` this encoding is built on."""
        return BitEncoding(pointer=Handle.create(f"{self.PREFIX}_encoding", self.handle))

    @classmethod
    def new(cls, alphabet: Alphabet) -> Base16:
        with alphabet.holding():
            return cls(Handle.create("umilib_codec_base_base16_base16_new", alphabet.pointer))


__all__ = ["Base16"]
