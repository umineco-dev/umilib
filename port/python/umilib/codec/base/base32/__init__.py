"""Base32, RFC 4648 sections 6 and 7. Mirrors ``umilib::codec::base::base32``."""

from __future__ import annotations

import ctypes  # noqa: F401

from umilib.codec.base import Alphabet, BitEncoding, Encoding, Padding, Preset
from umilib.ffi import Handle


class Base32(Encoding):
    FREE = "umilib_codec_base_base32_base32_free"
    PREFIX = "umilib_codec_base_base32_base32"

    STANDARD = Preset(lambda: Base32(Handle.create("umilib_codec_base_base32_base32_standard")))
    STANDARD_NO_PADDING = Preset(lambda: Base32(Handle.create("umilib_codec_base_base32_base32_standard_no_padding")))
    HEX = Preset(lambda: Base32(Handle.create("umilib_codec_base_base32_base32_hex")))
    HEX_NO_PADDING = Preset(lambda: Base32(Handle.create("umilib_codec_base_base32_base32_hex_no_padding")))
    STANDARD_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base32_base32_standard_alphabet"))
    STANDARD_ALPHABET_ANY_CASE = Preset(lambda: Alphabet.static("umilib_codec_base_base32_base32_standard_alphabet_any_case"))
    HEX_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base32_base32_hex_alphabet"))
    HEX_ALPHABET_ANY_CASE = Preset(lambda: Alphabet.static("umilib_codec_base_base32_base32_hex_alphabet_any_case"))

    def __init__(self, pointer: int) -> None:
        super().__init__(pointer)

    @property
    def encoding(self) -> BitEncoding:
        """A copy of the :class:`BitEncoding` this encoding is built on."""
        return BitEncoding(pointer=Handle.create(f"{self.PREFIX}_encoding", self.handle))

    @classmethod
    def new(cls, alphabet: Alphabet, padding: Padding) -> Base32:
        with alphabet.holding():
            return cls(Handle.create("umilib_codec_base_base32_base32_new", alphabet.pointer, int(padding)))


__all__ = ["Base32"]
