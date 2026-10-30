"""Base58, as used by Bitcoin addresses and others. Mirrors ``umilib::codec::base::base58``."""

from __future__ import annotations

import ctypes  # noqa: F401

from umilib.codec.base import Alphabet, Encoding, Preset
from umilib.ffi import Handle


class Base58(Encoding):
    FREE = "umilib_codec_base_base58_base58_free"
    PREFIX = "umilib_codec_base_base58_base58"

    BITCOIN = Preset(lambda: Base58(Handle.create("umilib_codec_base_base58_base58_bitcoin")))
    FLICKR = Preset(lambda: Base58(Handle.create("umilib_codec_base_base58_base58_flickr")))
    RIPPLE = Preset(lambda: Base58(Handle.create("umilib_codec_base_base58_base58_ripple")))
    BITCOIN_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base58_base58_bitcoin_alphabet"))
    FLICKR_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base58_base58_flickr_alphabet"))
    RIPPLE_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base58_base58_ripple_alphabet"))

    DEFAULT_MAXIMUM_LENGTH = 4096

    def __init__(self, pointer: int) -> None:
        super().__init__(pointer)

    @classmethod
    def new(cls, alphabet: Alphabet) -> Base58:
        with alphabet.holding():
            return cls(Handle.create("umilib_codec_base_base58_base58_new", alphabet.pointer))

    def with_maximum_length(self, maximum_length: int) -> Base58:
        return Base58(Handle.create(f"{self.PREFIX}_with_maximum_length", self.handle, maximum_length))

    @property
    def maximum_length(self) -> int:
        return self.library.value(f"{self.PREFIX}_maximum_length", ctypes.c_size_t, self.handle)

    def check_length(self, length: int) -> None:
        self.library.call(f"{self.PREFIX}_check_length", self.handle, length)


__all__ = ["Base58"]
