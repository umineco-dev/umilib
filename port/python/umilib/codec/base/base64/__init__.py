"""Base64, RFC 4648 sections 4 and 5. Mirrors ``umilib::codec::base::base64``."""

from __future__ import annotations

import ctypes  # noqa: F401

from umilib.codec.base import Alphabet, BitEncoding, Encoding, Padding, Preset
from umilib.ffi import Handle


class Base64(Encoding):
    FREE = "umilib_codec_base_base64_base64_free"
    PREFIX = "umilib_codec_base_base64_base64"

    STANDARD = Preset(lambda: Base64(Handle.create("umilib_codec_base_base64_base64_standard")))
    STANDARD_NO_PADDING = Preset(lambda: Base64(Handle.create("umilib_codec_base_base64_base64_standard_no_padding")))
    URL_SAFE = Preset(lambda: Base64(Handle.create("umilib_codec_base_base64_base64_url_safe")))
    URL_SAFE_NO_PADDING = Preset(lambda: Base64(Handle.create("umilib_codec_base_base64_base64_url_safe_no_padding")))
    STANDARD_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base64_base64_standard_alphabet"))
    URL_SAFE_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base64_base64_url_safe_alphabet"))

    def __init__(self, pointer: int) -> None:
        super().__init__(pointer)

    @property
    def encoding(self) -> BitEncoding:
        """A copy of the :class:`BitEncoding` this encoding is built on."""
        return BitEncoding(pointer=Handle.create(f"{self.PREFIX}_encoding", self.handle))

    @classmethod
    def new(cls, alphabet: Alphabet, padding: Padding) -> Base64:
        with alphabet.holding():
            return cls(Handle.create("umilib_codec_base_base64_base64_new", alphabet.pointer, int(padding)))


__all__ = ["Base64"]
