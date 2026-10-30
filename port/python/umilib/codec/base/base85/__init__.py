"""Base85: Ascii85, Z85 and the RFC 1924 alphabet. Mirrors ``umilib::codec::base::base85``."""

from __future__ import annotations

import ctypes  # noqa: F401

from umilib.codec.base import Alphabet, Encoding, Preset
from umilib.ffi import Handle


class Base85(Encoding):
    FREE = "umilib_codec_base_base85_base85_free"
    PREFIX = "umilib_codec_base_base85_base85"

    ASCII85 = Preset(lambda: Base85(Handle.create("umilib_codec_base_base85_base85_ascii85")))
    ASCII85_ADOBE = Preset(lambda: Base85(Handle.create("umilib_codec_base_base85_base85_ascii85_adobe")))
    Z85 = Preset(lambda: Base85(Handle.create("umilib_codec_base_base85_base85_z85")))
    RFC1924 = Preset(lambda: Base85(Handle.create("umilib_codec_base_base85_base85_rfc1924")))
    ASCII85_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base85_base85_ascii85_alphabet"))
    Z85_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base85_base85_z85_alphabet"))
    RFC1924_ALPHABET = Preset(lambda: Alphabet.static("umilib_codec_base_base85_base85_rfc1924_alphabet"))

    WHITESPACE = bytes([0x20, 0x09, 0x0A, 0x0C, 0x0D, 0x00])

    def __init__(self, pointer: int) -> None:
        super().__init__(pointer)

    def settings(self) -> tuple[int | None, bool, bool]:
        has_zero, zero, partial, whitespace = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_bool()
        self.library.call(f"{self.PREFIX}_settings", self.handle, ctypes.byref(has_zero), ctypes.byref(zero), ctypes.byref(partial), ctypes.byref(whitespace))
        return (zero.value if has_zero.value else None), partial.value, whitespace.value

    @property
    def zero_group(self) -> int | None:
        return self.settings()[0]

    @property
    def partial_groups(self) -> bool:
        return self.settings()[1]

    @property
    def ignore_whitespace(self) -> bool:
        return self.settings()[2]

    @property
    def delimiters(self) -> tuple[bytes, bytes] | None:
        from umilib.ffi import Buffer

        has, start, end = ctypes.c_bool(), Buffer(), Buffer()
        self.library.call(f"{self.PREFIX}_delimiters", self.handle, ctypes.byref(has), ctypes.byref(start), ctypes.byref(end))
        start_bytes, end_bytes = self.library.take(start), self.library.take(end)
        return (start_bytes, end_bytes) if has.value else None

    def delimiter_lengths(self) -> tuple[int, int]:
        start, end = ctypes.c_size_t(), ctypes.c_size_t()
        self.library.call(f"{self.PREFIX}_delimiter_lengths", self.handle, ctypes.byref(start), ctypes.byref(end))
        return start.value, end.value

    def encode_group(self, value: int) -> bytes:
        """The five digits of ``value``, most significant first."""
        out = (ctypes.c_uint8 * 5)()
        self.library.call(f"{self.PREFIX}_encode_group", self.handle, value, out)
        return bytes(out)


__all__ = ["Base85"]
