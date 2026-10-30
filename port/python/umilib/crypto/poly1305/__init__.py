"""Poly1305 (RFC 8439 section 2.5): a one-time MAC. Mirrors ``umilib::crypto::poly1305``."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from umilib.crypto import MAC
from umilib.ffi import Bytes, Handle, Library

P = "umilib_crypto_poly1305_poly1305"


class Poly1305(MAC):
    """Poly1305 with a one-time key of 32 bytes (r, then s): a key must authenticate one message only."""

    PREFIX = P
    KEY_SIZE: ClassVar[int] = 32
    TAG_SIZE: ClassVar[int] = 16

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{P}_new", data, length))

    @staticmethod
    def mac(key: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview) -> bytes:
        """The tag of ``data`` under the one-time ``key``."""
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        out = (ctypes.c_uint8 * 16)()
        Library.default().call(f"{P}_mac", key_data, key_length, data, length, out, 16)
        return bytes(out)


__all__ = ["Poly1305"]
