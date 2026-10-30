"""RC4: a stream cipher, broken (RFC 7465), for legacy data. Mirrors ``umilib::crypto::rc4``."""

from __future__ import annotations

from typing import ClassVar

from umilib.crypto import StreamCipher
from umilib.ffi import Bytes, Handle


class RC4(StreamCipher):
    """RC4 with a key of 1 to 256 bytes."""

    PREFIX = "umilib_crypto_rc4_rc4"
    MAXIMUM_KEY_SIZE: ClassVar[int] = 256

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", data, length))


__all__ = ["RC4"]
