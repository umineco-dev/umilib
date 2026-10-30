"""ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha). Mirrors
``umilib::crypto::chacha20poly1305``."""

from __future__ import annotations

from typing import ClassVar

from umilib.crypto import AEAD
from umilib.ffi import Bytes, Handle


class ChaCha20Poly1305(AEAD):
    """ChaCha20-Poly1305: a 32-byte key, 12-byte nonces and 16-byte tags."""

    PREFIX = "umilib_crypto_chacha20poly1305_chacha20poly1305"
    KEY_SIZE: ClassVar[int] = 32

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", data, length))


class XChaCha20Poly1305(AEAD):
    """XChaCha20-Poly1305: a 32-byte key, 24-byte nonces (enough to be chosen at random) and 16-byte tags."""

    PREFIX = "umilib_crypto_chacha20poly1305_xchacha20poly1305"
    KEY_SIZE: ClassVar[int] = 32

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", data, length))


__all__ = ["ChaCha20Poly1305", "XChaCha20Poly1305"]
