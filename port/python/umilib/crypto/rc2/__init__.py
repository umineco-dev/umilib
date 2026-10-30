"""RC2 (RFC 2268): broken, for legacy data. Mirrors ``umilib::crypto::rc2``."""

from __future__ import annotations

from umilib.crypto import BlockCipher
from umilib.ffi import Bytes, Handle


class RC2(BlockCipher):
    """RC2: keys of 1 to 128 bytes and an effective key length of 1 to 1024 bits."""

    PREFIX = "umilib_crypto_rc2_rc2"

    def __init__(self, key: bytes | bytearray | memoryview, effective_bits: int | None = None) -> None:
        """RC2 with ``key`` and an effective key length of ``effective_bits`` bits, by default 8 × the
        key length (``RC2::new``; the default is ``KeyInit``)."""
        if effective_bits is None:
            super().__init__(key)
            return
        data, length = Bytes.readable(key)
        Handle.__init__(self, Handle.create("umilib_crypto_rc2_rc2_new_with_effective_bits", data, length, effective_bits))


__all__ = ["RC2"]
