"""Ascon-AEAD128 (NIST SP 800-232). Mirrors ``umilib::crypto::ascon``.

``AsconAEAD128[TAG](key)`` has tags of TAG bytes (4 to 16); ``AsconAEAD128[16]``
is the recommended choice.
"""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import AEAD, Specialization
from umilib.ffi import Bytes, Handle


class AsconAEAD128(AEAD):
    """Ascon-AEAD128 with tags of TAG bytes: a 16-byte key and 16-byte nonces."""

    PREFIX = "umilib_crypto_ascon_ascon_aead128"
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, tag: int) -> Any:
        Specialization.size(tag, range(4, 17), "AsconAEAD128", "tags of 4 to 16 bytes")
        return Specialization.of(cls, (tag,), {"TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview, nonce_mask: bytes | bytearray | memoryview | None = None) -> None:
        """Ascon-AEAD128 with ``key``, and with the nonce mask K2 of section 4.2.2 if it is given (the
        second half of a 32-byte key)."""
        tag = Specialization.require(self.TAG, "AsconAEAD128")
        data, length = Bytes.readable(key)
        if nonce_mask is None:
            super().__init__(Handle.create("umilib_crypto_ascon_ascon_aead128_new", tag, data, length))
        else:
            mask, mask_length = Bytes.readable(nonce_mask)
            super().__init__(Handle.create("umilib_crypto_ascon_ascon_aead128_with_nonce_mask", tag, data, length, mask, mask_length))

    @classmethod
    def with_nonce_mask(cls, key: bytes | bytearray | memoryview, nonce_mask: bytes | bytearray | memoryview) -> Any:
        return cls(key, nonce_mask)


__all__ = ["AsconAEAD128"]
