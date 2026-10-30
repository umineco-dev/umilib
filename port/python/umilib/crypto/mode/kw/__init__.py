"""Key wrapping (SP 800-38F): KW and TKW (RFC 3394) and KWP (RFC 5649). Mirrors ``umilib::crypto::mode::kw``."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization
from umilib.ffi import Buffer, Bytes, Handle, Text


class KW(Primitive):
    """KW over the cipher ``KW[C]`` (TKW over a cipher of 64-bit blocks): wraps keys of whole semiblocks,
    at least two, with an integrity check, adding one semiblock."""

    PREFIX = "umilib_crypto_mode_kw_kw"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of KW over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, cls.__name__)
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        """Key wrapping under the key-encryption key ``key``."""
        cipher = Specialization.require(self.CIPHER, type(self).__name__)
        name, name_length = Text.encode(cipher.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, data, length))

    def wrap(self, key: bytes | bytearray | memoryview) -> bytes:
        """The wrapping of ``key``."""
        data, length = Bytes.readable(key)
        buffer = Buffer()
        self.library.call(f"{self.PREFIX}_wrap", self.handle, data, length, ctypes.byref(buffer))
        return self.library.take(buffer)

    def unwrap(self, wrapped: bytes | bytearray | memoryview) -> bytes:
        """The key ``wrapped`` holds; raises ``AuthenticationFailed`` if the integrity check fails."""
        data, length = Bytes.readable(wrapped)
        buffer = Buffer()
        self.library.call(f"{self.PREFIX}_unwrap", self.handle, data, length, ctypes.byref(buffer))
        return self.library.take(buffer)


class KWP(KW):
    """KWP over the cipher of 128-bit blocks ``KWP[C]``: KW with padding, for keys of 1 to 2^32 − 1 bytes."""

    PREFIX = "umilib_crypto_mode_kw_kwp"


__all__ = ["KW", "KWP"]
