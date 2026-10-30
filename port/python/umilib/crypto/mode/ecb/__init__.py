"""ECB (SP 800-38A section 6.1): every block is encrypted alone, which shows equal blocks; for legacy data. Mirrors ``umilib::crypto::mode::ecb``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization
from umilib.ffi import Bytes, Handle, Text



class ECB(Primitive):
    """ECB over the cipher ``ECB[C]``."""

    PREFIX = "umilib_crypto_mode_ecb_ecb"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of ECB over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "ECB")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "ECB")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length))

    def encrypt(self, data: bytearray) -> None:
        """Encrypts ``data``, a whole number of blocks, in place."""
        self.library.call(f"{self.PREFIX}_encrypt", self.handle, Bytes.mutable(data), len(data))

    def decrypt(self, data: bytearray) -> None:
        """Decrypts ``data``, a whole number of blocks, in place."""
        self.library.call(f"{self.PREFIX}_decrypt", self.handle, Bytes.mutable(data), len(data))


__all__ = ["ECB"]
