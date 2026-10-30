"""CBC (SP 800-38A section 6.2): each block is chained to the previous ciphertext. Mirrors ``umilib::crypto::mode::cbc``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization
from umilib.ffi import Bytes, Handle, Text



class CBC(Primitive):
    """CBC over the cipher ``CBC[C]``, chaining across calls."""

    PREFIX = "umilib_crypto_mode_cbc_cbc"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CBC over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CBC")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview, iv: bytes | bytearray | memoryview) -> None:
        """CBC with ``key`` and the IV of one block."""
        cipher = Specialization.require(self.CIPHER, "CBC")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        iv_data, iv_length = Bytes.readable(iv)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length, iv_data, iv_length))

    def encrypt(self, data: bytearray) -> None:
        """Encrypts ``data``, a whole number of blocks, in place, continuing the chain."""
        self.library.call(f"{self.PREFIX}_encrypt", self.handle, Bytes.mutable(data), len(data))

    def decrypt(self, data: bytearray) -> None:
        """Decrypts ``data``, a whole number of blocks, in place, continuing the chain."""
        self.library.call(f"{self.PREFIX}_decrypt", self.handle, Bytes.mutable(data), len(data))


__all__ = ["CBC"]
