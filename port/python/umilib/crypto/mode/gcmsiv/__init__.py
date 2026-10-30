"""AES-GCM-SIV (RFC 8452): nonce-misuse-resistant authenticated encryption. Mirrors ``umilib::crypto::mode::gcmsiv``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import AEAD, BlockCipher, BlockCipherClass, Specialization
from umilib.ffi import Bytes, Handle, Text



class GCMSIV(AEAD):
    """GCM-SIV over the 128-bit cipher ``GCMSIV[C]``, with a key-generating key of 16 or 32 bytes,
    12-byte nonces and 16-byte tags."""

    PREFIX = "umilib_crypto_mode_gcmsiv_gcmsiv"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of GCM-SIV over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "GCMSIV", 16)
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "GCMSIV")
        name, name_length = Text.encode(cipher.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, data, length))


__all__ = ["GCMSIV"]
