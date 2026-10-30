"""OFB (SP 800-38A section 6.4): a stream cipher from a block cipher. Mirrors ``umilib::crypto::mode::ofb``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization, StreamCipher
from umilib.ffi import Bytes, Handle, Text



class OFB(StreamCipher):
    """OFB over the cipher ``OFB[C]``."""

    PREFIX = "umilib_crypto_mode_ofb_ofb"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of OFB over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "OFB")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview, iv: bytes | bytearray | memoryview) -> None:
        """OFB with ``key`` and the IV of one block."""
        cipher = Specialization.require(self.CIPHER, "OFB")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        iv_data, iv_length = Bytes.readable(iv)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length, iv_data, iv_length))

    def apply(self, data: bytearray) -> None:
        """Xors the next ``len(data)`` bytes of key stream into ``data``."""
        self.library.call(f"{self.PREFIX}_apply", self.handle, Bytes.mutable(data), len(data))

    def apply_keystream(self, data: bytearray) -> None:
        """Xors the next ``len(data)`` bytes of key stream into ``data``; OFB never runs out of key stream."""
        self.apply(data)


__all__ = ["OFB"]
