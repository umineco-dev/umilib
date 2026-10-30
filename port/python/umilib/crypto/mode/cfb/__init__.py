"""CFB (SP 800-38A section 6.3) with segments of a whole block, 8 bits or 1 bit. Mirrors ``umilib::crypto::mode::cfb``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization
from umilib.ffi import Bytes, Handle, Text



class CFB(Primitive):
    """CFB with segments of a whole block over the cipher ``CFB[C]``."""

    PREFIX = "umilib_crypto_mode_cfb_cfb"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CFB over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CFB")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview, iv: bytes | bytearray | memoryview) -> None:
        """CFB with ``key`` and the IV of one block."""
        cipher = Specialization.require(self.CIPHER, "CFB")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        iv_data, iv_length = Bytes.readable(iv)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length, iv_data, iv_length))

    def encrypt(self, data: bytearray) -> None:
        """Encrypts ``data`` in place, continuing the stream."""
        self.library.call(f"{self.PREFIX}_encrypt", self.handle, Bytes.mutable(data), len(data))

    def decrypt(self, data: bytearray) -> None:
        """Decrypts ``data`` in place, continuing the stream."""
        self.library.call(f"{self.PREFIX}_decrypt", self.handle, Bytes.mutable(data), len(data))


class CFB8(Primitive):
    """CFB with 8-bit segments over the cipher ``CFB8[C]``."""

    PREFIX = "umilib_crypto_mode_cfb_cfb8"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CFB8 over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CFB8")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview, iv: bytes | bytearray | memoryview) -> None:
        """CFB8 with ``key`` and the IV of one block."""
        cipher = Specialization.require(self.CIPHER, "CFB8")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        iv_data, iv_length = Bytes.readable(iv)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length, iv_data, iv_length))

    def encrypt(self, data: bytearray) -> None:
        """Encrypts ``data`` in place, continuing the stream."""
        self.library.call(f"{self.PREFIX}_encrypt", self.handle, Bytes.mutable(data), len(data))

    def decrypt(self, data: bytearray) -> None:
        """Decrypts ``data`` in place, continuing the stream."""
        self.library.call(f"{self.PREFIX}_decrypt", self.handle, Bytes.mutable(data), len(data))


class CFB1(Primitive):
    """CFB with 1-bit segments over the cipher ``CFB1[C]``."""

    PREFIX = "umilib_crypto_mode_cfb_cfb1"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CFB1 over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CFB1")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, key: bytes | bytearray | memoryview, iv: bytes | bytearray | memoryview) -> None:
        """CFB1 with ``key`` and the IV of one block."""
        cipher = Specialization.require(self.CIPHER, "CFB1")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        iv_data, iv_length = Bytes.readable(iv)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, key_data, key_length, iv_data, iv_length))

    def encrypt_bits(self, data: bytearray, bits: int) -> None:
        """Encrypts the first ``bits`` bits of ``data`` (most significant first) in place."""
        self.library.call(f"{self.PREFIX}_encrypt_bits", self.handle, Bytes.mutable(data), len(data), bits)

    def decrypt_bits(self, data: bytearray, bits: int) -> None:
        """Decrypts the first ``bits`` bits of ``data`` (most significant first) in place."""
        self.library.call(f"{self.PREFIX}_decrypt_bits", self.handle, Bytes.mutable(data), len(data), bits)


__all__ = ["CFB", "CFB1", "CFB8"]
