"""XTS (SP 800-38E, IEEE 1619): each data unit, such as a disk sector, is encrypted under a tweak, without expansion. Mirrors ``umilib::crypto::mode::xts``."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Primitive, Specialization
from umilib.ffi import Bytes, Handle, Library, Text, U128



class XTS(Primitive):
    """XTS over the 128-bit cipher ``XTS[C]``, with a data key and a tweak key, which must differ."""

    PREFIX = "umilib_crypto_mode_xts_xts"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of XTS over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "XTS", 16)
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(self, data_key: bytes | bytearray | memoryview, tweak_key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "XTS")
        name, name_length = Text.encode(cipher.C_TYPE)
        data, data_length = Bytes.readable(data_key)
        tweak, tweak_length = Bytes.readable(tweak_key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, data, data_length, tweak, tweak_length))

    @staticmethod
    def tweak_of(unit: int) -> bytes:
        """The tweak of data unit number ``unit``: its little-endian encoding (IEEE 1619 section 5.1)."""
        out = (ctypes.c_uint8 * 16)()
        Library.default().call("umilib_crypto_mode_xts_xts_tweak_of", U128.from_int(unit), out, 16)
        return bytes(out)

    def encrypt(self, tweak: bytes | bytearray | memoryview, data: bytearray) -> None:
        """Encrypts the data unit ``data`` (16 bytes to 2^20 blocks) in place under the 16-byte ``tweak``."""
        tweak_data, tweak_length = Bytes.readable(tweak)
        self.library.call(f"{self.PREFIX}_encrypt", self.handle, tweak_data, tweak_length, Bytes.mutable(data), len(data))

    def decrypt(self, tweak: bytes | bytearray | memoryview, data: bytearray) -> None:
        """Decrypts the data unit ``data`` (16 bytes to 2^20 blocks) in place under the 16-byte ``tweak``."""
        tweak_data, tweak_length = Bytes.readable(tweak)
        self.library.call(f"{self.PREFIX}_decrypt", self.handle, tweak_data, tweak_length, Bytes.mutable(data), len(data))


__all__ = ["XTS"]
