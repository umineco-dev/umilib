"""CMAC (SP 800-38B, RFC 4493): the MAC of a block cipher. Mirrors ``umilib::crypto::cmac``.

``CMAC[AES128](key)`` is ``CMAC::new(AES128::new(key))``; the cipher may have
blocks of 8 or 16 bytes.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import MAC, BlockCipher, BlockCipherClass, Specialization
from umilib.ffi import Bytes, Handle, Library, Text


class CMAC(MAC):
    """CMAC over the cipher ``CMAC[C]``."""

    PREFIX = "umilib_crypto_cmac_cmac"
    #: The C type name, by which the KDFs select CMAC as their PRF.
    C_TYPE: ClassVar[str] = "umilib_crypto_cmac_CMAC"
    CIPHER: ClassVar[type[BlockCipher] | None] = None
    #: The cipher, as the primitive of the PRF of the KDFs.
    PRIMITIVE: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CMAC over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CMAC")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher, "PRIMITIVE": cipher})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "CMAC")
        name, name_length = Text.encode(cipher.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create("umilib_crypto_cmac_cmac_new", name, name_length, data, length))

    @classmethod
    def mac(cls, key: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview) -> bytes:
        """The tag of ``data`` under ``key``."""
        cipher = Specialization.require(cls.CIPHER, "CMAC")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        out = (ctypes.c_uint8 * cipher.BLOCK_SIZE)()
        Library.default().call("umilib_crypto_cmac_cmac_mac", name, name_length, key_data, key_length, data, length, out, len(out))
        return bytes(out)

    def verify_truncated(self, tag: bytes | bytearray | memoryview) -> bool:
        """Whether ``tag`` is the leftmost bytes (at least 8, or the whole block if shorter) of the tag;
        releases the state."""
        return self.verify_with("umilib_crypto_cmac_cmac_verify_truncated", tag)

    def verify_truncated_with_minimum(self, tag: bytes | bytearray | memoryview, minimum: int) -> bool:
        """Whether ``tag`` is the leftmost bytes, at least ``minimum`` (and one) of them, of the tag;
        SP 800-38B appendix A.2 allows fewer than 8 only where failed verifications are limited.
        Releases the state."""
        data, length = Bytes.readable(tag)
        valid = ctypes.c_bool()
        with self.locked():
            self.library.call("umilib_crypto_cmac_cmac_verify_truncated_with_minimum", self.pointer, data, length, minimum, ctypes.byref(valid))
            self.consumed()
        return valid.value


__all__ = ["CMAC"]
