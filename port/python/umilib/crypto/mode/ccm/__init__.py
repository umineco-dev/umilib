"""CCM (SP 800-38C, RFC 3610): CTR with CBC-MAC, with nonces of 7 to 13 bytes. Mirrors ``umilib::crypto::mode::ccm``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import AEAD, BlockCipher, BlockCipherClass, Specialization
from umilib.ffi import Bytes, Handle, Text



class CCM(AEAD):
    """CCM over the cipher and the tag size of ``CCM[C, TAG]``."""

    PREFIX = "umilib_crypto_mode_ccm_ccm"
    TAG_SIZES: ClassVar[tuple[int, ...]] = (4, 6, 8, 10, 12, 14, 16)
    CIPHER: ClassVar[type[BlockCipher] | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        """The class of CCM over a 128-bit cipher with tags of ``TAG`` bytes: ``CCM[AES128, 16]``."""
        cipher, tag = Specialization.pair(parameters, "CCM")
        cipher = BlockCipherClass.require(cipher, "CCM", 16)
        Specialization.size(tag, cls.TAG_SIZES, "CCM", f"tags of {', '.join(map(str, cls.TAG_SIZES))} bytes")
        return Specialization.of(cls, (cipher, tag), {"CIPHER": cipher, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "CCM")
        name, name_length = Text.encode(cipher.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, data, length, self.TAG))


__all__ = ["CCM"]
