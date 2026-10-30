"""GCM (SP 800-38D): CTR with the authentication of GHASH, with nonces of 12 bytes recommended. Mirrors ``umilib::crypto::mode::gcm``."""

from __future__ import annotations

from typing import Any, ClassVar

from umilib.crypto import AEAD, BlockCipher, BlockCipherClass, Specialization
from umilib.ffi import Bytes, Handle, Text



class GCM(AEAD):
    """GCM over the cipher and the tag size of ``GCM[C, TAG]``; ``GCM[C]`` has 16-byte tags."""

    PREFIX = "umilib_crypto_mode_gcm_gcm"
    TAG_SIZES: ClassVar[tuple[int, ...]] = (4, 8, 12, 13, 14, 15, 16)
    CIPHER: ClassVar[type[BlockCipher] | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        """The class of GCM over a 128-bit cipher with tags of ``TAG`` bytes (16 by default, as
        ``GCM<C>`` in Rust: ``GCM[AES128]``)."""
        cipher, tag = Specialization.pair(parameters, "GCM") if isinstance(parameters, tuple) else (parameters, 16)
        cipher = BlockCipherClass.require(cipher, "GCM", 16)
        Specialization.size(tag, cls.TAG_SIZES, "GCM", f"tags of {', '.join(map(str, cls.TAG_SIZES))} bytes")
        return Specialization.of(cls, (cipher, tag), {"CIPHER": cipher, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        cipher = Specialization.require(self.CIPHER, "GCM")
        name, name_length = Text.encode(cipher.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", name, name_length, data, length, self.TAG))


__all__ = ["GCM"]
