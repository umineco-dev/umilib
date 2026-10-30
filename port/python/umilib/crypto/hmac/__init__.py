"""HMAC, the keyed-hash message authentication code (RFC 2104, FIPS 198-1). Mirrors ``umilib::crypto::hmac``.

``HMAC[SHA256](key)`` is ``HMAC::<SHA256>::new(key)``. The hash function is
any :class:`~umilib.hash.CryptographicDigest` class, such as
``umilib.hash.sha.v2.SHA256``.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import MAC, Specialization
from umilib.ffi import Bytes, Handle, Library, Preset, Text
from umilib.hash import CryptographicDigest

P = "umilib_crypto_hmac_hmac"


class HMAC(MAC):
    """HMAC over the hash function ``HMAC[H]``; the key is absorbed once."""

    PREFIX = P
    #: The C type name, by which the KDFs select HMAC as their PRF.
    C_TYPE: ClassVar[str] = "umilib_crypto_hmac_HMAC"
    HASH: ClassVar[type[CryptographicDigest] | None] = None
    #: The hash function, as the primitive of the PRF of the KDFs.
    PRIMITIVE: ClassVar[type[CryptographicDigest] | None] = None
    MINIMUM_TRUNCATED_LENGTH: ClassVar[Any]

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        """The class of HMAC over ``hash``."""
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE):
            raise TypeError("HMAC needs a cryptographic hash function class, such as HMAC[SHA256]")
        attributes = {
            "HASH": hash,
            "PRIMITIVE": hash,
            "MINIMUM_TRUNCATED_LENGTH": Preset(lambda: HMAC[hash](b"").minimum_truncated_length()),
            "__doc__": f"HMAC over {hash.__name__}.",
        }
        return Specialization.of(cls, (hash,), attributes)

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        hash = Specialization.require(self.HASH, "HMAC")
        name, name_length = Text.encode(hash.C_TYPE)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{P}_new", name, name_length, data, length))

    @classmethod
    def new(cls, key: bytes | bytearray | memoryview) -> Any:
        return cls(key)

    @classmethod
    def mac(cls, key: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview) -> bytes:
        """The tag of ``data`` under ``key``."""
        hash = Specialization.require(cls.HASH, "HMAC")
        name, name_length = Text.encode(hash.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        out = (ctypes.c_uint8 * hash.OUTPUT_SIZE)()
        Library.default().call(f"{P}_mac", name, name_length, key_data, key_length, data, length, out, len(out))
        return bytes(out)

    def minimum_truncated_length(self) -> int:
        return self.library.value(f"{P}_minimum_truncated_length", ctypes.c_size_t, self.handle)

    def finalize_reset(self) -> bytes:
        """The tag of the message; returns the state to the key."""
        out = (ctypes.c_uint8 * self.output_size())()
        self.library.call(f"{P}_finalize_reset", self.handle, out, len(out))
        return bytes(out)

    def verify_truncated(self, tag: bytes | bytearray | memoryview) -> bool:
        """Whether ``tag`` is the leftmost bytes of the tag, of at least
        ``MINIMUM_TRUNCATED_LENGTH`` bytes; releases the state."""
        return self.verify_with(f"{P}_verify_truncated", tag)


__all__ = ["HMAC"]
