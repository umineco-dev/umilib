"""PBKDF2 (RFC 8018 section 5.2) with HMAC. Mirrors ``umilib::crypto::pbkdf2``.

``PBKDF2[SHA256].derive(password, salt, iterations, length)`` is
``PBKDF2::<SHA256>::derive``.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Specialization
from umilib.ffi import Bytes, Library, Preset, Text
from umilib.hash import CryptographicDigest


class PBKDF2:
    """PBKDF2 with HMAC over the hash function ``PBKDF2[H]``."""

    HASH: ClassVar[type[CryptographicDigest] | None] = None
    #: The longest output: (2^32 - 1) × HashLen bytes.
    MAXIMUM_OUTPUT: ClassVar[Any]

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE):
            raise TypeError("PBKDF2 needs a cryptographic hash function class, such as PBKDF2[SHA256]")
        name, name_length = Text.encode(hash.C_TYPE)
        maximum = Preset(lambda: Library.default().value("umilib_crypto_pbkdf2_pbkdf2_maximum_output", ctypes.c_uint64, name, name_length))
        return Specialization.of(cls, (hash,), {"HASH": hash, "MAXIMUM_OUTPUT": maximum})

    @classmethod
    def derive(
        cls,
        password: bytes | bytearray | memoryview,
        salt: bytes | bytearray | memoryview,
        iterations: int,
        length: int,
    ) -> bytes:
        """``length`` bytes derived from ``password`` and ``salt`` with ``iterations`` (at least 1) iterations."""
        name, name_length = Text.encode(Specialization.require(cls.HASH, "PBKDF2").C_TYPE)
        password_data, password_length = Bytes.readable(password)
        salt_data, salt_length = Bytes.readable(salt)
        out = (ctypes.c_uint8 * length)()
        Library.default().call(
            "umilib_crypto_pbkdf2_pbkdf2_derive", name, name_length, password_data, password_length, salt_data, salt_length, iterations, out, length
        )
        return bytes(out)


__all__ = ["PBKDF2"]
