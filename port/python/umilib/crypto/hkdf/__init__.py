"""HKDF (RFC 5869): the HMAC-based extract-and-expand key derivation function. Mirrors
``umilib::crypto::hkdf``.

``HKDF[SHA256](prk)`` is ``HKDF::<SHA256>::new(prk)``.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Primitive, Specialization
from umilib.ffi import Bytes, Handle, Library, Preset, Text
from umilib.hash import CryptographicDigest


class HKDF(Primitive):
    """HKDF over the hash function ``HKDF[H]``, keyed with a pseudorandom key (PRK)."""

    PREFIX = "umilib_crypto_hkdf_hkdf"
    HASH: ClassVar[type[CryptographicDigest] | None] = None
    #: The longest output: 255 × HashLen bytes (section 2.3).
    MAXIMUM_OUTPUT: ClassVar[Any]

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE):
            raise TypeError("HKDF needs a cryptographic hash function class, such as HKDF[SHA256]")
        return Specialization.of(cls, (hash,), {"HASH": hash, "MAXIMUM_OUTPUT": Preset(lambda: 255 * hash.OUTPUT_SIZE)})

    @classmethod
    def name(cls) -> tuple[Any, int]:
        return Text.encode(Specialization.require(cls.HASH, "HKDF").C_TYPE)

    def __init__(self, prk: bytes | bytearray | memoryview) -> None:
        """HKDF with ``prk``, of at least HashLen bytes."""
        name, name_length = self.name()
        data, length = Bytes.readable(prk)
        super().__init__(Handle.create("umilib_crypto_hkdf_hkdf_new", name, name_length, data, length))

    @classmethod
    def from_secret(cls, salt: bytes | bytearray | memoryview, ikm: bytes | bytearray | memoryview) -> Any:
        """HKDF with the PRK extracted from ``salt`` (empty for HashLen zeros) and ``ikm``."""
        name, name_length = cls.name()
        salt_data, salt_length = Bytes.readable(salt)
        ikm_data, ikm_length = Bytes.readable(ikm)
        return cls.from_pointer(Handle.create("umilib_crypto_hkdf_hkdf_from_secret", name, name_length, salt_data, salt_length, ikm_data, ikm_length))

    @classmethod
    def extract(cls, salt: bytes | bytearray | memoryview, ikm: bytes | bytearray | memoryview) -> bytes:
        """HKDF-Extract(salt, IKM) (section 2.2): the PRK."""
        name, name_length = cls.name()
        salt_data, salt_length = Bytes.readable(salt)
        ikm_data, ikm_length = Bytes.readable(ikm)
        out = (ctypes.c_uint8 * Specialization.require(cls.HASH, "HKDF").OUTPUT_SIZE)()
        Library.default().call("umilib_crypto_hkdf_hkdf_extract", name, name_length, salt_data, salt_length, ikm_data, ikm_length, out, len(out))
        return bytes(out)

    def expand(self, info: bytes | bytearray | memoryview, length: int) -> bytes:
        """HKDF-Expand(PRK, info, L) (section 2.3): ``length`` bytes of output keying material."""
        data, info_length = Bytes.readable(info)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_hkdf_hkdf_expand", self.handle, data, info_length, out, length)
        return bytes(out)

    @classmethod
    def derive(
        cls,
        salt: bytes | bytearray | memoryview,
        ikm: bytes | bytearray | memoryview,
        info: bytes | bytearray | memoryview,
        length: int,
    ) -> bytes:
        """Extract and Expand: ``length`` bytes from ``salt``, ``ikm`` and ``info``."""
        name, name_length = cls.name()
        arguments = []
        for data in (salt, ikm, info):
            arguments.extend(Bytes.readable(data))
        out = (ctypes.c_uint8 * length)()
        Library.default().call("umilib_crypto_hkdf_hkdf_derive", name, name_length, *arguments, out, length)
        return bytes(out)


__all__ = ["HKDF"]
