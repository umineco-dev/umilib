"""The one-step key derivation function of SP 800-56C Rev. 2 (the Concat KDF of JOSE, RFC 7518 section 4.6.2).
Mirrors ``umilib::crypto::concatkdf``.

``ConcatKDF[HashFunction[SHA256]]()`` is ``ConcatKDF::<HashFunction<SHA256>>::hash()`` (option 1);
``ConcatKDF[HMAC[SHA256]](salt)`` is ``ConcatKDF::new(HMAC::<SHA256>::new(salt))`` (option 2).
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import Primitive, Specialization
from umilib.ffi import Bytes, Handle, Text
from umilib.hash import CryptographicDigest


class HashFunction:
    """The hash function ``HashFunction[H]`` as the auxiliary function of the one-step KDF (option 1)."""

    #: The C type name, by which the KDF selects a hash function as its auxiliary function.
    C_TYPE: ClassVar[str] = "umilib_crypto_concatkdf_HashFunction"
    HASH: ClassVar[type[CryptographicDigest] | None] = None
    #: The hash function, as the primitive of the auxiliary function.
    PRIMITIVE: ClassVar[type[CryptographicDigest] | None] = None

    def __class_getitem__(cls, hash: type[CryptographicDigest]) -> Any:
        if not (isinstance(hash, type) and issubclass(hash, CryptographicDigest) and hash.C_TYPE):
            raise TypeError("HashFunction needs a cryptographic hash function class, such as HashFunction[SHA256]")
        return Specialization.of(cls, (hash,), {"HASH": hash, "PRIMITIVE": hash})


class ConcatKDF(Primitive):
    """The one-step KDF over the auxiliary function ``ConcatKDF[F]``: ``HashFunction[H]`` or ``HMAC[H]``."""

    PREFIX = "umilib_crypto_concatkdf_concat_kdf"
    FUNCTION: ClassVar[Any] = None

    def __class_getitem__(cls, function: Any) -> Any:
        primitive = getattr(function, "PRIMITIVE", None)
        if not (isinstance(function, type) and getattr(function, "C_TYPE", "") and primitive is not None):
            raise TypeError("ConcatKDF needs ConcatKDF[HashFunction[H]] or ConcatKDF[HMAC[H]]")
        return Specialization.of(cls, (function,), {"FUNCTION": function})

    def __init__(self, salt: bytes | bytearray | memoryview = b"") -> None:
        """The KDF; HMAC is keyed with ``salt``, which a hash function takes empty."""
        function = Specialization.require(self.FUNCTION, "ConcatKDF")
        function_name, function_length = Text.encode(function.C_TYPE)
        hash_name, hash_length = Text.encode(function.PRIMITIVE.C_TYPE)
        data, length = Bytes.readable(salt)
        super().__init__(Handle.create("umilib_crypto_concatkdf_concat_kdf_new", function_name, function_length, hash_name, hash_length, data, length))

    @classmethod
    def hash(cls) -> Any:
        """The KDF over a hash function (option 1)."""
        return cls()

    def derive(self, z: bytes | bytearray | memoryview, fixed_info: bytes | bytearray | memoryview, length: int) -> bytes:
        """``length`` bytes of K(1) || K(2) || ..., K(i) = H([i]_32 || Z || FixedInfo)."""
        z_data, z_length = Bytes.readable(z)
        info_data, info_length = Bytes.readable(fixed_info)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_concatkdf_concat_kdf_derive", self.handle, z_data, z_length, info_data, info_length, out, length)
        return bytes(out)


__all__ = ["ConcatKDF", "HashFunction"]
