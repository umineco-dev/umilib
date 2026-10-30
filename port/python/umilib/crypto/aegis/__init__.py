"""AEGIS-128X and AEGIS-256X (draft-irtf-cfrg-aegis-aead), their MACs and key streams. Mirrors
``umilib::crypto::aegis``.

``AEGIS128X[2, 16](key)`` is ``AEGIS128X::<2, 16>::new(key)``: the degree D (1,
2 or 4) and the tag size (16 or 32 bytes). ``AEGIS128L[TAG]`` and
``AEGIS256[TAG]`` are degree 1. A failed decryption zeroes the buffer.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import AEAD, MAC, Specialization
from umilib.ffi import Bytes, Handle, Library


class AEGISParameters:
    """The checks of the parameters D and TAG of the AEGIS types."""

    @staticmethod
    def require(parameters: Any, user: str) -> tuple[int, int]:
        """The degree (1, 2 or 4) and the tag size (16 or 32) of a subscript such as ``AEGIS128X[1, 16]``."""
        degree, tag = Specialization.pair(parameters, user)
        Specialization.size(degree, (1, 2, 4), user, "a degree of 1, 2 or 4")
        Specialization.size(tag, (16, 32), user, "tags of 16 or 32 bytes")
        return degree, tag


class AEGIS128X(AEAD):
    """AEGIS-128X of degree D with tags of TAG bytes: a 16-byte key and 16-byte nonces."""

    PREFIX = "umilib_crypto_aegis_aegis128x"
    KEY_SIZE: ClassVar[int] = 16
    DEGREE: ClassVar[int | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: tuple[int, int]) -> Any:
        degree, tag = AEGISParameters.require(parameters, cls.__name__)
        return Specialization.of(cls, (degree, tag), {"DEGREE": degree, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        degree = Specialization.require(self.DEGREE, type(self).__name__)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", degree, self.TAG, data, length))


class AEGIS256X(AEAD):
    """AEGIS-256X of degree D with tags of TAG bytes: a 32-byte key and 32-byte nonces."""

    PREFIX = "umilib_crypto_aegis_aegis256x"
    KEY_SIZE: ClassVar[int] = 32
    DEGREE: ClassVar[int | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: tuple[int, int]) -> Any:
        degree, tag = AEGISParameters.require(parameters, cls.__name__)
        return Specialization.of(cls, (degree, tag), {"DEGREE": degree, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        degree = Specialization.require(self.DEGREE, type(self).__name__)
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", degree, self.TAG, data, length))


class AEGIS128L:
    """AEGIS-128L, a type alias: ``AEGIS128L[TAG]`` is ``AEGIS128X[1, TAG]``."""

    def __class_getitem__(cls, tag: int) -> Any:
        return AEGIS128X[1, tag]


class AEGIS256:
    """AEGIS-256, a type alias: ``AEGIS256[TAG]`` is ``AEGIS256X[1, TAG]``."""

    def __class_getitem__(cls, tag: int) -> Any:
        return AEGIS256X[1, tag]


class AEGIS128XState:
    """The state of AEGIS-128X of degree D, ``AEGIS128XState[D]``, for its key stream."""

    DEGREE: ClassVar[int | None] = None

    def __class_getitem__(cls, degree: int) -> Any:
        Specialization.size(degree, (1, 2, 4), cls.__name__, "a degree of 1, 2 or 4")
        return Specialization.of(cls, (degree,), {"DEGREE": degree})

    @classmethod
    def stream(cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, length: int) -> bytes:
        """Stream(len, key, nonce) (section 7): ``length`` bytes of key stream, the encryption of zeros."""
        degree = Specialization.require(cls.DEGREE, cls.__name__)
        return AEGISStream.stream("umilib_crypto_aegis_aegis128x_stream", degree, key, nonce, length)


class AEGIS256XState:
    """The state of AEGIS-256X of degree D, ``AEGIS256XState[D]``, for its key stream."""

    DEGREE: ClassVar[int | None] = None

    def __class_getitem__(cls, degree: int) -> Any:
        Specialization.size(degree, (1, 2, 4), cls.__name__, "a degree of 1, 2 or 4")
        return Specialization.of(cls, (degree,), {"DEGREE": degree})

    @classmethod
    def stream(cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, length: int) -> bytes:
        """Stream(len, key, nonce) (section 7): ``length`` bytes of key stream, the encryption of zeros."""
        degree = Specialization.require(cls.DEGREE, cls.__name__)
        return AEGISStream.stream("umilib_crypto_aegis_aegis256x_stream", degree, key, nonce, length)


class AEGISStream:
    """The call of the key stream functions of the C ABI."""

    @staticmethod
    def stream(function: str, degree: int, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, length: int) -> bytes:
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        out = (ctypes.c_uint8 * length)()
        Library.default().call(function, degree, key_data, key_length, nonce_data, nonce_length, out, length)
        return bytes(out)


class AEGISMAC128X(MAC):
    """The MAC of AEGIS-128X of degree D with tags of TAG bytes, keyed with a 16-byte key and a 16-byte nonce."""

    PREFIX = "umilib_crypto_aegis_aegis_mac128x"
    DEGREE: ClassVar[int | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: tuple[int, int]) -> Any:
        degree, tag = AEGISParameters.require(parameters, cls.__name__)
        return Specialization.of(cls, (degree, tag), {"DEGREE": degree, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview) -> None:
        degree = Specialization.require(self.DEGREE, type(self).__name__)
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        super().__init__(Handle.create(f"{self.PREFIX}_new", degree, self.TAG, key_data, key_length, nonce_data, nonce_length))

    @classmethod
    def mac(
        cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview
    ) -> bytes:
        """The tag of ``data``."""
        state = cls(key, nonce)
        state.update(data)
        return state.finalize()


class AEGISMAC256X(MAC):
    """The MAC of AEGIS-256X of degree D with tags of TAG bytes, keyed with a 32-byte key and a 32-byte nonce."""

    PREFIX = "umilib_crypto_aegis_aegis_mac256x"
    DEGREE: ClassVar[int | None] = None
    TAG: ClassVar[int | None] = None

    def __class_getitem__(cls, parameters: tuple[int, int]) -> Any:
        degree, tag = AEGISParameters.require(parameters, cls.__name__)
        return Specialization.of(cls, (degree, tag), {"DEGREE": degree, "TAG": tag})

    def __init__(self, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview) -> None:
        degree = Specialization.require(self.DEGREE, type(self).__name__)
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        super().__init__(Handle.create(f"{self.PREFIX}_new", degree, self.TAG, key_data, key_length, nonce_data, nonce_length))

    @classmethod
    def mac(
        cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview
    ) -> bytes:
        """The tag of ``data``."""
        state = cls(key, nonce)
        state.update(data)
        return state.finalize()


class AEGISMAC128L:
    """A type alias: ``AEGISMAC128L[TAG]`` is ``AEGISMAC128X[1, TAG]``."""

    def __class_getitem__(cls, tag: int) -> Any:
        return AEGISMAC128X[1, tag]


class AEGISMAC256:
    """A type alias: ``AEGISMAC256[TAG]`` is ``AEGISMAC256X[1, TAG]``."""

    def __class_getitem__(cls, tag: int) -> Any:
        return AEGISMAC256X[1, tag]


__all__ = [
    "AEGIS128L",
    "AEGIS128X",
    "AEGIS128XState",
    "AEGIS256",
    "AEGIS256X",
    "AEGIS256XState",
    "AEGISMAC128L",
    "AEGISMAC128X",
    "AEGISMAC256",
    "AEGISMAC256X",
    "AEGISParameters",
    "AEGISStream",
]
