"""SHA-3 (FIPS 202) and the functions derived from it in SP 800-185. Mirrors ``umilib::hash::sha::v3``.

``Sponge<168>`` and ``Sponge<136>``, the readers of the functions with the
rates of SHAKE128 and SHAKE256, are :class:`Sponge168` and :class:`Sponge136`.
``SP800185``, the encodings of SP 800-185, is not available.
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from umilib.ffi import Bytes, Handle, Library
from umilib.hash import CryptographicDigest, ExtendableOutput, Hasher, XOFReader


class KeccakF1600:
    """The permutation Keccak-f[1600]."""

    @staticmethod
    def permute(state: list[int]) -> list[int]:
        """The 25 lanes of ``state`` (lane x + 5y at index x + 5y) after the permutation."""
        if len(state) != 25:
            raise ValueError("the state has 25 lanes")
        lanes = (ctypes.c_uint64 * 25)(*state)
        Library.default().call("umilib_hash_sha_v3_keccak_f1600_permute", lanes)
        return list(lanes)


class SHA3_224(CryptographicDigest):
    """SHA3-224."""

    PREFIX = "umilib_hash_sha_v3_sha3_224"


class SHA3_256(CryptographicDigest):
    """SHA3-256."""

    PREFIX = "umilib_hash_sha_v3_sha3_256"


class SHA3_384(CryptographicDigest):
    """SHA3-384."""

    PREFIX = "umilib_hash_sha_v3_sha3_384"


class SHA3_512(CryptographicDigest):
    """SHA3-512."""

    PREFIX = "umilib_hash_sha_v3_sha3_512"


class Keccak224(CryptographicDigest):
    """Keccak-224, with the padding of the Keccak submission."""

    PREFIX = "umilib_hash_sha_v3_keccak224"


class Keccak256(CryptographicDigest):
    """Keccak-256, with the padding of the Keccak submission."""

    PREFIX = "umilib_hash_sha_v3_keccak256"


class Keccak384(CryptographicDigest):
    """Keccak-384, with the padding of the Keccak submission."""

    PREFIX = "umilib_hash_sha_v3_keccak384"


class Keccak512(CryptographicDigest):
    """Keccak-512, with the padding of the Keccak submission."""

    PREFIX = "umilib_hash_sha_v3_keccak512"


class Sponge168(XOFReader):
    """The output of a function with the rate of SHAKE128 (``Sponge<168>``)."""

    PREFIX = "umilib_hash_sha_v3_sponge168"


class Sponge136(XOFReader):
    """The output of a function with the rate of SHAKE256 (``Sponge<136>``)."""

    PREFIX = "umilib_hash_sha_v3_sponge136"


class SHAKE128(ExtendableOutput):
    """SHAKE128."""

    PREFIX = "umilib_hash_sha_v3_shake128"
    READER = Sponge168


class SHAKE256(ExtendableOutput):
    """SHAKE256."""

    PREFIX = "umilib_hash_sha_v3_shake256"
    READER = Sponge136


class CSHAKE128(ExtendableOutput):
    """cSHAKE128, with a function name and a customization string; with both empty it is SHAKE128."""

    PREFIX = "umilib_hash_sha_v3_cshake128"
    READER = Sponge168

    def __init__(self, name: bytes = b"", customization: bytes = b"") -> None:
        name_data, name_length = Bytes.readable(name)
        data, length = Bytes.readable(customization)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", name_data, name_length, data, length))

    @classmethod
    def new(cls, name: bytes = b"", customization: bytes = b"") -> CSHAKE128:
        return cls(name, customization)

    @classmethod
    def digest_xof(cls, data: bytes | bytearray | memoryview, length: int) -> bytes:
        """The first ``length`` output bytes for ``data`` with empty name and customization."""
        state = cls()
        state.update(data)
        return state.finalize_xof().read(length)


class CSHAKE256(CSHAKE128):
    """cSHAKE256, with a function name and a customization string; with both empty it is SHAKE256."""

    PREFIX = "umilib_hash_sha_v3_cshake256"
    READER = Sponge136


class TupleHash128(Hasher):
    """TupleHash128 over a sequence of strings, with a customization string."""

    PREFIX = "umilib_hash_sha_v3_tuple_hash128"
    READER: ClassVar[type[XOFReader]] = Sponge168

    def __init__(self, customization: bytes = b"") -> None:
        data, length = Bytes.readable(customization)
        super().__init__(Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, customization: bytes = b"") -> TupleHash128:
        return cls(customization)

    def push(self, element: bytes | bytearray | memoryview) -> None:
        """Adds the next string of the tuple."""
        data, length = Bytes.readable(element)
        self.library.call(f"{self.PREFIX}_push", self.handle, data, length)

    def finalize(self, length: int) -> bytes:
        """``length`` bytes of output, a length that is part of the input; releases the state."""
        out = (ctypes.c_uint8 * length)()
        self.consume(f"{self.PREFIX}_finalize", out, length)
        return bytes(out)

    def finalize_xof(self) -> XOFReader:
        """The reader of the XOF variant, whose output does not depend on its length; releases the state."""
        out = ctypes.c_void_p()
        self.consume(f"{self.PREFIX}_finalize_xof", ctypes.byref(out))
        return self.READER(out.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class TupleHash256(TupleHash128):
    """TupleHash256 over a sequence of strings, with a customization string."""

    PREFIX = "umilib_hash_sha_v3_tuple_hash256"
    READER = Sponge136


class ParallelHash128(Hasher):
    """ParallelHash128 with blocks of ``block_size`` bytes (not 0) and a customization string."""

    PREFIX = "umilib_hash_sha_v3_parallel_hash128"
    READER: ClassVar[type[XOFReader]] = Sponge168

    def __init__(self, block_size: int, customization: bytes = b"") -> None:
        data, length = Bytes.readable(customization)
        super().__init__(Handle.create(f"{self.PREFIX}_new", block_size, data, length))

    @classmethod
    def new(cls, block_size: int, customization: bytes = b"") -> ParallelHash128:
        return cls(block_size, customization)

    def block_size(self) -> int:
        return self.library.value(f"{self.PREFIX}_block_size", ctypes.c_size_t, self.handle)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data`` to the input."""
        data, length = Bytes.readable(data)
        self.library.call(f"{self.PREFIX}_update", self.handle, data, length)

    def finalize(self, length: int) -> bytes:
        """``length`` bytes of output, a length that is part of the input; releases the state."""
        out = (ctypes.c_uint8 * length)()
        self.consume(f"{self.PREFIX}_finalize", out, length)
        return bytes(out)

    def finalize_xof(self) -> XOFReader:
        """The reader of the XOF variant, whose output does not depend on its length; releases the state."""
        out = ctypes.c_void_p()
        self.consume(f"{self.PREFIX}_finalize_xof", ctypes.byref(out))
        return self.READER(out.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class ParallelHash256(ParallelHash128):
    """ParallelHash256 with blocks of ``block_size`` bytes (not 0) and a customization string."""

    PREFIX = "umilib_hash_sha_v3_parallel_hash256"
    READER = Sponge136


__all__ = [
    "CSHAKE128",
    "CSHAKE256",
    "Keccak224",
    "Keccak256",
    "Keccak384",
    "Keccak512",
    "KeccakF1600",
    "ParallelHash128",
    "ParallelHash256",
    "SHA3_224",
    "SHA3_256",
    "SHA3_384",
    "SHA3_512",
    "SHAKE128",
    "SHAKE256",
    "Sponge136",
    "Sponge168",
    "TupleHash128",
    "TupleHash256",
]
