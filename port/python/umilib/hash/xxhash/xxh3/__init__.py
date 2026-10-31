"""XXH3 with 64 and 128 bits of output. Mirrors ``umilib::hash::xxhash::xxh3``.

``XXH3``, the state the two share, and ``XXH3Secret``, the key, are made by
the constructors of :class:`XXH3_64` and :class:`XXH3_128`.
"""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.ffi import U128, Bytes, Handle, Library
from umilib.hash import Digest


class XXH3_64(Digest):
    """XXH3 with 64 bits of output, keyed by a seed or a secret. The output
    bytes are the canonical, big-endian form of :meth:`value`."""

    PREFIX = "umilib_hash_xxhash_xxh3_xxh3_64"

    @classmethod
    def with_seed(cls, seed: int) -> Any:
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_seed", seed))

    @classmethod
    def with_secret(cls, secret: bytes) -> Any:
        """A copy of ``secret``, of at least 136 bytes."""
        data, length = Bytes.readable(secret)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_secret", data, length))

    def value(self) -> int:
        """The hash of the input so far, without changing the state."""
        return self.library.value(f"{self.PREFIX}_value", ctypes.c_uint64, self.handle)

    @classmethod
    def hash(cls, seed: int, data: bytes | bytearray | memoryview) -> int:
        """The hash of ``data`` with ``seed``."""
        data, length = Bytes.readable(data)
        return Library.default().value(f"{cls.PREFIX}_hash", ctypes.c_uint64, seed, data, length)


class XXH3_128(Digest):
    """XXH3 with 128 bits of output (XXH128), keyed by a seed or a secret. The
    output bytes are the canonical, big-endian form of :meth:`value`."""

    PREFIX = "umilib_hash_xxhash_xxh3_xxh3_128"

    @classmethod
    def with_seed(cls, seed: int) -> Any:
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_seed", seed))

    @classmethod
    def with_secret(cls, secret: bytes) -> Any:
        """A copy of ``secret``, of at least 136 bytes."""
        data, length = Bytes.readable(secret)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_secret", data, length))

    def value(self) -> int:
        """The hash of the input so far, without changing the state."""
        out = U128()
        self.library.call(f"{self.PREFIX}_value", self.handle, ctypes.byref(out))
        return out.to_int()

    @classmethod
    def hash(cls, seed: int, data: bytes | bytearray | memoryview) -> int:
        """The hash of ``data`` with ``seed``."""
        out = U128()
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_hash", seed, data, length, ctypes.byref(out))
        return out.to_int()


__all__ = ["XXH3_128", "XXH3_64"]
