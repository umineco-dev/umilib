"""XXH32. Mirrors ``umilib::hash::xxhash::xxh32``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, Handle, Library
from umilib.hash import Digest


class XXH32(Digest):
    """XXH32 with a 32-bit seed. The output bytes are the canonical, big-endian form of :meth:`value`."""

    PREFIX = "umilib_hash_xxhash_xxh32_xxh32"

    def __init__(self, pointer: int | None = None) -> None:
        """The seed 0."""
        super().__init__(pointer)

    @classmethod
    def with_seed(cls, seed: int) -> XXH32:
        return cls.from_pointer(Handle.create("umilib_hash_xxhash_xxh32_xxh32_with_seed", seed))

    def value(self) -> int:
        """The hash of the input so far, without changing the state."""
        return self.library.value("umilib_hash_xxhash_xxh32_xxh32_value", ctypes.c_uint32, self.handle)

    @staticmethod
    def hash(seed: int, data: bytes | bytearray | memoryview) -> int:
        """The hash of ``data`` with ``seed``."""
        data, length = Bytes.readable(data)
        return Library.default().value("umilib_hash_xxhash_xxh32_xxh32_hash", ctypes.c_uint32, seed, data, length)


__all__ = ["XXH32"]
