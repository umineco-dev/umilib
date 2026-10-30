"""Argon2 (RFC 9106), version 0x13. Mirrors ``umilib::crypto::argon2``."""

from __future__ import annotations

import ctypes
import enum

from umilib.crypto import Primitive
from umilib.ffi import Bytes, Handle, Library

P = "umilib_crypto_argon2_argon2"


class Argon2Type(enum.IntEnum):
    """The type y of Argon2 (section 3.1); section 4 recommends Argon2id."""

    Argon2d = 0
    Argon2i = 1
    Argon2id = 2


class Argon2(Primitive):
    """Argon2 of a type with ``memory`` KiB, ``passes`` passes and ``lanes`` lanes, checked when it is
    created (section 3.1); the memory is allocated for each derivation and zeroized after it."""

    PREFIX = P
    MINIMUM_TAG = 4

    def __init__(self, variant: Argon2Type, memory: int, passes: int, lanes: int) -> None:
        super().__init__(Handle.create(f"{P}_new", int(variant), memory, passes, lanes))

    def variant(self) -> Argon2Type:
        return Argon2Type(self.library.value(f"{P}_variant", ctypes.c_uint32, self.handle))

    def blocks(self) -> int:
        """m' = 4p × ⌊m / 4p⌋, the number of blocks of memory."""
        return self.library.value(f"{P}_blocks", ctypes.c_uint32, self.handle)

    def memory_bytes(self) -> int:
        """The bytes of memory a derivation allocates."""
        return self.library.value(f"{P}_memory_bytes", ctypes.c_uint64, self.handle)

    def derive(
        self,
        password: bytes | bytearray | memoryview,
        salt: bytes | bytearray | memoryview,
        secret: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        length: int,
    ) -> bytes:
        """The tag of ``length`` bytes (at least 4) from the password, the salt, the secret K and the
        associated data X, both possibly empty (section 3.2), in the order of ``Argon2::derive``."""
        arguments = []
        for data in (password, salt, secret, associated):
            arguments.extend(Bytes.readable(data))
        out = (ctypes.c_uint8 * length)()
        self.library.call(f"{P}_derive", self.handle, *arguments, out, length)
        return bytes(out)

    @staticmethod
    def variable_hash(inputs: list[bytes], length: int) -> bytes:
        """H' of the concatenation of ``inputs``, ``length`` bytes long (section 3.3)."""
        pointers, lengths, count, kept = Bytes.array(inputs)
        out = (ctypes.c_uint8 * length)()
        Library.default().call(f"{P}_variable_hash", pointers, lengths, count, out, length)
        del kept
        return bytes(out)


__all__ = ["Argon2", "Argon2Type"]
