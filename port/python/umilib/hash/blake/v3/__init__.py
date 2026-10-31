"""BLAKE3: hashing, keyed hashing and key derivation with output of any length. Mirrors ``umilib::hash::blake::v3``.

``BLAKE3Chunk`` and ``BLAKE3Output``, the building blocks of the tree, are not available.
"""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, Handle, Library
from umilib.hash import CryptographicDigest, XOFReader


class BLAKE3Reader(XOFReader):
    """The output of BLAKE3, read in order from any position up to 2^64 bytes."""

    PREFIX = "umilib_hash_blake_v3_blake3_reader"

    def position(self) -> int:
        """The number of bytes before the next one read."""
        return self.library.value(f"{self.PREFIX}_position", ctypes.c_uint64, self.handle)

    def set_position(self, position: int) -> None:
        """Moves to byte ``position`` of the output."""
        self.library.call(f"{self.PREFIX}_set_position", self.handle, position)


class BLAKE3(CryptographicDigest):
    """BLAKE3 in the hash mode, or the keyed hash and key derivation modes of
    :meth:`with_key` and :meth:`with_context`; 32 bytes of output, or any
    length through :meth:`finalize_xof`."""

    PREFIX = "umilib_hash_blake_v3_blake3"
    KEY_SIZE = 32

    @classmethod
    def with_key(cls, key: bytes) -> BLAKE3:
        """The keyed hash mode with a 32-byte key."""
        data, length = Bytes.readable(key)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_key", data, length))

    @classmethod
    def with_context(cls, context: bytes) -> BLAKE3:
        """The key derivation mode for ``context``; the input is the key material."""
        data, length = Bytes.readable(context)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_context", data, length))

    @staticmethod
    def keyed_hash(key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The 32-byte keyed hash of ``data`` under ``key``."""
        out = (ctypes.c_uint8 * 32)()
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        Library.default().call("umilib_hash_blake_v3_blake3_keyed_hash", key_data, key_length, data, length, out, 32)
        return bytes(out)

    @staticmethod
    def derive_key(context: bytes, material: bytes | bytearray | memoryview) -> bytes:
        """The 32-byte key derived from ``material`` for ``context``."""
        out = (ctypes.c_uint8 * 32)()
        context_data, context_length = Bytes.readable(context)
        data, length = Bytes.readable(material)
        Library.default().call("umilib_hash_blake_v3_blake3_derive_key", context_data, context_length, data, length, out, 32)
        return bytes(out)

    def finalize_xof(self) -> BLAKE3Reader:
        """The reader of the output of any length; releases the state."""
        out = ctypes.c_void_p()
        self.consume(f"{self.PREFIX}_finalize_xof", ctypes.byref(out))
        return BLAKE3Reader(out.value)

    @classmethod
    def digest_xof(cls, data: bytes | bytearray | memoryview, length: int) -> bytes:
        """The first ``length`` output bytes of the hash mode for ``data``."""
        out = (ctypes.c_uint8 * length)()
        data, data_length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_digest_xof", data, data_length, out, length)
        return bytes(out)


__all__ = ["BLAKE3", "BLAKE3Reader"]
