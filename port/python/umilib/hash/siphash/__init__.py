"""SipHash and HalfSipHash, keyed hash functions for short inputs. Mirrors ``umilib::hash::siphash``.

The Rust types take their numbers of rounds as const generic parameters:
:class:`SipHash`, :class:`SipHash128`, :class:`HalfSipHash` and
:class:`HalfSipHash64` stand for them, and their subclasses are the instances
that the Rust aliases name, such as :class:`SipHash24` for ``SipHash<2, 4>``.
``KEY_SIZE`` is the key size in bytes.
"""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.ffi import Bytes, Handle, Library, Preset
from umilib.hash import Digest


class SipHash(Digest):
    """SipHash-c-d with 64 bits of output and a 128-bit key."""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        prefix = cls.PREFIX
        cls.KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_key_size")())

    def __init__(self, key: bytes) -> None:
        data, length = Bytes.readable(key)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, key: bytes) -> Any:
        """The function with ``key``, of ``KEY_SIZE`` bytes."""
        return cls(key)

    @classmethod
    def hash(cls, key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The output for ``data`` under ``key``."""
        out = (ctypes.c_uint8 * cls.OUTPUT_SIZE)()
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_hash", key_data, key_length, data, length, out, len(out))
        return bytes(out)

    @classmethod
    def digest(cls, data: bytes | bytearray | memoryview) -> bytes:
        raise TypeError(f"{cls.__name__} is keyed: use hash(key, data)")

    def finish(self) -> int:
        """The output of the input so far as a little-endian integer, as ``core::hash::Hasher::finish``."""
        return int.from_bytes(self.clone().finalize(), "little")


class SipHash128(Digest):
    """SipHash-c-d with 128 bits of output and a 128-bit key."""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        prefix = cls.PREFIX
        cls.KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_key_size")())

    def __init__(self, key: bytes) -> None:
        data, length = Bytes.readable(key)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, key: bytes) -> Any:
        """The function with ``key``, of ``KEY_SIZE`` bytes."""
        return cls(key)

    @classmethod
    def hash(cls, key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The output for ``data`` under ``key``."""
        out = (ctypes.c_uint8 * cls.OUTPUT_SIZE)()
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_hash", key_data, key_length, data, length, out, len(out))
        return bytes(out)

    @classmethod
    def digest(cls, data: bytes | bytearray | memoryview) -> bytes:
        raise TypeError(f"{cls.__name__} is keyed: use hash(key, data)")


class HalfSipHash(Digest):
    """HalfSipHash-c-d: 32-bit words, 32 bits of output and a 64-bit key."""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        prefix = cls.PREFIX
        cls.KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_key_size")())

    def __init__(self, key: bytes) -> None:
        data, length = Bytes.readable(key)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, key: bytes) -> Any:
        """The function with ``key``, of ``KEY_SIZE`` bytes."""
        return cls(key)

    @classmethod
    def hash(cls, key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The output for ``data`` under ``key``."""
        out = (ctypes.c_uint8 * cls.OUTPUT_SIZE)()
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_hash", key_data, key_length, data, length, out, len(out))
        return bytes(out)

    @classmethod
    def digest(cls, data: bytes | bytearray | memoryview) -> bytes:
        raise TypeError(f"{cls.__name__} is keyed: use hash(key, data)")


class HalfSipHash64(Digest):
    """HalfSipHash-c-d: 32-bit words, 64 bits of output and a 64-bit key."""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        prefix = cls.PREFIX
        cls.KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_key_size")())

    def __init__(self, key: bytes) -> None:
        data, length = Bytes.readable(key)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, key: bytes) -> Any:
        """The function with ``key``, of ``KEY_SIZE`` bytes."""
        return cls(key)

    @classmethod
    def hash(cls, key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The output for ``data`` under ``key``."""
        out = (ctypes.c_uint8 * cls.OUTPUT_SIZE)()
        key_data, key_length = Bytes.readable(key)
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_hash", key_data, key_length, data, length, out, len(out))
        return bytes(out)

    @classmethod
    def digest(cls, data: bytes | bytearray | memoryview) -> bytes:
        raise TypeError(f"{cls.__name__} is keyed: use hash(key, data)")

    def finish(self) -> int:
        """The output of the input so far as a little-endian integer, as ``core::hash::Hasher::finish``."""
        return int.from_bytes(self.clone().finalize(), "little")


class SipHash24(SipHash):
    """SipHash-2-4, the recommended SipHash."""

    PREFIX = "umilib_hash_siphash_sip_hash24"


class SipHash13(SipHash):
    """SipHash-1-3, the faster variant."""

    PREFIX = "umilib_hash_siphash_sip_hash13"


class SipHash128_24(SipHash128):
    """SipHash-2-4 with 128 bits of output."""

    PREFIX = "umilib_hash_siphash_sip_hash128_24"


class SipHash128_13(SipHash128):
    """SipHash-1-3 with 128 bits of output."""

    PREFIX = "umilib_hash_siphash_sip_hash128_13"


class HalfSipHash24(HalfSipHash):
    """HalfSipHash-2-4 with 32 bits of output."""

    PREFIX = "umilib_hash_siphash_half_sip_hash24"


class HalfSipHash13(HalfSipHash):
    """HalfSipHash-1-3 with 32 bits of output."""

    PREFIX = "umilib_hash_siphash_half_sip_hash13"


class HalfSipHash64_24(HalfSipHash64):
    """HalfSipHash-2-4 with 64 bits of output."""

    PREFIX = "umilib_hash_siphash_half_sip_hash64_24"


class HalfSipHash64_13(HalfSipHash64):
    """HalfSipHash-1-3 with 64 bits of output."""

    PREFIX = "umilib_hash_siphash_half_sip_hash64_13"


__all__ = [
    "HalfSipHash",
    "HalfSipHash13",
    "HalfSipHash24",
    "HalfSipHash64",
    "HalfSipHash64_13",
    "HalfSipHash64_24",
    "SipHash",
    "SipHash128",
    "SipHash128_13",
    "SipHash128_24",
    "SipHash13",
    "SipHash24",
]
