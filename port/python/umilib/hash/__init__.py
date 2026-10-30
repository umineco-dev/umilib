"""Hash functions. Mirrors ``umilib::hash``.

:class:`Digest`, :class:`ExtendableOutput` and :class:`XOFReader` are the
bases of every hash function type, as the Rust traits of the same names are:
each subclass names the C functions of its type with ``PREFIX``. Methods that
consume the state in Rust (``finalize``, ``finalize_xof``) release the Python
object too; use ``clone`` first to keep it. Errors are :class:`HashError`.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar, TypeVar

from umilib.ffi import Bytes, FFIError, Handle, Library, Preset

T = TypeVar("T", bound="Hasher")


class HashError(FFIError):
    """An error of a hash function; ``name`` is the variant, such as ``OutputLength``."""


Library.register_error("hash", HashError)


class Hasher(Handle):
    """The functions every hash function type shares: ``reset`` and ``clone``.

    A subclass sets ``PREFIX``, the start of the names of its C functions,
    such as ``umilib_hash_sha_v2_sha256``.
    """

    PREFIX: ClassVar[str] = ""
    #: The C type name, which the C ABI of types generic over a hash function
    #: (such as ``umilib.crypto.hmac.HMAC``) uses to select it.
    C_TYPE: ClassVar[str] = ""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"
        if "PREFIX" in cls.__dict__:
            # Only a class that names its own C functions mirrors a C type.
            cls.C_TYPE = f"{cls.__module__.replace('.', '_')}_{cls.__name__}"

    @classmethod
    def from_pointer(cls: type[T], pointer: int) -> T:
        """The object that owns ``pointer``, a handle of this type created by umilib."""
        state = cls.__new__(cls)
        Handle.__init__(state, pointer)
        return state

    def reset(self) -> None:
        """Returns the state to its start."""
        self.library.call(f"{self.PREFIX}_reset", self.handle)

    def clone(self: T) -> T:
        """A copy of the state."""
        return type(self).from_pointer(Handle.create(f"{self.PREFIX}_clone", self.handle))

    def consume(self, name: str, *arguments: Any) -> None:
        """Calls the C function ``name``, which releases this object on success."""
        with self.locked():
            self.library.call(name, self.pointer, *arguments)
            self.consumed()


class Digest(Hasher):
    """A hash function with a fixed output size, as the Rust trait ``Digest``.

    ``OUTPUT_SIZE`` and ``BLOCK_SIZE`` are the sizes in bytes. A subclass of an
    unkeyed function is created with no arguments.
    """

    OUTPUT_SIZE: ClassVar[Any]
    BLOCK_SIZE: ClassVar[Any]

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            prefix = cls.PREFIX
            cls.OUTPUT_SIZE = Preset(lambda: Library.default().function(f"{prefix}_output_size")())
            cls.BLOCK_SIZE = Preset(lambda: Library.default().function(f"{prefix}_block_size")())

    def __init__(self, pointer: int | None = None) -> None:
        if pointer is None:
            pointer = Handle.create(f"{self.PREFIX}_new")
        super().__init__(pointer)

    @classmethod
    def new(cls: type[T]) -> T:
        """The state of the empty input."""
        return cls()

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data`` to the input."""
        data, length = Bytes.readable(data)
        self.library.call(f"{self.PREFIX}_update", self.handle, data, length)

    def finalize(self) -> bytes:
        """The hash of the input; releases the state."""
        out = (ctypes.c_uint8 * self.OUTPUT_SIZE)()
        self.consume(f"{self.PREFIX}_finalize", out, len(out))
        return bytes(out)

    def finalize_reset(self) -> bytes:
        """The hash of the input; returns the state to its start."""
        out = (ctypes.c_uint8 * self.OUTPUT_SIZE)()
        self.library.call(f"{self.PREFIX}_finalize_reset", self.handle, out, len(out))
        return bytes(out)

    @classmethod
    def digest(cls, data: bytes | bytearray | memoryview) -> bytes:
        """The hash of ``data`` (unkeyed functions only)."""
        out = (ctypes.c_uint8 * cls.OUTPUT_SIZE)()
        data, length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_digest", data, length, out, len(out))
        return bytes(out)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class CryptographicDigest(Digest):
    """A :class:`Digest` designed as a cryptographic hash function, as the
    Rust trait ``CryptographicDigest``: what ``HMAC`` and the DRBGs accept."""


class XOFReader(Handle):
    """The output of an extendable-output function, read in order, as the Rust trait ``XOFReader``."""

    PREFIX: ClassVar[str] = ""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"

    def read(self, length: int) -> bytes:
        """The next ``length`` bytes of output."""
        out = (ctypes.c_uint8 * length)()
        self.library.call(f"{self.PREFIX}_read", self.handle, out, length)
        return bytes(out)

    def read_into(self, out: bytearray) -> None:
        """Fills ``out`` with the next bytes of output."""
        self.library.call(f"{self.PREFIX}_read", self.handle, Bytes.mutable(out), len(out))

    def clone(self) -> XOFReader:
        """A copy of the reader at the same position."""
        return type(self)(Handle.create(f"{self.PREFIX}_clone", self.handle))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class ExtendableOutput(Hasher):
    """A hash function with output of any length, as the Rust trait ``ExtendableOutput``.

    ``READER`` is the :class:`XOFReader` type that :meth:`finalize_xof` returns.
    """

    READER: ClassVar[type[XOFReader]]
    BLOCK_SIZE: ClassVar[Any]

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            prefix = cls.PREFIX
            cls.BLOCK_SIZE = Preset(lambda: Library.default().function(f"{prefix}_block_size")())

    def __init__(self, pointer: int | None = None) -> None:
        if pointer is None:
            pointer = Handle.create(f"{self.PREFIX}_new")
        super().__init__(pointer)

    @classmethod
    def new(cls: type[T]) -> T:
        """The state of the empty input."""
        return cls()

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data`` to the input."""
        data, length = Bytes.readable(data)
        self.library.call(f"{self.PREFIX}_update", self.handle, data, length)

    def finalize_xof(self) -> XOFReader:
        """The reader of the output; releases the state."""
        out = ctypes.c_void_p()
        self.consume(f"{self.PREFIX}_finalize_xof", ctypes.byref(out))
        return self.READER(out.value)

    @classmethod
    def digest_xof(cls, data: bytes | bytearray | memoryview, length: int) -> bytes:
        """The first ``length`` output bytes for ``data`` (unkeyed functions only)."""
        out = (ctypes.c_uint8 * length)()
        data, data_length = Bytes.readable(data)
        Library.default().call(f"{cls.PREFIX}_digest_xof", data, data_length, out, length)
        return bytes(out)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


__all__ = ["CryptographicDigest", "Digest", "ExtendableOutput", "HashError", "Hasher", "XOFReader"]
