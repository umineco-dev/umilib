"""BLAKE2 (RFC 7693) with the parallel and extendable-output variants. Mirrors ``umilib::hash::blake::v2``.

:class:`BLAKE2b` and :class:`BLAKE2s` take any output length and any
parameters; :class:`BLAKE2bp`, :class:`BLAKE2sp`, :class:`BLAKE2Xb` and
:class:`BLAKE2Xs` are the parallel and extendable-output modes; the
fixed-length types such as :class:`BLAKE2b512` are :class:`~umilib.hash.Digest`
objects, unkeyed when created with no key.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.ffi import Bytes, Fields, Handle, Library
from umilib.hash import CryptographicDigest, Hasher, XOFReader

P = "umilib_hash_blake_v2"


class BLAKE2bParameters:
    """The parameter block of BLAKE2b: its fields are attributes, as in the Rust structure."""

    STRUCTURE: ClassVar[str] = f"{P}_BLAKE2bParameters"
    FUNCTIONS: ClassVar[str] = f"{P}_blake2b_parameters"
    BLOCK: ClassVar[int] = 64
    FIELDS: ClassVar[tuple[str, ...]] = (
        "digest_length",
        "key_length",
        "fanout",
        "depth",
        "leaf_length",
        "node_offset",
        "xof_length",
        "node_depth",
        "inner_length",
        "salt",
        "personal",
    )

    def __init__(self, digest_length: int) -> None:
        """The sequential mode (fanout and depth 1) with ``digest_length`` bytes of output."""
        self.from_structure(Library.default().function(f"{self.FUNCTIONS}_new")(digest_length))

    @classmethod
    def new(cls, digest_length: int) -> Any:
        return cls(digest_length)

    def from_structure(self, structure: Any) -> None:
        for name in self.FIELDS:
            value = getattr(structure, name)
            setattr(self, name, bytes(value) if name in ("salt", "personal") else value)

    def structure(self) -> Any:
        """The C structure with the values of the attributes."""
        structure = Library.default().type(self.STRUCTURE)()
        for name in self.FIELDS:
            value = getattr(self, name)
            if name in ("salt", "personal"):
                field = getattr(structure, name)
                if len(value) != len(field):
                    raise ValueError(f"{name} has {len(field)} bytes")
                ctypes.memmove(field, bytes(value), len(field))
            else:
                Fields.assign(structure, name, value)
        return structure

    def to_bytes(self) -> bytes:
        """The parameter block in the byte order of RFC 7693 section 2.5."""
        structure = self.structure()
        out = (ctypes.c_uint8 * self.BLOCK)()
        Library.default().call(f"{self.FUNCTIONS}_to_bytes", ctypes.byref(structure), out, self.BLOCK)
        return bytes(out)

    @classmethod
    def from_bytes(cls, block: bytes) -> Any:
        """The parameters of ``block``."""
        library = Library.default()
        structure = library.type(cls.STRUCTURE)()
        data, length = Bytes.readable(block)
        library.call(f"{cls.FUNCTIONS}_from_bytes", data, length, ctypes.byref(structure))
        parameters = cls.__new__(cls)
        parameters.from_structure(structure)
        return parameters

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and all(getattr(self, name) == getattr(other, name) for name in self.FIELDS)

    def __repr__(self) -> str:
        fields = ", ".join(f"{name}={getattr(self, name)!r}" for name in self.FIELDS)
        return f"{type(self).__name__}({fields})"


class BLAKE2sParameters(BLAKE2bParameters):
    """The parameter block of BLAKE2s: its fields are attributes, as in the Rust structure."""

    STRUCTURE = f"{P}_BLAKE2sParameters"
    FUNCTIONS = f"{P}_blake2s_parameters"
    BLOCK = 32


class BLAKE2Variable(Hasher):
    """The methods that the engines, the parallel modes and BLAKE2X share, as
    their Rust types do: the output has the length they were created with."""

    def __init__(self, output_length: int, key: bytes = b"") -> None:
        if key:
            data, length = Bytes.readable(key)
            pointer = Handle.create(f"{self.PREFIX}_with_key", data, length, output_length)
        else:
            pointer = Handle.create(f"{self.PREFIX}_new", output_length)
        super().__init__(pointer)

    @classmethod
    def new(cls, output_length: int) -> Any:
        return cls(output_length)

    @classmethod
    def with_key(cls, key: bytes, output_length: int) -> Any:
        """The keyed function; an empty key is the unkeyed function."""
        return cls(output_length, key)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data`` to the input."""
        data, length = Bytes.readable(data)
        self.library.call(f"{self.PREFIX}_update", self.handle, data, length)

    def output_length(self) -> int:
        return self.library.value(f"{self.PREFIX}_output_length", ctypes.c_size_t, self.handle)

    def finalize_into(self, out: bytearray) -> None:
        """Writes the output into ``out``, which must have the output length (any
        length but 0 for BLAKE2X of unknown length), and returns the state to its start."""
        self.library.call(f"{self.PREFIX}_finalize_into", self.handle, Bytes.mutable(out), len(out))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.output_length()} bytes, ..)"


class BLAKE2b(BLAKE2Variable):
    """BLAKE2b with any output length of 1 to 64 bytes and any parameters."""

    PREFIX = f"{P}_blake2b"
    PARAMETERS: ClassVar[type[BLAKE2bParameters]] = BLAKE2bParameters

    @classmethod
    def with_parameters(cls, parameters: BLAKE2bParameters, key: bytes = b"") -> Any:
        """The function with every parameter given; ``parameters.key_length`` must be ``len(key)``."""
        structure = parameters.structure()
        data, length = Bytes.readable(key)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_parameters", ctypes.byref(structure), data, length))

    @classmethod
    def without_key_block(cls, parameters: BLAKE2bParameters) -> Any:
        """The function with the parameter block and no key block, as the root of the parallel modes."""
        structure = parameters.structure()
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_without_key_block", ctypes.byref(structure)))

    def set_last_node(self, last_node: bool) -> None:
        """Marks the state as the last node of its tree level, or not."""
        self.library.call(f"{self.PREFIX}_set_last_node", self.handle, last_node)


class BLAKE2s(BLAKE2b):
    """BLAKE2s with any output length of 1 to 32 bytes and any parameters."""

    PREFIX = f"{P}_blake2s"
    PARAMETERS = BLAKE2sParameters


class BLAKE2bp(BLAKE2Variable):
    """BLAKE2bp: BLAKE2b over 4 interleaved leaves."""

    PREFIX = f"{P}_blake2bp"


class BLAKE2sp(BLAKE2Variable):
    """BLAKE2sp: BLAKE2s over 8 interleaved leaves."""

    PREFIX = f"{P}_blake2sp"


class BLAKE2XbReader(XOFReader):
    """The output of BLAKE2Xb, computed node by node; reading past its length raises."""

    PREFIX = f"{P}_blake2xb_reader"


class BLAKE2XsReader(XOFReader):
    """The output of BLAKE2Xs, computed node by node; reading past its length raises."""

    PREFIX = f"{P}_blake2xs_reader"


class BLAKE2Xb(BLAKE2Variable):
    """BLAKE2Xb: outputs of up to 2^32 - 2 bytes over BLAKE2b; :attr:`UNKNOWN_LENGTH` leaves the length open."""

    PREFIX = f"{P}_blake2xb"
    UNKNOWN_LENGTH: ClassVar[int] = (1 << 32) - 1
    PARAMETERS: ClassVar[type[BLAKE2bParameters]] = BLAKE2bParameters
    READER: ClassVar[type[XOFReader]] = BLAKE2XbReader

    @classmethod
    def with_parameters(cls, parameters: BLAKE2bParameters, key: bytes = b"") -> Any:
        """BLAKE2X with every parameter of the root given, such as a salt and a personalization."""
        structure = parameters.structure()
        data, length = Bytes.readable(key)
        return cls.from_pointer(Handle.create(f"{cls.PREFIX}_with_parameters", ctypes.byref(structure), data, length))

    def finalize_xof(self) -> XOFReader:
        """The reader of the output, computed node by node; releases the state."""
        out = ctypes.c_void_p()
        self.consume(f"{self.PREFIX}_finalize_xof", ctypes.byref(out))
        return self.READER(out.value)


class BLAKE2Xs(BLAKE2Xb):
    """BLAKE2Xs: outputs of up to 2^16 - 2 bytes over BLAKE2s; :attr:`UNKNOWN_LENGTH` leaves the length open."""

    PREFIX = f"{P}_blake2xs"
    UNKNOWN_LENGTH = (1 << 16) - 1
    PARAMETERS = BLAKE2sParameters
    READER = BLAKE2XsReader


class BLAKE2Fixed(CryptographicDigest):
    """The constructors that the fixed-length types share, as their Rust types
    do: unkeyed when created with no key."""

    def __init__(self, key: bytes = b"") -> None:
        if key:
            data, length = Bytes.readable(key)
            pointer = Handle.create(f"{self.PREFIX}_with_key", data, length)
        else:
            pointer = Handle.create(f"{self.PREFIX}_new")
        Handle.__init__(self, pointer)

    @classmethod
    def with_key(cls, key: bytes) -> Any:
        """The keyed function (a MAC)."""
        return cls(key)


class BLAKE2b160(BLAKE2Fixed):
    """BLAKE2b with 160 bits of output."""

    PREFIX = f"{P}_blake2b160"


class BLAKE2b256(BLAKE2Fixed):
    """BLAKE2b with 256 bits of output."""

    PREFIX = f"{P}_blake2b256"


class BLAKE2b384(BLAKE2Fixed):
    """BLAKE2b with 384 bits of output."""

    PREFIX = f"{P}_blake2b384"


class BLAKE2b512(BLAKE2Fixed):
    """BLAKE2b with 512 bits of output."""

    PREFIX = f"{P}_blake2b512"


class BLAKE2s128(BLAKE2Fixed):
    """BLAKE2s with 128 bits of output."""

    PREFIX = f"{P}_blake2s128"


class BLAKE2s160(BLAKE2Fixed):
    """BLAKE2s with 160 bits of output."""

    PREFIX = f"{P}_blake2s160"


class BLAKE2s224(BLAKE2Fixed):
    """BLAKE2s with 224 bits of output."""

    PREFIX = f"{P}_blake2s224"


class BLAKE2s256(BLAKE2Fixed):
    """BLAKE2s with 256 bits of output."""

    PREFIX = f"{P}_blake2s256"


__all__ = [
    "BLAKE2Fixed",
    "BLAKE2Variable",
    "BLAKE2Xb",
    "BLAKE2XbReader",
    "BLAKE2Xs",
    "BLAKE2XsReader",
    "BLAKE2b",
    "BLAKE2b160",
    "BLAKE2b256",
    "BLAKE2b384",
    "BLAKE2b512",
    "BLAKE2bParameters",
    "BLAKE2bp",
    "BLAKE2s",
    "BLAKE2s128",
    "BLAKE2s160",
    "BLAKE2s224",
    "BLAKE2s256",
    "BLAKE2sParameters",
    "BLAKE2sp",
]
