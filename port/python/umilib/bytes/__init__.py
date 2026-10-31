"""Reading and writing integers and byte sequences. Mirrors ``umilib::bytes``.

Rust type parameters become leading arguments: ``reader.read_be::<u32>()``
is ``reader.read_be(Integer.U32)``. Slices borrowed in Rust are returned as
``bytes`` copies.
"""

from __future__ import annotations

import ctypes
import enum

from umilib.ffi import Buffer as FFIBuffer
from umilib.ffi import Bytes, FFIError, Handle, I128, Library, U128


class BytesError(FFIError):
    """An error from :class:`Reader` or a :class:`Writer`; ``name`` is the variant."""


Library.register_error("bytes", BytesError)


class BitOrder(enum.IntEnum):
    """The order in which a stream of bits fills the bits of each byte, and in which a value read
    from it holds the bits."""

    LeastSignificantFirst = 0
    MostSignificantFirst = 1


class Integer(enum.Enum):
    """The integer types of ``umilib::bytes::Integer``: (suffix, size in bytes, signed)."""

    U8 = ("u8", 1, False)
    U16 = ("u16", 2, False)
    U32 = ("u32", 4, False)
    U64 = ("u64", 8, False)
    U128 = ("u128", 16, False)
    I8 = ("i8", 1, True)
    I16 = ("i16", 2, True)
    I32 = ("i32", 4, True)
    I64 = ("i64", 8, True)
    I128 = ("i128", 16, True)

    @classmethod
    def maximum_size(cls) -> int:
        """``Integer::MAXIMUM_SIZE``: the largest supported size, that of ``u128``."""
        return 16

    @property
    def suffix(self) -> str:
        return self.value[0]

    @property
    def SIZE(self) -> int:  # noqa: N802 - mirrors the Rust associated constant
        return self.value[1]

    @property
    def SIGNED(self) -> bool:  # noqa: N802 - mirrors the Rust associated constant
        return self.value[2]

    @property
    def ctype(self) -> type:
        if self is Integer.U128:
            return U128
        if self is Integer.I128:
            return I128
        return getattr(ctypes, f"c_{'int' if self.SIGNED else 'uint'}{self.SIZE * 8}")

    def to_c(self, value: int) -> object:
        if self.SIZE == 16:
            return self.ctype.from_int(value)
        bits = self.SIZE * 8
        low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if self.SIGNED else (0, (1 << bits) - 1)
        if not low <= value <= high:
            raise OverflowError(f"{value} does not fit in {self.suffix}")
        return value

    def from_c(self, value: object) -> int:
        return value.to_int() if self.SIZE == 16 else value


class Reader(Handle):
    """A cursor that reads from bytes without moving on failure."""

    FREE = "umilib_bytes_reader_free"

    def __init__(self, data: bytes, pointer: int | None = None, parent: Reader | None = None) -> None:
        self.data = bytes(data) if parent is None else parent.data
        self.parent = parent
        if pointer is None:
            pointer = Handle.create("umilib_bytes_reader_new", self.data, len(self.data))
        super().__init__(pointer)

    @staticmethod
    def slice_at(pointer: int, length: int) -> bytes:
        """Copies ``length`` bytes at ``pointer``, which points into the data of a reader."""
        return ctypes.string_at(pointer, length) if length else b""

    def position(self) -> int:
        return self.library.value("umilib_bytes_reader_position", ctypes.c_size_t, self.handle)

    def remaining(self) -> int:
        return self.library.value("umilib_bytes_reader_remaining", ctypes.c_size_t, self.handle)

    def is_empty(self) -> bool:
        return self.library.value("umilib_bytes_reader_is_empty", ctypes.c_bool, self.handle)

    def peek(self, length: int) -> bytes:
        pointer = self.library.value("umilib_bytes_reader_peek", ctypes.c_void_p, self.handle, length)
        return self.slice_at(pointer, length)

    def read_slice(self, length: int) -> bytes:
        pointer = self.library.value("umilib_bytes_reader_read_slice", ctypes.c_void_p, self.handle, length)
        return self.slice_at(pointer, length)

    def read_array(self, length: int) -> bytes:
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_bytes_reader_read_array", self.handle, length, out if length else None)
        return bytes(out)

    def read_reader(self, length: int) -> Reader:
        pointer = Handle.create("umilib_bytes_reader_read_reader", self.handle, length)
        return Reader(b"", pointer, self)

    def read_rest(self) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call("umilib_bytes_reader_read_rest", self.handle, ctypes.byref(pointer), ctypes.byref(length))
        return self.slice_at(pointer.value or 0, length.value)

    def skip(self, length: int) -> None:
        self.library.call("umilib_bytes_reader_skip", self.handle, length)

    def read_u8(self) -> int:
        return self.library.value("umilib_bytes_reader_read_u8", ctypes.c_uint8, self.handle)

    def read_be(self, integer: Integer) -> int:
        out = integer.ctype()
        self.library.call(f"umilib_bytes_reader_read_be_{integer.suffix}", self.handle, ctypes.byref(out))
        return integer.from_c(out.value if integer.SIZE < 16 else out)

    def read_le(self, integer: Integer) -> int:
        out = integer.ctype()
        self.library.call(f"umilib_bytes_reader_read_le_{integer.suffix}", self.handle, ctypes.byref(out))
        return integer.from_c(out.value if integer.SIZE < 16 else out)

    def read_be_sized(self, integer: Integer, length: int) -> int:
        out = integer.ctype()
        self.library.call(f"umilib_bytes_reader_read_be_sized_{integer.suffix}", self.handle, length, ctypes.byref(out))
        return integer.from_c(out.value if integer.SIZE < 16 else out)

    def read_le_sized(self, integer: Integer, length: int) -> int:
        out = integer.ctype()
        self.library.call(f"umilib_bytes_reader_read_le_sized_{integer.suffix}", self.handle, length, ctypes.byref(out))
        return integer.from_c(out.value if integer.SIZE < 16 else out)

    @staticmethod
    def check_length(integer: Integer, length: int) -> None:
        """Raises ``InvalidLength`` unless an integer of type ``integer`` fits in ``length`` bytes."""
        if length == 0 or length > integer.SIZE:
            raise BytesError("bytes", "InvalidLength", "integer length is zero or larger than the integer type")


class Writer(Handle):
    """A sink of bytes. Every write either succeeds completely or writes nothing."""

    PREFIX = ""

    def write(self, data: bytes) -> None:
        data = bytes(data)
        self.library.call(f"{self.PREFIX}_write", self.handle, data, len(data))

    def write_u8(self, value: int) -> None:
        self.library.call(f"{self.PREFIX}_write_u8", self.handle, Integer.U8.to_c(value))

    def write_be(self, integer: Integer, value: int) -> None:
        self.library.call(f"{self.PREFIX}_write_be_{integer.suffix}", self.handle, integer.to_c(value))

    def write_le(self, integer: Integer, value: int) -> None:
        self.library.call(f"{self.PREFIX}_write_le_{integer.suffix}", self.handle, integer.to_c(value))

    def write_be_sized(self, integer: Integer, value: int, length: int) -> None:
        self.library.call(f"{self.PREFIX}_write_be_sized_{integer.suffix}", self.handle, integer.to_c(value), length)

    def write_le_sized(self, integer: Integer, value: int, length: int) -> None:
        self.library.call(f"{self.PREFIX}_write_le_sized_{integer.suffix}", self.handle, integer.to_c(value), length)


class Buffer(Writer):
    """A growable byte buffer with an optional size limit."""

    FREE = "umilib_bytes_buffer_free"
    PREFIX = "umilib_bytes_buffer"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_bytes_buffer_new"))

    @classmethod
    def new(cls) -> Buffer:
        return cls()

    @classmethod
    def with_limit(cls, limit: int) -> Buffer:
        return cls(Handle.create("umilib_bytes_buffer_with_limit", limit))

    @classmethod
    def with_capacity(cls, capacity: int) -> Buffer:
        """Raises ``BytesError`` (``CapacityExceeded``) if the memory cannot be allocated."""
        return cls(Handle.create("umilib_bytes_buffer_with_capacity", capacity))

    @classmethod
    def try_with_capacity(cls, capacity: int) -> Buffer:
        return cls(Handle.create("umilib_bytes_buffer_try_with_capacity", capacity))

    def capacity(self) -> int:
        return self.library.value("umilib_bytes_buffer_capacity", ctypes.c_size_t, self.handle)

    @classmethod
    def from_bytes(cls, data: bytes) -> Buffer:
        """Mirrors ``Buffer::from(Vec<u8>)``."""
        buffer = cls()
        buffer.write(data)
        return buffer

    def limit(self) -> int | None:
        return self.library.optional("umilib_bytes_buffer_limit", ctypes.c_size_t, self.handle)

    def set_limit(self, limit: int | None) -> None:
        self.library.call("umilib_bytes_buffer_set_limit", self.handle, limit is not None, limit or 0)

    def len(self) -> int:
        return self.library.value("umilib_bytes_buffer_len", ctypes.c_size_t, self.handle)

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return self.library.value("umilib_bytes_buffer_is_empty", ctypes.c_bool, self.handle)

    def as_slice(self) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        with self.locked():
            self.library.call("umilib_bytes_buffer_as_slice", self.handle, ctypes.byref(pointer), ctypes.byref(length))
            return ctypes.string_at(pointer.value, length.value) if length.value else b""

    def clear(self) -> None:
        self.library.call("umilib_bytes_buffer_clear", self.handle)

    def truncate(self, length: int) -> None:
        self.library.call("umilib_bytes_buffer_truncate", self.handle, length)

    def into_vec(self) -> bytes:
        """Returns the written bytes and releases the buffer."""
        buffer = FFIBuffer()
        with self.locked():
            self.library.call("umilib_bytes_buffer_into_vec", self.handle, ctypes.byref(buffer))
            self.consumed()
        return self.library.take(buffer)


class SliceWriter(Writer):
    """A writer that fills a caller-provided ``bytearray`` from the start."""

    FREE = "umilib_bytes_slice_writer_free"
    PREFIX = "umilib_bytes_slice_writer"

    def __init__(self, storage: bytearray) -> None:
        self.storage = storage
        self.view = Bytes.mutable(storage)
        super().__init__(Handle.create("umilib_bytes_slice_writer_new", self.view, len(storage)))

    def position(self) -> int:
        return self.library.value("umilib_bytes_slice_writer_position", ctypes.c_size_t, self.handle)

    def capacity(self) -> int:
        return self.library.value("umilib_bytes_slice_writer_capacity", ctypes.c_size_t, self.handle)

    def free(self) -> None:
        """Releases the writer and the export of the ``bytearray``, which can then be resized."""
        super().free()
        self.view = None

    def remaining(self) -> int:
        return self.library.value("umilib_bytes_slice_writer_remaining", ctypes.c_size_t, self.handle)

    def written(self) -> bytes:
        return bytes(self.storage[: self.position()])

    def into_written(self) -> bytes:
        """Returns the written bytes and releases the writer."""
        with self.locked():
            length = self.library.value("umilib_bytes_slice_writer_into_written", ctypes.c_size_t, self.handle)
            self.consumed()
        self.view = None
        return bytes(self.storage[:length])


class LineBuffer(Handle):
    """Received bytes not yet read, read as lines ended by CRLF (a CR or an LF alone ends none) or as
    counted bytes. Mirrors ``umilib::bytes::LineBuffer``."""

    FREE = "umilib_bytes_line_buffer_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer if pointer is not None else Handle.create("umilib_bytes_line_buffer_new"))

    def push(self, data: bytes) -> None:
        self.library.call("umilib_bytes_line_buffer_push", self.handle, *Bytes.readable(data))

    def len(self) -> int:
        return self.library.value("umilib_bytes_line_buffer_len", ctypes.c_size_t, self.handle)

    def __len__(self) -> int:
        return self.len()

    def is_empty(self) -> bool:
        return self.len() == 0

    def unread(self) -> bytes:
        return self.library.output("umilib_bytes_line_buffer_unread", self.handle)

    def consume(self, count: int) -> None:
        self.library.call("umilib_bytes_line_buffer_consume", self.handle, count)

    def take(self, count: int) -> bytes:
        return self.library.output("umilib_bytes_line_buffer_take", self.handle, count)

    def clear(self) -> None:
        self.library.call("umilib_bytes_line_buffer_clear", self.handle)

    def line(self, maximum: int) -> bytes | None:
        """The next line, its CRLF removed, if a whole line is here; raises ``BytesError``
        (``LineTooLong``) once for a line of more than ``maximum`` bytes, whose rest is skipped."""
        return self.library.optional("umilib_bytes_line_buffer_line", FFIBuffer, self.handle, maximum)


__all__ = ["BitOrder", "Buffer", "BytesError", "Integer", "LineBuffer", "Reader", "SliceWriter", "Writer"]
