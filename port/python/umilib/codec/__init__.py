"""Codecs: conversions between representations of data, and compression. Mirrors ``umilib::codec``.

:class:`Compressor` and :class:`Decompressor` are the bases of the types of
every compressed format, as the Rust traits of the same names are: each
subclass names the C functions of its type with ``PREFIX``. A call works on
caller-provided buffers and reports what it did in a :class:`Progress`.
Errors are :class:`CompressionError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import Any, ClassVar, TypeVar

from umilib.ffi import Bytes, FFIError, Handle, Library

T = TypeVar("T", bound="Codec")


class CompressionError(FFIError):
    """An error of a compressor or a decompressor; ``name`` is the variant, such as ``InvalidData``."""


Library.register_error("codec", CompressionError)


class Flush(enum.IntEnum):
    """What a :class:`Compressor` does with the input it has buffered (``None_``
    stands for Rust's ``Flush::None``, a keyword in Python)."""

    None_ = 0
    Sync = 1
    Finish = 2


@dataclasses.dataclass(frozen=True)
class Progress:
    """What one call did: the bytes it consumed and produced, and whether the stream ended."""

    consumed: int
    produced: int
    finished: bool


class Codec(Handle):
    """The functions compressors and decompressors share: ``reset`` and ``clone``.

    A subclass sets ``PREFIX``, the start of the names of its C functions,
    such as ``umilib_codec_huffman_adaptive_adaptive_huffman_compressor``.
    """

    PREFIX: ClassVar[str] = ""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"

    @classmethod
    def from_pointer(cls: type[T], pointer: int) -> T:
        """The object that owns ``pointer``, a handle of this type created by umilib."""
        state = cls.__new__(cls)
        Handle.__init__(state, pointer)
        return state

    def reset(self) -> None:
        """Returns to the state of a new stream, keeping the parameters."""
        self.library.call(f"{self.PREFIX}_reset", self.handle)

    def clone(self: T) -> T:
        """A copy of the state."""
        return type(self).from_pointer(Handle.create(f"{self.PREFIX}_clone", self.handle))

    def progress(self, name: str, *arguments: Any) -> Progress:
        """Calls ``name`` with a trailing ``umilib_codec_Progress`` output and returns it."""
        out = self.library.type("umilib_codec_Progress")()
        self.library.call(name, self.handle, *arguments, ctypes.byref(out))
        return Progress(out.consumed, out.produced, bool(out.finished))


class Compressor(Codec):
    """A streaming compressor, as the Rust trait ``Compressor``."""

    def compress(self, input: bytes | bytearray | memoryview, output: bytearray | memoryview, flush: Flush = Flush.None_) -> Progress:
        """Compresses from ``input`` into ``output`` (changed in place), as ``flush`` asks."""
        data, length = Bytes.readable(input)
        return self.progress(f"{self.PREFIX}_compress", data, length, Bytes.mutable(output), len(output), int(flush))

    def compress_to_vec(self, input: bytes | bytearray | memoryview) -> bytes:
        """The whole stream of ``input``, compressed and finished."""
        data, length = Bytes.readable(input)
        return self.library.output(f"{self.PREFIX}_compress_to_vec", self.handle, data, length)


class Decompressor(Codec):
    """A streaming decompressor, as the Rust trait ``Decompressor``."""

    def decompress(self, input: bytes | bytearray | memoryview, output: bytearray | memoryview) -> Progress:
        """Decompresses from ``input`` into ``output`` (changed in place)."""
        data, length = Bytes.readable(input)
        return self.progress(f"{self.PREFIX}_decompress", data, length, Bytes.mutable(output), len(output))

    def finish(self) -> None:
        """Tells the decompressor that the input ended with the bytes it consumed; raises
        ``UnexpectedEnd`` unless the stream may end there."""
        self.library.call(f"{self.PREFIX}_finish", self.handle)

    def decompress_to_vec(self, input: bytes | bytearray | memoryview, limit: int) -> bytes:
        """The data of the stream in ``input``, which must hold all of it, of at most ``limit`` bytes."""
        data, length = Bytes.readable(input)
        return self.library.output(f"{self.PREFIX}_decompress_to_vec", self.handle, data, length, limit)
