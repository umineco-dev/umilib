"""Filters: reversible transformations that keep the size of data. Mirrors ``umilib::codec::filter``.

:class:`Filter` is the base of the filter types, as the Rust trait of the same
name is; :class:`FilterChain` runs several of them over a stream, as the Rust
type of the same name does (in Python, over the filter objects).
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.ffi import Bytes, Handle


class Filter(Handle):
    """A filter, in place on successive pieces of a stream: ``encode`` and ``decode`` convert
    what they can and return how many bytes they converted; the rest (at most ``lookahead``
    bytes) is given again, followed by more data, and stays as it is at the end of the stream."""

    PREFIX: ClassVar[str] = ""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"

    @property
    def lookahead(self) -> int:
        """The most bytes at the end of a piece that may be left unconverted."""
        return self.library.value(f"{self.PREFIX}_lookahead", ctypes.c_size_t, self.handle)

    def encode(self, data: bytearray | memoryview) -> int:
        """Encodes in place the bytes it can of ``data``; returns how many."""
        return self.library.value(f"{self.PREFIX}_encode", ctypes.c_size_t, self.handle, Bytes.mutable(data), len(data))

    def decode(self, data: bytearray | memoryview) -> int:
        """Decodes in place the bytes it can of ``data``; returns how many."""
        return self.library.value(f"{self.PREFIX}_decode", ctypes.c_size_t, self.handle, Bytes.mutable(data), len(data))

    def reset(self) -> None:
        """Starts a new stream with the same parameters."""
        self.library.call(f"{self.PREFIX}_reset", self.handle)


class FilterChain:
    """Filters applied one after another to a stream: encoding in their order, decoding in the
    reverse order (the order of a .xz filter chain)."""

    def __init__(self, filters: list[Filter]) -> None:
        self.filters = list(filters)
        self.buffer = bytearray()
        self.converted = [0] * len(self.filters)

    def __len__(self) -> int:
        return len(self.buffer)

    @property
    def lookahead(self) -> int:
        """The most bytes the filters may hold back."""
        return sum(filter.lookahead for filter in self.filters)

    def extend(self, data: bytes | bytearray | memoryview) -> None:
        """Appends ``data`` to the stream."""
        self.buffer.extend(data)

    def encode(self, end: bool) -> None:
        """Encodes the new bytes with the filters in order; ``end`` says the stream ends with them."""
        self.run(end, True)

    def decode(self, end: bool) -> None:
        """Decodes the new bytes with the filters in reverse order."""
        self.run(end, False)

    def run(self, end: bool, encoding: bool) -> None:
        """Runs the filters as successive stages."""
        available = len(self.buffer)
        order = self.filters if encoding else list(reversed(self.filters))
        for stage, filter in enumerate(order):
            start = self.converted[stage]
            piece = memoryview(self.buffer)[start:available]
            done = filter.encode(piece) if encoding else filter.decode(piece)
            piece.release()
            self.converted[stage] = available if end else start + done
            available = self.converted[stage]

    def ready(self) -> bytes:
        """The bytes every filter has converted."""
        ready = self.converted[-1] if self.converted else len(self.buffer)
        return bytes(self.buffer[:ready])

    def consume(self, count: int) -> None:
        """Drops the first ``count`` ready bytes."""
        count = min(count, len(self.ready()))
        del self.buffer[:count]
        self.converted = [converted - count for converted in self.converted]

    def reset(self) -> None:
        """Starts a new stream: empties the buffer and resets the filters."""
        self.buffer.clear()
        self.converted = [0] * len(self.filters)
        for filter in self.filters:
            filter.reset()


__all__ = ["Filter", "FilterChain"]
