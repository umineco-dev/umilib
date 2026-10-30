"""Handling of secret values. Mirrors ``umilib::secret``.

Python cannot guarantee that copies of secret bytes are erased, so keep
secrets in :class:`Secret` (memory owned and zeroized by umilib) or in a
``bytearray`` passed to :meth:`Zeroize.zeroize`, and avoid converting them to
``bytes`` or ``str``.
"""

from __future__ import annotations

import ctypes
import weakref

from umilib.ffi import Bytes, FFIError, Handle, Library, Preset


class Choice:
    """A secret boolean, stored as ``0`` or ``1``, combined without branching."""

    TRUE: Choice
    FALSE: Choice

    def __init__(self, bit: int) -> None:
        self.value = bit & 1

    @classmethod
    def from_bit(cls, bit: int) -> Choice:
        return cls(Library.default().function("umilib_secret_choice_from_bit")(bit & 0xFF))

    @classmethod
    def from_bool(cls, value: bool) -> Choice:
        """Mirrors ``Choice::from(bool)``."""
        return cls.from_bit(1 if value else 0)

    def bit(self) -> int:
        return self.value

    def into_bool(self) -> bool:
        """Reveals the choice. Only call this when the result may become public."""
        return bool(Library.default().function("umilib_secret_choice_into_bool")(self.value))

    def __and__(self, other: Choice) -> Choice:
        return Choice(Library.default().function("umilib_secret_choice_and")(self.value, other.value))

    def __or__(self, other: Choice) -> Choice:
        return Choice(Library.default().function("umilib_secret_choice_or")(self.value, other.value))

    def __xor__(self, other: Choice) -> Choice:
        return Choice(Library.default().function("umilib_secret_choice_xor")(self.value, other.value))

    def __invert__(self) -> Choice:
        return Choice(Library.default().function("umilib_secret_choice_not")(self.value))

    def __repr__(self) -> str:
        return "Choice(..)"


Choice.TRUE = Choice(1)
Choice.FALSE = Choice(0)


class ConstantTimeEq:
    """Equality of byte sequences that takes the same time for every value of the same length."""

    @staticmethod
    def ct_eq(a: bytes | bytearray | memoryview, b: bytes | bytearray | memoryview) -> Choice:
        """Compares without copying ``bytearray`` or writable ``memoryview`` arguments."""
        (a, a_length), (b, b_length) = Bytes.readable(a), Bytes.readable(b)
        return Choice(Library.default().value("umilib_secret_constant_time_eq_ct_eq", ctypes.c_uint8, a, a_length, b, b_length))

    @staticmethod
    def ct_ne(a: bytes | bytearray | memoryview, b: bytes | bytearray | memoryview) -> Choice:
        (a, a_length), (b, b_length) = Bytes.readable(a), Bytes.readable(b)
        return Choice(Library.default().value("umilib_secret_constant_time_eq_ct_ne", ctypes.c_uint8, a, a_length, b, b_length))


class ConditionallySelectable:
    """Selection between byte sequences of equal length without branching on the secret choice."""

    @staticmethod
    def select(a: bytes | bytearray, b: bytes | bytearray, choice: Choice) -> bytearray:
        """Returns a new ``bytearray`` holding ``a`` if ``choice`` is false and ``b`` if it is true."""
        (a, a_length), (b, b_length) = Bytes.readable(a), Bytes.readable(b)
        if a_length != b_length:
            raise FFIError("ffi", "InvalidArgument", "both sequences must have the same length")
        out = bytearray(a_length)
        Library.default().call("umilib_secret_conditionally_selectable_select", a, b, a_length, choice.value, Bytes.mutable(out))
        return out

    @staticmethod
    def conditional_assign(target: bytearray, source: bytes | bytearray, choice: Choice) -> None:
        """Overwrites ``target`` with ``source`` if ``choice`` is true."""
        source, length = Bytes.readable(source)
        if len(target) != length:
            raise FFIError("ffi", "InvalidArgument", "both sequences must have the same length")
        Library.default().call(
            "umilib_secret_conditionally_selectable_conditional_assign", Bytes.mutable(target), source, length, choice.value
        )

    @staticmethod
    def conditional_swap(a: bytearray, b: bytearray, choice: Choice) -> None:
        """Swaps the contents of ``a`` and ``b`` if ``choice`` is true."""
        if len(a) != len(b):
            raise FFIError("ffi", "InvalidArgument", "both sequences must have the same length")
        Library.default().call(
            "umilib_secret_conditionally_selectable_conditional_swap", Bytes.mutable(a), Bytes.mutable(b), len(a), choice.value
        )


class DataIndependentTiming:
    """Keeps the processor in its data-independent timing mode within a ``with`` block.

    The mode belongs to the calling thread (``PSTATE.DIT`` on Arm processors
    with FEAT_DIT, such as Apple silicon); see the Rust type for details. The
    guard is released when the block ends, on the thread that entered it,
    which is why this class is used only as a context manager.
    """

    AVAILABLE = Preset(lambda: bool(Library.default().function("umilib_secret_data_independent_timing_available")()))

    def __init__(self) -> None:
        self.guard: int | None = None

    @staticmethod
    def is_enabled() -> bool:
        return bool(Library.default().function("umilib_secret_data_independent_timing_is_enabled")())

    def __enter__(self) -> DataIndependentTiming:
        if self.guard is not None:
            raise FFIError("secret", "Reentrant", "the guard is already entered")
        out = ctypes.c_void_p()
        Library.default().call("umilib_secret_data_independent_timing_enable", ctypes.byref(out))
        self.guard = out.value
        return self

    def __exit__(self, *exception: object) -> None:
        guard, self.guard = self.guard, None
        Library.default().function("umilib_secret_data_independent_timing_free")(guard)


class Zeroize:
    """Overwriting memory with zeros in a way the compiler does not remove."""

    @staticmethod
    def zeroize(data: bytearray) -> None:
        Library.default().call("umilib_secret_zeroize_zeroize", Bytes.mutable(data), len(data))


class Secret(Handle):
    """Bytes owned by umilib that are zeroized when released and never printed."""

    FREE = "umilib_secret_secret_free"

    def __init__(self, data: bytes | bytearray) -> None:
        """Copies ``data`` into umilib. A ``bytearray`` is zeroized afterwards, as
        ownership of the value moves into the secret, like ``Secret::new`` in Rust."""
        source = data if isinstance(data, bytearray) else bytearray(data)
        self.views: list[weakref.ref] = []
        try:
            super().__init__(Handle.create("umilib_secret_secret_new", Bytes.mutable(source), len(source)))
        finally:
            Zeroize.zeroize(source)

    def location(self) -> tuple[int | None, int]:
        """The address and length of the secret bytes inside umilib."""
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call("umilib_secret_secret_expose", self.handle, ctypes.byref(pointer), ctypes.byref(length))
        return pointer.value, length.value

    def location_mut(self) -> tuple[int | None, int]:
        """The address and length of the secret bytes inside umilib, to write them in place; hold the
        lock (:meth:`Handle.locked`) while the address is used."""
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call("umilib_secret_secret_expose_mut", self.handle, ctypes.byref(pointer), ctypes.byref(length))
        return pointer.value, length.value

    def expose(self) -> bytes:
        """A copy of the secret bytes; prefer :meth:`expose_mut`, which does not copy."""
        with self.locked():
            pointer, length = self.location()
            return ctypes.string_at(pointer, length) if length else b""

    def expose_mut(self) -> memoryview:
        """A view of the secret bytes inside umilib. The view keeps the secret
        alive; using it after :meth:`close` is not allowed."""
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call("umilib_secret_secret_expose_mut", self.handle, ctypes.byref(pointer), ctypes.byref(length))
        if not length.value:
            return memoryview(bytearray())
        array = (ctypes.c_uint8 * length.value).from_address(pointer.value)
        array.owner = self  # the view keeps the secret, and so its memory, alive
        self.views.append(weakref.ref(array))
        return memoryview(array).cast("B")

    def close(self) -> None:
        """Zeroizes and releases the secret. Fails while a view from
        :meth:`expose_mut` is still in use, because it would point to freed memory."""
        self.views = [view for view in self.views if view() is not None]
        if self.views:
            raise FFIError("secret", "Borrowed", "a view from expose_mut is still in use")
        super().close()

    def ct_eq(self, other: Secret) -> Choice:
        """Compares two secrets without copying them."""
        with Handle.locked_all(self, other):
            (a, a_length), (b, b_length) = self.location(), other.location()
            return Choice(self.library.value("umilib_secret_constant_time_eq_ct_eq", ctypes.c_uint8, a, a_length, b, b_length))

    def __repr__(self) -> str:
        return "Secret(..)"


class ConstantTimeTable32_8(Handle):
    """``ConstantTimeTable<32, 8>``: a table of 256 entries of 8 bits whose reads and writes take the
    same time for every index, as each touches every word of the table. An index is taken modulo 256."""

    FREE = "umilib_secret_constant_time_table32_8_free"
    PREFIX = "umilib_secret_constant_time_table32_8"
    ENTRIES = 256

    def __init__(self, entries: bytes | bytearray | memoryview | None = None) -> None:
        """The table of the 256 ``entries``, or of zeros."""
        if entries is None:
            super().__init__(Handle.create(f"{self.PREFIX}_new"))
            return
        data, length = Bytes.readable(entries)
        super().__init__(Handle.create(f"{self.PREFIX}_from_bytes", data, length))

    @classmethod
    def from_bytes(cls, entries: bytes | bytearray | memoryview) -> ConstantTimeTable32_8:
        return cls(entries)

    def clone(self) -> ConstantTimeTable32_8:
        copy = type(self).__new__(type(self))
        Handle.__init__(copy, Handle.create(f"{self.PREFIX}_clone", self.handle))
        return copy

    def get(self, index: int) -> int:
        return self.library.value(f"{self.PREFIX}_get", ctypes.c_uint32, self.handle, index)

    def set(self, index: int, value: int) -> None:
        """Replaces the entry at ``index`` with the low 8 bits of ``value``."""
        self.library.call(f"{self.PREFIX}_set", self.handle, index, value)

    def swap(self, first: int, second: int) -> None:
        self.library.call(f"{self.PREFIX}_swap", self.handle, first, second)

    def words(self) -> list[int]:
        """The 32 packed words: entry ``i`` is bits 8 × (``i`` mod 8) and up of word ``i`` / 8."""
        out = (ctypes.c_uint64 * 32)()
        self.library.call(f"{self.PREFIX}_words", self.handle, out)
        return list(out)

    @staticmethod
    def mask(a: int, b: int) -> int:
        """All ones if ``a == b`` and zero otherwise, without branching on them."""
        return Library.default().function("umilib_secret_constant_time_table32_8_mask")(a, b)

    def __repr__(self) -> str:
        return "ConstantTimeTable32_8(..)"


Library.register_error("secret", FFIError)

__all__ = [
    "Choice",
    "ConditionallySelectable",
    "ConstantTimeEq",
    "ConstantTimeTable32_8",
    "DataIndependentTiming",
    "Secret",
    "Zeroize",
]
