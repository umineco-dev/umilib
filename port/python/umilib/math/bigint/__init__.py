"""Unsigned big integers of fixed precision, in constant time. Mirrors ``umilib::math::bigint``.

Only :class:`BoxedUint` is available: ``Uint`` has its precision in a Rust
const generic parameter, which the C ABI cannot name (a ``BoxedUint`` of the
same precision computes the same results), and ``Limbs`` works on native
words, whose size differs between platforms. Conversions to and from Python
``int`` are provided by :meth:`BoxedUint.from_int` and ``int(value)``; they
are not constant-time, and the ``int``, ``bytes`` and ``str`` objects they
make (``int(value)``, :meth:`BoxedUint.to_be_bytes`, ``format``, ``repr``)
cannot be erased: write secrets into a ``bytearray`` with
:meth:`BoxedUint.write_be_bytes` and erase it with ``Zeroize.zeroize``.
"""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, FFIError, Handle, Library, Preset, Text
from umilib.secret import Choice

P = "umilib_math_bigint_boxed_uint"


class MathError(FFIError):
    """An error of big integer or modular arithmetic; ``name`` is the variant, such as ``Overflow``."""


Library.register_error("math.bigint", MathError)


class BoxedUint(Handle):
    """An unsigned integer whose precision is chosen at run time.

    The precision is a multiple of :attr:`PRECISION_UNIT` bits. Operands of
    different precisions are zero-extended to the larger one. The value is
    zeroized when released. ``==`` compares in constant time and reveals only
    the result; ``&``, ``|``, ``^`` and ``~`` are the bitwise operators.
    """

    FREE = f"{P}_free"
    PRECISION_UNIT = Preset(lambda: Library.default().value(f"{P}_precision_unit", ctypes.c_uint32))
    MAXIMUM_PRECISION = Preset(lambda: Library.default().value(f"{P}_maximum_precision", ctypes.c_uint32))

    @classmethod
    def zero(cls, precision: int) -> BoxedUint:
        return cls(Handle.create(f"{P}_zero", precision))

    @classmethod
    def one(cls, precision: int) -> BoxedUint:
        return cls(Handle.create(f"{P}_one", precision))

    @classmethod
    def from_u64(cls, value: int, precision: int) -> BoxedUint:
        return cls(Handle.create(f"{P}_from_u64", value, precision))

    @classmethod
    def from_be_bytes(cls, data: bytes | bytearray | memoryview, precision: int) -> BoxedUint:
        data, length = Bytes.readable(data)
        return cls(Handle.create(f"{P}_from_be_bytes", data, length, precision))

    @classmethod
    def from_le_bytes(cls, data: bytes | bytearray | memoryview, precision: int) -> BoxedUint:
        data, length = Bytes.readable(data)
        return cls(Handle.create(f"{P}_from_le_bytes", data, length, precision))

    @classmethod
    def from_hex_vartime(cls, text: str, precision: int) -> BoxedUint:
        """Reads big-endian hexadecimal digits; the time depends on them."""
        data, length = Text.encode(text)
        return cls(Handle.create(f"{P}_from_hex_vartime", data, length, precision))

    @classmethod
    def from_int(cls, value: int, precision: int) -> BoxedUint:
        """The Python ``int`` ``value``, which must not be negative."""
        if value < 0:
            raise MathError("math.bigint", "Overflow", "the value does not fit")
        return cls.from_be_bytes(value.to_bytes((value.bit_length() + 7) // 8, "big"), precision)

    def __int__(self) -> int:
        return int.from_bytes(self.to_be_bytes(), "big")

    def clone(self) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_clone", self.handle))

    def resize(self, precision: int) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_resize", self.handle, precision))

    def precision(self) -> int:
        return self.library.value(f"{P}_precision", ctypes.c_uint32, self.handle)

    def bytes(self) -> int:
        """The number of bytes of the precision."""
        return self.library.value(f"{P}_bytes", ctypes.c_size_t, self.handle)

    def to_be_bytes(self) -> bytes:
        return self.library.output(f"{P}_to_be_bytes", self.handle)

    def to_le_bytes(self) -> bytes:
        return self.library.output(f"{P}_to_le_bytes", self.handle)

    def write_be_bytes(self, out: bytearray) -> None:
        """Writes the value big-endian into all of ``out``, with leading zeros."""
        self.library.call(f"{P}_write_be_bytes", self.handle, Bytes.mutable(out), len(out))

    def write_le_bytes(self, out: bytearray) -> None:
        self.library.call(f"{P}_write_le_bytes", self.handle, Bytes.mutable(out), len(out))

    def is_zero(self) -> Choice:
        return Choice(self.library.value(f"{P}_is_zero", ctypes.c_uint8, self.handle))

    def is_odd(self) -> Choice:
        return Choice(self.library.value(f"{P}_is_odd", ctypes.c_uint8, self.handle))

    def ct_eq(self, other: BoxedUint) -> Choice:
        return Choice(self.library.value(f"{P}_ct_eq", ctypes.c_uint8, self.handle, other.handle))

    def ct_lt(self, other: BoxedUint) -> Choice:
        return Choice(self.library.value(f"{P}_ct_lt", ctypes.c_uint8, self.handle, other.handle))

    def ct_gt(self, other: BoxedUint) -> Choice:
        return Choice(self.library.value(f"{P}_ct_gt", ctypes.c_uint8, self.handle, other.handle))

    def compare_vartime(self, other: BoxedUint) -> int:
        """-1, 0 or 1 as ``self`` is below, equal to or above ``other``; the time depends on the values."""
        return self.library.value(f"{P}_compare_vartime", ctypes.c_int8, self.handle, other.handle)

    def bit(self, index: int) -> Choice:
        return Choice(self.library.value(f"{P}_bit", ctypes.c_uint8, self.handle, index))

    def bit_length(self) -> int:
        return self.library.value(f"{P}_bit_length", ctypes.c_uint32, self.handle)

    def overflowing_add(self, other: BoxedUint) -> tuple[BoxedUint, Choice]:
        out, carry = ctypes.c_void_p(), ctypes.c_uint8()
        self.library.call(f"{P}_overflowing_add", self.handle, other.handle, ctypes.byref(out), ctypes.byref(carry))
        return BoxedUint(out.value), Choice(carry.value)

    def overflowing_sub(self, other: BoxedUint) -> tuple[BoxedUint, Choice]:
        out, borrow = ctypes.c_void_p(), ctypes.c_uint8()
        self.library.call(f"{P}_overflowing_sub", self.handle, other.handle, ctypes.byref(out), ctypes.byref(borrow))
        return BoxedUint(out.value), Choice(borrow.value)

    def wrapping_add(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_wrapping_add", self.handle, other.handle))

    def wrapping_sub(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_wrapping_sub", self.handle, other.handle))

    def wrapping_mul(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_wrapping_mul", self.handle, other.handle))

    def widening_mul(self, other: BoxedUint) -> tuple[BoxedUint, BoxedUint]:
        """The low and the high half of the full product."""
        low, high = ctypes.c_void_p(), ctypes.c_void_p()
        self.library.call(f"{P}_widening_mul", self.handle, other.handle, ctypes.byref(low), ctypes.byref(high))
        return BoxedUint(low.value), BoxedUint(high.value)

    def div_rem(self, divisor: BoxedUint) -> tuple[BoxedUint, BoxedUint]:
        """The quotient, in the precision of ``self``, and the remainder, in that of the divisor."""
        quotient, remainder = ctypes.c_void_p(), ctypes.c_void_p()
        self.library.call(f"{P}_div_rem", self.handle, divisor.handle, ctypes.byref(quotient), ctypes.byref(remainder))
        return BoxedUint(quotient.value), BoxedUint(remainder.value)

    def rem(self, modulus: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_rem", self.handle, modulus.handle))

    @staticmethod
    def rem_wide(low: BoxedUint, high: BoxedUint, modulus: BoxedUint) -> BoxedUint:
        """``(low + high * 2^precision(low)) mod modulus``."""
        return BoxedUint(Handle.create(f"{P}_rem_wide", low.handle, high.handle, modulus.handle))

    def shl(self, bits: int) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_shl", self.handle, bits))

    def shr(self, bits: int) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_shr", self.handle, bits))

    def __and__(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_bitand", self.handle, other.handle))

    def __or__(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_bitor", self.handle, other.handle))

    def __xor__(self, other: BoxedUint) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_bitxor", self.handle, other.handle))

    def __invert__(self) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_not", self.handle))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BoxedUint) and self.ct_eq(other).into_bool()

    __hash__ = None  # type: ignore[assignment] - mutable, like the Rust type, which has no Hash

    def conditional_assign(self, other: BoxedUint, choice: Choice) -> None:
        """Sets ``self`` to ``other`` if ``choice``; both must have the same precision."""
        self.library.call(f"{P}_conditional_assign", self.handle, other.handle, choice.bit())

    @staticmethod
    def conditional_swap(a: BoxedUint, b: BoxedUint, choice: Choice) -> None:
        Library.default().call(f"{P}_conditional_swap", a.handle, b.handle, choice.bit())

    def zeroize(self) -> None:
        """Sets the value to zero, keeping the precision."""
        self.library.call(f"{P}_zeroize", self.handle)

    def __format__(self, specification: str) -> str:
        """``x`` and ``X`` write every digit of the precision, as Rust's ``LowerHex`` and ``UpperHex`` do."""
        if specification == "x":
            return self.to_be_bytes().hex()
        if specification == "X":
            return self.to_be_bytes().hex().upper()
        if specification == "":
            return repr(self)
        raise ValueError(f"unsupported format {specification!r} for BoxedUint")

    def __repr__(self) -> str:
        return f"BoxedUint(0x{self:x})"
