"""Arithmetic modulo an odd number, in constant time. Mirrors ``umilib::math::modular``.

A :class:`BoxedModulus` performs every operation; its values are
:class:`BoxedResidue` objects in the Montgomery form, which do not remember
their modulus: pass them only to the modulus that made them. ``Modulus``,
``Residue`` and ``ModularLimbs`` are not available, for the reasons given in
:mod:`umilib.math.bigint`. Errors are :class:`umilib.math.bigint.MathError`.
"""

from __future__ import annotations

import ctypes

from umilib.ffi import Handle, Library
from umilib.math.bigint import BoxedUint
from umilib.secret import Choice

P = "umilib_math_modular"


class BoxedResidue(Handle):
    """A value modulo a :class:`BoxedModulus`, in the Montgomery form; zeroized when released."""

    FREE = f"{P}_boxed_residue_free"

    @classmethod
    def from_montgomery_unchecked(cls, montgomery: BoxedUint) -> BoxedResidue:
        """The residue whose Montgomery form is ``montgomery``, which must be below the modulus
        and of its precision; :meth:`BoxedModulus.from_montgomery` checks both."""
        return cls(Handle.create(f"{P}_boxed_residue_from_montgomery_unchecked", montgomery.handle))

    def clone(self) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_residue_clone", self.handle))

    def as_montgomery(self) -> BoxedUint:
        """A copy of the Montgomery form ``x * R mod modulus`` of the value ``x``."""
        return BoxedUint(Handle.create(f"{P}_boxed_residue_as_montgomery", self.handle))

    def precision(self) -> int:
        return self.library.value(f"{P}_boxed_residue_precision", ctypes.c_uint32, self.handle)

    def conditional_assign(self, other: BoxedResidue, choice: Choice) -> None:
        """Sets ``self`` to ``other`` if ``choice``; both must have the same precision."""
        self.library.call(f"{P}_boxed_residue_conditional_assign", self.handle, other.handle, choice.bit())

    @staticmethod
    def conditional_swap(a: BoxedResidue, b: BoxedResidue, choice: Choice) -> None:
        Library.default().call(f"{P}_boxed_residue_conditional_swap", a.handle, b.handle, choice.bit())

    def ct_eq(self, other: BoxedResidue) -> Choice:
        return Choice(self.library.value(f"{P}_boxed_residue_ct_eq", ctypes.c_uint8, self.handle, other.handle))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BoxedResidue) and self.ct_eq(other).into_bool()

    __hash__ = None  # type: ignore[assignment]

    def zeroize(self) -> None:
        self.library.call(f"{P}_boxed_residue_zeroize", self.handle)

    def __repr__(self) -> str:
        return f"BoxedResidue(montgomery: 0x{self.as_montgomery():x})"


class BoxedModulus(Handle):
    """An odd modulus, at least 3, with its Montgomery constants; zeroized when released."""

    FREE = f"{P}_boxed_modulus_free"

    def __init__(self, value: BoxedUint | None = None, pointer: int | None = None) -> None:
        if pointer is None:
            if value is None:
                raise TypeError("BoxedModulus needs a value")
            pointer = Handle.create(f"{P}_boxed_modulus_new", value.handle)
        super().__init__(pointer)

    @classmethod
    def new(cls, value: BoxedUint) -> BoxedModulus:
        """Prepares a copy of ``value``; fails if it is even or below 3."""
        return cls(value)

    def clone(self) -> BoxedModulus:
        return BoxedModulus(pointer=Handle.create(f"{P}_boxed_modulus_clone", self.handle))

    def value(self) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_boxed_modulus_value", self.handle))

    def precision(self) -> int:
        return self.library.value(f"{P}_boxed_modulus_precision", ctypes.c_uint32, self.handle)

    def check(self, residue: BoxedResidue) -> None:
        """Raises unless ``residue`` has the precision of the modulus."""
        self.library.call(f"{P}_boxed_modulus_check", self.handle, residue.handle)

    def zero(self) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_zero", self.handle))

    def one(self) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_one", self.handle))

    def residue(self, x: BoxedUint) -> BoxedResidue:
        """``x mod modulus`` as a residue; ``x`` may have any precision."""
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_residue", self.handle, x.handle))

    def retrieve(self, residue: BoxedResidue) -> BoxedUint:
        return BoxedUint(Handle.create(f"{P}_boxed_modulus_retrieve", self.handle, residue.handle))

    def from_montgomery(self, montgomery: BoxedUint) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_from_montgomery", self.handle, montgomery.handle))

    def add(self, a: BoxedResidue, b: BoxedResidue) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_add", self.handle, a.handle, b.handle))

    def sub(self, a: BoxedResidue, b: BoxedResidue) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_sub", self.handle, a.handle, b.handle))

    def neg(self, a: BoxedResidue) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_neg", self.handle, a.handle))

    def mul(self, a: BoxedResidue, b: BoxedResidue) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_mul", self.handle, a.handle, b.handle))

    def square(self, a: BoxedResidue) -> BoxedResidue:
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_square", self.handle, a.handle))

    def pow(self, base: BoxedResidue, exponent: BoxedUint) -> BoxedResidue:
        """``base^exponent`` over every bit of the exponent's precision, in constant time."""
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_pow", self.handle, base.handle, exponent.handle))

    def pow_vartime(self, base: BoxedResidue, exponent: BoxedUint) -> BoxedResidue:
        """``base^exponent`` in time that depends on the exponent, which must be public."""
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_pow_vartime", self.handle, base.handle, exponent.handle))

    def invert(self, a: BoxedResidue) -> BoxedResidue:
        """``a^-1``; raises ``NotInvertible`` if it does not exist."""
        return BoxedResidue(Handle.create(f"{P}_boxed_modulus_invert", self.handle, a.handle))

    def ct_eq(self, other: BoxedModulus) -> Choice:
        return Choice(self.library.value(f"{P}_boxed_modulus_ct_eq", ctypes.c_uint8, self.handle, other.handle))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BoxedModulus) and self.ct_eq(other).into_bool()

    __hash__ = None  # type: ignore[assignment]

    def zeroize(self) -> None:
        """Zeroizes the modulus, which is unusable afterwards except to be released."""
        self.library.call(f"{P}_boxed_modulus_zeroize", self.handle)

    def __repr__(self) -> str:
        return f"BoxedModulus(0x{self.value():x})"
