"""Polynomial rings of module lattices and their number-theoretic transform. Mirrors
``umilib::math::lattice``.

``Polynomial[MLKEMRing]`` holds the n coefficients of an element of R_q (or, after :meth:`Polynomial.ntt`,
of T_q) as integers below q; the transforms and the product in T_q are computed by the library.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar, Iterable

from umilib.ffi import Library, Marker, Text


class LatticeRing(Marker, abstract=True):
    """A ring R_q = Z_q[X]/(X^n + 1), named by its C type name, with its modulus ``Q`` and degree ``N``."""

    Q: ClassVar[int] = 0
    N: ClassVar[int] = 0


class MLKEMRing(LatticeRing):
    """The ring of ML-KEM (FIPS 203 section 4.3): q = 3329, n = 256."""

    Q = 3329
    N = 256


class MLDSARing(LatticeRing):
    """The ring of ML-DSA (FIPS 204 section 7.5): q = 8380417, n = 256."""

    Q = 8380417
    N = 256


class Polynomial:
    """An element of the ring of ``Polynomial[R]``: its coefficients, each reduced modulo q."""

    RING: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, ring: Any) -> Any:
        from umilib.crypto import Specialization

        ring = LatticeRing.require(ring, "Polynomial")
        return Specialization.of(cls, (ring,), {"RING": ring})

    def __init__(self, coefficients: Iterable[int]) -> None:
        """The polynomial of n coefficients, each reduced modulo q."""
        if self.RING is None:
            raise TypeError("choose the ring first, as in Polynomial[MLKEMRing]")
        values = [value % self.RING.Q for value in coefficients]
        if len(values) != self.RING.N:
            raise ValueError(f"a polynomial of {self.RING.__name__} has {self.RING.N} coefficients")
        self.coefficients = values

    @classmethod
    def zero(cls) -> Any:
        return cls([0] * cls.RING.N)

    def transform(self, function: str, *others: Polynomial) -> Any:
        """The polynomial the function ``umilib_math_lattice_polynomial_{function}`` writes."""
        array = ctypes.c_uint32 * self.RING.N
        arguments: list[Any] = [*Text.encode(self.RING.C_TYPE)]
        for polynomial in (self, *others):
            if type(polynomial) is not type(self):
                raise TypeError(f"both polynomials must be of {type(self).__name__}")
            arguments.extend([array(*polynomial.coefficients), self.RING.N])
        out = array()
        Library.default().call(f"umilib_math_lattice_polynomial_{function}", *arguments, out, self.RING.N)
        return type(self)(list(out))

    def ntt(self) -> Any:
        """The NTT (FIPS 203 algorithm 9, FIPS 204 algorithm 41)."""
        return self.transform("ntt")

    def inverse_ntt(self) -> Any:
        """The inverse NTT (FIPS 203 algorithm 10, FIPS 204 algorithm 42)."""
        return self.transform("inverse_ntt")

    def multiply_ntt(self, other: Polynomial) -> Any:
        """The product in T_q of two NTT representations."""
        return self.transform("multiply_ntt", other)

    def add(self, other: Polynomial) -> Any:
        return type(self)([a + b for a, b in zip(self.coefficients, other.coefficients)])

    def sub(self, other: Polynomial) -> Any:
        return type(self)([a - b for a, b in zip(self.coefficients, other.coefficients)])

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return NotImplemented
        return self.coefficients == other.coefficients  # type: ignore[attr-defined]

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


__all__ = ["LatticeRing", "MLDSARing", "MLKEMRing", "Polynomial"]
