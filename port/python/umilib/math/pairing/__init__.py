"""Pairings on curves of embedding degree 12. Mirrors ``umilib::math::pairing``.

``Pairing[BLS12381].pairing(p, q)`` is e(P, Q) of a point of G_1 (SEC 1,
compressed or not) and a point of G_2 (x0 || x1 || y0 || y1), both in their
subgroups of order r, as the twelve coefficients of the element of G_T.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.ffi import Bytes, Library, Marker, Text


class PairingCurve(Marker, abstract=True):
    """A pairing-friendly curve, named by its C type name."""


class BLS12381(PairingCurve):
    """BLS12-381 of draft-irtf-cfrg-pairing-friendly-curves section 4.2.1."""


class BN254(PairingCurve):
    """BN254 (alt_bn128 of Ethereum), of no more than 100 bits of security (draft-irtf-cfrg-pairing-friendly-curves appendix D)."""


class BN462(PairingCurve):
    """BN462 of draft-irtf-cfrg-pairing-friendly-curves section 4.2.2."""


class SM9BN256(PairingCurve):
    """The BN curve of SM9 (GM/T 0044.5-2016 section 3.1), with its tower over u^2 = -2."""


class Pairing:
    """The optimal ate pairing of the curve of ``Pairing[C]``."""

    CURVE: ClassVar[Any] = None
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    def __class_getitem__(cls, curve: Any) -> Any:
        from umilib.crypto import Specialization

        curve = PairingCurve.require(curve, "Pairing")
        return Specialization.of(cls, (curve,), {"CURVE": curve})

    @classmethod
    def name(cls) -> tuple[Any, int]:
        if cls.CURVE is None:
            raise TypeError("choose the curve first, as in Pairing[BLS12381]")
        return Text.encode(cls.CURVE.C_TYPE)

    @classmethod
    def sizes(cls) -> tuple[int, int, int]:
        """The bytes of an uncompressed point of G_1, a point of G_2 and an element of G_T."""
        out = (ctypes.c_size_t * 3)()
        Library.default().call("umilib_math_pairing_pairing_sizes", *cls.name(), out)
        return out[0], out[1], out[2]

    @classmethod
    def pairing(cls, p: bytes | bytearray | memoryview, q: bytes | bytearray | memoryview) -> bytes:
        """e(P, Q); raises ``InvalidArgument`` for points not on the curve or not in their subgroups."""
        out = (ctypes.c_uint8 * cls.sizes()[2])()
        p_data, p_length = Bytes.readable(p)
        q_data, q_length = Bytes.readable(q)
        Library.default().call("umilib_math_pairing_pairing_pairing", *cls.name(), p_data, p_length, q_data, q_length, out, len(out))
        return bytes(out)


__all__ = ["BLS12381", "BN254", "BN462", "Pairing", "PairingCurve", "SM9BN256"]
