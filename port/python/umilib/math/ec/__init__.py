"""Elliptic curves over prime fields. Mirrors ``umilib::math::ec``.

The arithmetic of the curves is generic in Rust; the C ABI exports the
schemes that use it, which name a curve by the C type name of its type. The
classes here are the kinds of those curves, as the Rust traits
``WeierstrassCurve``, ``MontgomeryCurve`` and ``EdwardsCurve``; the curves
themselves are in :mod:`umilib.crypto.curve`.
"""

from __future__ import annotations

from umilib.ffi import Marker


class Curve(Marker, abstract=True):
    """A curve of the specifications, a type of no value named by its C type name ``C_TYPE``."""


class WeierstrassCurve(Curve, abstract=True):
    """A short Weierstrass curve y^2 = x^3 + a x + b of prime order times a cofactor."""


class MontgomeryCurve(Curve, abstract=True):
    """A Montgomery curve B v^2 = u^3 + A u^2 + u, of the u-coordinate ladder of RFC 7748."""


class EdwardsCurve(Curve, abstract=True):
    """A twisted Edwards curve a x^2 + y^2 = 1 + d x^2 y^2 of RFC 8032."""


__all__ = ["Curve", "EdwardsCurve", "MontgomeryCurve", "WeierstrassCurve"]
