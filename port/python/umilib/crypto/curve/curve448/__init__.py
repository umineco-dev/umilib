"""Curve448 and edwards448 (RFC 7748, RFC 8032). Mirrors ``umilib::crypto::curve::curve448``."""

from __future__ import annotations

from umilib.math.ec import EdwardsCurve, MontgomeryCurve


class Curve448(MontgomeryCurve):
    """Curve448, the Montgomery curve of X448."""


class Edwards448(EdwardsCurve):
    """edwards448, the Edwards curve of Ed448."""


__all__ = ["Curve448", "Edwards448"]
