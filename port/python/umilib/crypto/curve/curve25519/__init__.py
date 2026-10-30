"""Curve25519 and edwards25519 (RFC 7748, RFC 8032). Mirrors ``umilib::crypto::curve::curve25519``."""

from __future__ import annotations

from umilib.math.ec import EdwardsCurve, MontgomeryCurve


class Curve25519(MontgomeryCurve):
    """Curve25519, the Montgomery curve of X25519."""


class Edwards25519(EdwardsCurve):
    """edwards25519, the twisted Edwards curve of Ed25519."""


__all__ = ["Curve25519", "Edwards25519"]
