"""NIST P-521 (FIPS 186-5, SEC 2 secp521r1). Mirrors ``umilib::crypto::curve::p521``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class P521(WeierstrassCurve):
    """NIST P-521."""


__all__ = ["P521"]
