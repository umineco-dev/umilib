"""NIST P-384 (FIPS 186-5, SEC 2 secp384r1). Mirrors ``umilib::crypto::curve::p384``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class P384(WeierstrassCurve):
    """NIST P-384."""


__all__ = ["P384"]
