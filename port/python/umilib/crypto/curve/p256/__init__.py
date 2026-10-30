"""NIST P-256 (FIPS 186-5, SEC 2 secp256r1). Mirrors ``umilib::crypto::curve::p256``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class P256(WeierstrassCurve):
    """NIST P-256."""


__all__ = ["P256"]
