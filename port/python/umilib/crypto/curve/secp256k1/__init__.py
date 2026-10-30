"""secp256k1 (SEC 2). Mirrors ``umilib::crypto::curve::secp256k1``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class Secp256k1(WeierstrassCurve):
    """secp256k1, of a = 0."""


__all__ = ["Secp256k1"]
