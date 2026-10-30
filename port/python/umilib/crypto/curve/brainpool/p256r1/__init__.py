"""brainpoolP256r1 (RFC 5639). Mirrors ``umilib::crypto::curve::brainpool::p256r1``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class BrainpoolP256r1(WeierstrassCurve):
    """brainpoolP256r1."""


__all__ = ["BrainpoolP256r1"]
