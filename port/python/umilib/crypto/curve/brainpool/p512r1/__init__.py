"""brainpoolP512r1 (RFC 5639). Mirrors ``umilib::crypto::curve::brainpool::p512r1``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class BrainpoolP512r1(WeierstrassCurve):
    """brainpoolP512r1."""


__all__ = ["BrainpoolP512r1"]
