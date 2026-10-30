"""brainpoolP384r1 (RFC 5639). Mirrors ``umilib::crypto::curve::brainpool::p384r1``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class BrainpoolP384r1(WeierstrassCurve):
    """brainpoolP384r1."""


__all__ = ["BrainpoolP384r1"]
