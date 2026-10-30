"""The curve of SM2 (GB/T 32918.5). Mirrors ``umilib::crypto::curve::sm2``."""

from __future__ import annotations

from umilib.math.ec import WeierstrassCurve


class SM2(WeierstrassCurve):
    """The recommended curve of SM2."""


__all__ = ["SM2"]
