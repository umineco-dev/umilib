"""Elliptic curve Diffie-Hellman: ECDH, X25519 and X448. Mirrors ``umilib::crypto::ecdh``.

``ECDH[P256]`` is ECDH on a Weierstrass curve of :mod:`umilib.crypto.curve`
(SEC 1 section 3.3.1): private keys are big-endian scalars, public keys SEC 1
points (compressed or not when read, uncompressed when written) and the
shared secret the x-coordinate. ``XDH[Curve25519]`` (:data:`X25519`) and
``XDH[Curve448]`` (:data:`X448`) are the functions of RFC 7748.
"""

from __future__ import annotations

from typing import Any

from umilib.crypto import KeyAgreement, Names
from umilib.math.ec import MontgomeryCurve, WeierstrassCurve


class ECDH(KeyAgreement):
    """ECDH on the curve of ``ECDH[C]``."""

    PREFIX = "umilib_crypto_ecdh_ecdh"

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = Names.require(curve, WeierstrassCurve, "ECDH")
        return cls.specialize((curve,), cls.SIZES, {"__doc__": f"ECDH on {curve.__name__}."})


class XDH(KeyAgreement):
    """X25519 or X448 (RFC 7748 section 5) on the curve of ``XDH[C]``."""

    PREFIX = "umilib_crypto_ecdh_xdh"

    def __class_getitem__(cls, curve: Any) -> Any:
        curve = Names.require(curve, MontgomeryCurve, "XDH")
        return cls.specialize((curve,), cls.SIZES, {"__doc__": f"XDH on {curve.__name__}."})


class XDHCurves:
    """The curves of the aliases of RFC 7748."""

    @staticmethod
    def x25519() -> Any:
        from umilib.crypto.curve.curve25519 import Curve25519

        return XDH[Curve25519]

    @staticmethod
    def x448() -> Any:
        from umilib.crypto.curve.curve448 import Curve448

        return XDH[Curve448]


#: X25519 of RFC 7748.
X25519 = XDHCurves.x25519()
#: X448 of RFC 7748.
X448 = XDHCurves.x448()

__all__ = ["ECDH", "X25519", "X448", "XDH", "XDHCurves"]
