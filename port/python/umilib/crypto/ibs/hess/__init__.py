"""The identity-based signature of F. Hess, "Efficient Identity Based Signature Schemes Based on
Pairings" (SAC 2002), scheme 1, in the asymmetric setting. Mirrors ``umilib::crypto::ibs::hess``.

``Hess[C, H]`` signs with (u, v): u in G_1 (compressed SEC 1) and v a
scalar (big-endian).
"""

from __future__ import annotations

from umilib.crypto.ibs import IdentityBasedSignature


class Hess(IdentityBasedSignature):
    """Hess's signature on the curve and with the hash function of ``Hess[C, H]``."""

    PREFIX = "umilib_crypto_ibs_hess_hess"


__all__ = ["Hess"]
