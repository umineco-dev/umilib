"""The identity-based signature of J. C. Cha and J. H. Cheon, "An Identity-Based Signature from Gap
Diffie-Hellman Groups" (PKC 2003), in the asymmetric setting. Mirrors ``umilib::crypto::ibs::chacheon``.

``ChaCheon[C, H]`` signs with (U, V), two points of G_1 (compressed SEC 1).
"""

from __future__ import annotations

from umilib.crypto.ibs import IdentityBasedSignature


class ChaCheon(IdentityBasedSignature):
    """The signature of Cha and Cheon on the curve and with the hash function of ``ChaCheon[C, H]``."""

    PREFIX = "umilib_crypto_ibs_chacheon_chacheon"


__all__ = ["ChaCheon"]
