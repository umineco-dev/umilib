"""The identity-based digital signature algorithm of SM9 (GM/T 0044.2-2016). Mirrors
``umilib::crypto::ibs::sm9``.

``SM9[SM9BN256, SM3]`` is the standard instance, on the curve of GM/T 0044.5-2016 section 3.1
(:class:`umilib.math.pairing.SM9BN256`) with SM3, with hid 0x01: a signature (h, S) is h of 32
bytes then S uncompressed (04 || x || y), and the master public key 04 || x || y with each
coordinate of GF(p^2) written as its u-coefficient, then its constant.
"""

from __future__ import annotations

from typing import ClassVar

from umilib.crypto.ibs import IdentityBasedSignature


class SM9(IdentityBasedSignature):
    """The signatures of SM9 on the curve and with the hash function of ``SM9[C, H]``."""

    PREFIX = "umilib_crypto_ibs_sm9_sm9"
    #: hid of the signature keys in GM/T 0044.5-2016 annex A.
    SIGNATURE_IDENTIFIER: ClassVar[int] = 0x01


__all__ = ["SM9"]
