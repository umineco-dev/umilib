"""Finite field Diffie-Hellman (RFC 7919, RFC 3526). Mirrors ``umilib::crypto::dh``.

``DH[FFDHE2048]`` is DH in a group of this module: private keys and public
keys are big-endian integers of the bytes of the prime, and so is the shared
secret (RFC 7919 section 5.1).
"""

from __future__ import annotations

from typing import Any

from umilib.crypto import KeyAgreement, Names
from umilib.ffi import Marker


class DHGroup(Marker, abstract=True):
    """A group of DH: a safe prime and its generator, named by its C type name."""


class FFDHE2048(DHGroup):
    """ffdhe2048 of RFC 7919 appendix A.1."""


class FFDHE3072(DHGroup):
    """ffdhe3072 of RFC 7919 appendix A.2."""


class FFDHE4096(DHGroup):
    """ffdhe4096 of RFC 7919 appendix A.3."""


class FFDHE6144(DHGroup):
    """ffdhe6144 of RFC 7919 appendix A.4."""


class FFDHE8192(DHGroup):
    """ffdhe8192 of RFC 7919 appendix A.5."""


class MODP1536(DHGroup):
    """The 1536-bit MODP group of RFC 3526 section 2."""


class MODP2048(DHGroup):
    """The 2048-bit MODP group of RFC 3526 section 3."""


class MODP3072(DHGroup):
    """The 3072-bit MODP group of RFC 3526 section 4."""


class MODP4096(DHGroup):
    """The 4096-bit MODP group of RFC 3526 section 5."""


class MODP6144(DHGroup):
    """The 6144-bit MODP group of RFC 3526 section 6."""


class MODP8192(DHGroup):
    """The 8192-bit MODP group of RFC 3526 section 7."""


class DH(KeyAgreement):
    """DH in the group of ``DH[G]``."""

    PREFIX = "umilib_crypto_dh_dh"

    def __class_getitem__(cls, group: Any) -> Any:
        group = Names.require(group, DHGroup, "DH")
        return cls.specialize((group,), cls.SIZES, {"__doc__": f"DH in {group.__name__}."})


__all__ = [
    "DH",
    "DHGroup",
    "FFDHE2048",
    "FFDHE3072",
    "FFDHE4096",
    "FFDHE6144",
    "FFDHE8192",
    "MODP1536",
    "MODP2048",
    "MODP3072",
    "MODP4096",
    "MODP6144",
    "MODP8192",
]
