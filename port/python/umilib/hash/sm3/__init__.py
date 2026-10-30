"""SM3 (GB/T 32905-2016). Mirrors ``umilib::hash::sm3``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class SM3(CryptographicDigest):
    """SM3."""

    PREFIX = "umilib_hash_sm3_sm3"


__all__ = ["SM3"]
