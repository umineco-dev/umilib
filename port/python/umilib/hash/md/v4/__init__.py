"""MD4 (RFC 1320), broken: for compatibility only. Mirrors ``umilib::hash::md::v4``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class MD4(CryptographicDigest):
    """MD4."""

    PREFIX = "umilib_hash_md_v4_md4"


__all__ = ["MD4"]
