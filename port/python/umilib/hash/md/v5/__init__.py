"""MD5 (RFC 1321), broken: for compatibility only. Mirrors ``umilib::hash::md::v5``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class MD5(CryptographicDigest):
    """MD5."""

    PREFIX = "umilib_hash_md_v5_md5"


__all__ = ["MD5"]
