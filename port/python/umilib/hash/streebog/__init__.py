"""Streebog (GOST R 34.11-2012, RFC 6986). Mirrors ``umilib::hash::streebog``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class Streebog256(CryptographicDigest):
    """Streebog with 256 bits of output."""

    PREFIX = "umilib_hash_streebog_streebog256"


class Streebog512(CryptographicDigest):
    """Streebog with 512 bits of output."""

    PREFIX = "umilib_hash_streebog_streebog512"


__all__ = ["Streebog256", "Streebog512"]
