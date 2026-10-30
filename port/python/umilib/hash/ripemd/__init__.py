"""RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320. Mirrors ``umilib::hash::ripemd``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class RIPEMD128(CryptographicDigest):
    """RIPEMD-128."""

    PREFIX = "umilib_hash_ripemd_ripemd128"


class RIPEMD160(CryptographicDigest):
    """RIPEMD-160."""

    PREFIX = "umilib_hash_ripemd_ripemd160"


class RIPEMD256(CryptographicDigest):
    """RIPEMD-256."""

    PREFIX = "umilib_hash_ripemd_ripemd256"


class RIPEMD320(CryptographicDigest):
    """RIPEMD-320."""

    PREFIX = "umilib_hash_ripemd_ripemd320"


__all__ = ["RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320"]
