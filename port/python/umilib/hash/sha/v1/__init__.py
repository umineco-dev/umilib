"""SHA-1 (FIPS 180-4), for compatibility: collisions are practical. Mirrors ``umilib::hash::sha::v1``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class SHA1(CryptographicDigest):
    """SHA-1."""

    PREFIX = "umilib_hash_sha_v1_sha1"


__all__ = ["SHA1"]
