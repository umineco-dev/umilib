"""SHA-2 (FIPS 180-4). Mirrors ``umilib::hash::sha::v2``."""

from __future__ import annotations

from umilib.hash import CryptographicDigest


class SHA224(CryptographicDigest):
    """SHA-224."""

    PREFIX = "umilib_hash_sha_v2_sha224"


class SHA256(CryptographicDigest):
    """SHA-256."""

    PREFIX = "umilib_hash_sha_v2_sha256"


class SHA384(CryptographicDigest):
    """SHA-384."""

    PREFIX = "umilib_hash_sha_v2_sha384"


class SHA512(CryptographicDigest):
    """SHA-512."""

    PREFIX = "umilib_hash_sha_v2_sha512"


class SHA512_224(CryptographicDigest):
    """SHA-512/224."""

    PREFIX = "umilib_hash_sha_v2_sha512_224"


class SHA512_256(CryptographicDigest):
    """SHA-512/256."""

    PREFIX = "umilib_hash_sha_v2_sha512_256"


__all__ = ["SHA224", "SHA256", "SHA384", "SHA512", "SHA512_224", "SHA512_256"]
