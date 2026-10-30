"""ARIA (RFC 5794), with constant-time tables. Mirrors ``umilib::crypto::aria``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class ARIA128(BlockCipher):
    """ARIA-128: a 128-bit key and 12 rounds."""

    PREFIX = "umilib_crypto_aria_aria128"


class ARIA192(BlockCipher):
    """ARIA-192: a 192-bit key and 14 rounds."""

    PREFIX = "umilib_crypto_aria_aria192"


class ARIA256(BlockCipher):
    """ARIA-256: a 256-bit key and 16 rounds."""

    PREFIX = "umilib_crypto_aria_aria256"


__all__ = ["ARIA128", "ARIA192", "ARIA256"]
