"""Camellia (RFC 3713), with constant-time tables. Mirrors ``umilib::crypto::camellia``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class Camellia128(BlockCipher):
    """Camellia-128: a 128-bit key and 18 rounds."""

    PREFIX = "umilib_crypto_camellia_camellia128"


class Camellia192(BlockCipher):
    """Camellia-192: a 192-bit key and 24 rounds."""

    PREFIX = "umilib_crypto_camellia_camellia192"


class Camellia256(BlockCipher):
    """Camellia-256: a 256-bit key and 24 rounds."""

    PREFIX = "umilib_crypto_camellia_camellia256"


__all__ = ["Camellia128", "Camellia192", "Camellia256"]
