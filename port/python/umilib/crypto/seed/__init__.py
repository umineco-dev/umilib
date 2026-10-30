"""SEED (RFC 4269), with constant-time tables. Mirrors ``umilib::crypto::seed``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class SEED(BlockCipher):
    """SEED: a 128-bit key and 16 rounds."""

    PREFIX = "umilib_crypto_seed_seed"


__all__ = ["SEED"]
