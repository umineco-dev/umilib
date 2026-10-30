"""IDEA, with multiplication modulo 2^16 + 1 in constant time. Mirrors ``umilib::crypto::idea``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class IDEA(BlockCipher):
    """IDEA: a 128-bit key, 64-bit blocks and 8.5 rounds."""

    PREFIX = "umilib_crypto_idea_idea"


__all__ = ["IDEA"]
