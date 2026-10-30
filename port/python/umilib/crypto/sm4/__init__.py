"""SM4 (GB/T 32907-2016), with constant-time tables. Mirrors ``umilib::crypto::sm4``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class SM4(BlockCipher):
    """SM4: a 128-bit key and 32 rounds."""

    PREFIX = "umilib_crypto_sm4_sm4"


__all__ = ["SM4"]
