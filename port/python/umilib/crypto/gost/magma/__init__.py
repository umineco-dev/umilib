"""Magma (GOST R 34.12-2015, RFC 8891), with constant-time tables. Mirrors ``umilib::crypto::gost::magma``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class Magma(BlockCipher):
    """Magma: a 256-bit key and 64-bit blocks."""

    PREFIX = "umilib_crypto_gost_magma_magma"


__all__ = ["Magma"]
