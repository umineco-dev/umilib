"""Kuznyechik (GOST R 34.12-2015, RFC 7801), with constant-time tables. Mirrors ``umilib::crypto::gost::kuznyechik``."""

from __future__ import annotations

from umilib.crypto import BlockCipher


class Kuznyechik(BlockCipher):
    """Kuznyechik: a 256-bit key and 128-bit blocks."""

    PREFIX = "umilib_crypto_gost_kuznyechik_kuznyechik"


__all__ = ["Kuznyechik"]
