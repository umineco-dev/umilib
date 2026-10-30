"""DES and Triple DES (SP 800-67r2): broken or retired, for legacy data. Mirrors ``umilib::crypto::des``."""

from __future__ import annotations

import ctypes

from umilib.crypto import BlockCipher
from umilib.ffi import Bytes, Library


class DES(BlockCipher):
    """DES: a 64-bit key of 56 bits and 64-bit blocks."""

    PREFIX = "umilib_crypto_des_des"

    @staticmethod
    def is_weak(key: bytes | bytearray | memoryview) -> bool:
        """Whether the 8-byte ``key`` is a weak, semi-weak or possibly weak key (section 3.3.2),
        ignoring the parity bits."""
        data, length = Bytes.readable(key)
        return Library.default().value("umilib_crypto_des_des_is_weak", ctypes.c_bool, data, length)


class TDES(BlockCipher):
    """Triple DES: a bundle of three keys (24 bytes) or two (16 bytes, Key3 = Key1); Key1 = Key2 or Key2 = Key3 is refused."""

    PREFIX = "umilib_crypto_des_tdes"


__all__ = ["DES", "TDES"]
