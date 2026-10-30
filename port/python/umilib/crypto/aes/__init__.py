"""AES (FIPS 197), bitsliced so that no memory access depends on secret data. Mirrors ``umilib::crypto::aes``."""

from __future__ import annotations

from umilib.crypto import BlockCipher
from umilib.ffi import Bytes, Library


class AES128(BlockCipher):
    """AES-128: a 128-bit key and 10 rounds."""

    PREFIX = "umilib_crypto_aes_aes128"


class AES192(BlockCipher):
    """AES-192: a 192-bit key and 12 rounds."""

    PREFIX = "umilib_crypto_aes_aes192"


class AES256(BlockCipher):
    """AES-256: a 256-bit key and 14 rounds."""

    PREFIX = "umilib_crypto_aes_aes256"


class AESBitslice:
    """The bitsliced rounds of AES."""

    @staticmethod
    def round(blocks: bytearray, keys: bytes | bytearray | memoryview) -> None:
        """Applies one round of the cipher (SubBytes, ShiftRows, MixColumns, AddRoundKey) to each
        16-byte block of ``blocks`` in place, with the key of the same position in ``keys``: AESRound of AEGIS."""
        if len(keys) != len(blocks):
            raise ValueError("there is one key for each block")
        data, _ = Bytes.readable(keys)
        Library.default().call("umilib_crypto_aes_aes_bitslice_round", Bytes.mutable(blocks), data, len(blocks))


__all__ = ["AES128", "AES192", "AES256", "AESBitslice"]
