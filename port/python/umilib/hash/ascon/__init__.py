"""The hash functions of Ascon (NIST SP 800-232): Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128, and the
permutation Ascon-p. Mirrors ``umilib::hash::ascon``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, Handle, Library, Words
from umilib.hash import CryptographicDigest, ExtendableOutput, XOFReader

P = "umilib_hash_ascon"


class AsconPermutation:
    """The permutation Ascon-p on 5 words, S0 to S4 (section 3)."""

    MAXIMUM_ROUNDS = 16

    @staticmethod
    def permute(words: list[int], rounds: int) -> list[int]:
        """The 5 words of ``words`` after Ascon-p[``rounds``], 1 to 16 rounds."""
        state = Words.array(ctypes.c_uint64, words, 5)
        Library.default().call(f"{P}_ascon_permutation_permute", state, rounds)
        return list(state)


class AsconHash256(CryptographicDigest):
    """Ascon-Hash256: a 256-bit hash."""

    PREFIX = f"{P}_ascon_hash256"


class AsconReader(XOFReader):
    """The output of Ascon-XOF128 or Ascon-CXOF128."""

    PREFIX = f"{P}_ascon_reader"


class AsconXOF128(ExtendableOutput):
    """Ascon-XOF128: output of any length."""

    PREFIX = f"{P}_ascon_xof128"
    READER = AsconReader


class AsconCXOF128(ExtendableOutput):
    """Ascon-CXOF128: Ascon-XOF128 with a customization string of at most 256 bytes."""

    PREFIX = f"{P}_ascon_cxof128"
    READER = AsconReader
    MAXIMUM_CUSTOMIZATION = 256

    def __init__(self, customization: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(customization)
        Handle.__init__(self, Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new(cls, customization: bytes | bytearray | memoryview) -> AsconCXOF128:
        return cls(customization)


__all__ = ["AsconCXOF128", "AsconHash256", "AsconPermutation", "AsconReader", "AsconXOF128"]
