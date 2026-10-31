"""scrypt (RFC 7914): a memory-hard password-based key derivation function. Mirrors
``umilib::crypto::scrypt``."""

from __future__ import annotations

import ctypes

from umilib.crypto import Primitive
from umilib.ffi import Bytes, Handle, Library, U128, Words


class Scrypt(Primitive):
    """The parameters N, r and p of scrypt, checked when they are created (section 6).

    A derivation needs 128 × r × (N + p) bytes of memory (:meth:`memory`), which a
    caller should bound before deriving with parameters it did not choose.
    """

    PREFIX = "umilib_crypto_scrypt_scrypt"

    def __init__(self, n: int, r: int, p: int) -> None:
        super().__init__(Handle.create("umilib_crypto_scrypt_scrypt_new", n, r, p))

    def n(self) -> int:
        return self.library.value("umilib_crypto_scrypt_scrypt_n", ctypes.c_uint64, self.handle)

    def r(self) -> int:
        return self.library.value("umilib_crypto_scrypt_scrypt_r", ctypes.c_uint32, self.handle)

    def p(self) -> int:
        return self.library.value("umilib_crypto_scrypt_scrypt_p", ctypes.c_uint32, self.handle)

    def memory(self) -> int:
        """The bytes of memory a derivation allocates."""
        out = U128()
        self.library.call("umilib_crypto_scrypt_scrypt_memory", self.handle, ctypes.byref(out))
        return out.to_int()

    def derive(self, password: bytes | bytearray | memoryview, salt: bytes | bytearray | memoryview, length: int) -> bytes:
        """``length`` bytes derived from ``password`` and ``salt``."""
        password_data, password_length = Bytes.readable(password)
        salt_data, salt_length = Bytes.readable(salt)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_scrypt_scrypt_derive", self.handle, password_data, password_length, salt_data, salt_length, out, length)
        return bytes(out)

    @staticmethod
    def salsa20_8(block: list[int]) -> list[int]:
        """The 16 words of ``block`` after the Salsa20/8 core (section 3)."""
        words = Words.array(ctypes.c_uint32, block, 16)
        Library.default().call("umilib_crypto_scrypt_scrypt_salsa20_8", words)
        return list(words)


__all__ = ["Scrypt"]
