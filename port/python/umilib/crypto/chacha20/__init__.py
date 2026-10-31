"""ChaCha20 (RFC 8439) and XChaCha20 (draft-irtf-cfrg-xchacha). Mirrors ``umilib::crypto::chacha20``.

Both stop with ``LimitExceeded`` before their block counter wraps.
"""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import StreamCipher
from umilib.ffi import Bytes, Handle, Library, U128, Words


class ChaCha20(StreamCipher):
    """ChaCha20 with a 32-byte key: a 12-byte nonce and a 32-bit block counter (RFC 8439), or with
    :meth:`with_64_bit_counter` an 8-byte nonce and a 64-bit counter (the original design)."""

    PREFIX = "umilib_crypto_chacha20_chacha20"
    KEY_SIZE: ClassVar[int] = 32
    NONCE_SIZE: ClassVar[int] = 12

    def __init__(self, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, counter: int = 0) -> None:
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        super().__init__(Handle.create("umilib_crypto_chacha20_chacha20_new", key_data, key_length, nonce_data, nonce_length, counter))

    @classmethod
    def with_64_bit_counter(
        cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, counter: int = 0
    ) -> Any:
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        return cls.from_pointer(Handle.create("umilib_crypto_chacha20_chacha20_with_64_bit_counter", key_data, key_length, nonce_data, nonce_length, counter))

    def remaining_bytes(self) -> int:
        """The bytes of key stream left before the counter wraps."""
        out = U128()
        self.library.call("umilib_crypto_chacha20_chacha20_remaining_bytes", self.handle, ctypes.byref(out))
        return out.to_int()

    @staticmethod
    def initial_state(key: bytes | bytearray | memoryview, counter: int, nonce: bytes | bytearray | memoryview) -> list[int]:
        """The 16 words of section 2.3: constants, key, block counter, nonce."""
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        out = (ctypes.c_uint32 * 16)()
        Library.default().call("umilib_crypto_chacha20_chacha20_initial_state", key_data, key_length, counter, nonce_data, nonce_length, out)
        return list(out)

    @staticmethod
    def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> list[int]:
        """The 16 words of ``state`` after the quarter round on the words ``a``, ``b``, ``c`` and ``d``."""
        words = ChaCha20.words(state)
        Library.default().call("umilib_crypto_chacha20_chacha20_quarter_round", words, a, b, c, d)
        return list(words)

    @staticmethod
    def rounds(state: list[int]) -> list[int]:
        """The 16 words of ``state`` after the 20 rounds."""
        words = ChaCha20.words(state)
        Library.default().call("umilib_crypto_chacha20_chacha20_rounds", words)
        return list(words)

    @staticmethod
    def block(state: list[int]) -> bytes:
        """The 64-byte block of ``state``: the rounds, then the addition of the input state."""
        out = (ctypes.c_uint8 * 64)()
        Library.default().call("umilib_crypto_chacha20_chacha20_block", ChaCha20.words(state), out, 64)
        return bytes(out)

    @staticmethod
    def words(state: list[int]) -> Any:
        """The 16 words of ``state`` as a C array, checked to be 32-bit words."""
        return Words.array(ctypes.c_uint32, state, 16)


class XChaCha20(StreamCipher):
    """XChaCha20 with a 32-byte key and a 24-byte nonce, through HChaCha20."""

    PREFIX = "umilib_crypto_chacha20_xchacha20"
    KEY_SIZE: ClassVar[int] = 32
    NONCE_SIZE: ClassVar[int] = 24

    def __init__(self, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, counter: int = 0) -> None:
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        super().__init__(Handle.create("umilib_crypto_chacha20_xchacha20_new", key_data, key_length, nonce_data, nonce_length, counter))

    @classmethod
    def with_64_bit_counter(
        cls, key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview, counter: int = 0
    ) -> Any:
        """XChaCha20 with the 64-bit counter of the original ChaCha20 (libsodium)."""
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        return cls.from_pointer(Handle.create("umilib_crypto_chacha20_xchacha20_with_64_bit_counter", key_data, key_length, nonce_data, nonce_length, counter))

    def remaining_bytes(self) -> int:
        """The bytes of key stream left before the counter wraps."""
        out = U128()
        self.library.call("umilib_crypto_chacha20_xchacha20_remaining_bytes", self.handle, ctypes.byref(out))
        return out.to_int()

    @staticmethod
    def derive(key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview) -> tuple[bytes, bytes]:
        """The subkey (HChaCha20 of the key and the first 16 bytes of the nonce) and the 12-byte nonce of
        ChaCha20 (4 zero bytes, then the last 8 bytes of the nonce)."""
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        subkey = (ctypes.c_uint8 * 32)()
        inner = (ctypes.c_uint8 * 12)()
        Library.default().call("umilib_crypto_chacha20_xchacha20_derive", key_data, key_length, nonce_data, nonce_length, subkey, 32, inner, 12)
        return bytes(subkey), bytes(inner)

    @staticmethod
    def hchacha20(key: bytes | bytearray | memoryview, nonce: bytes | bytearray | memoryview) -> bytes:
        """HChaCha20 of the 32-byte ``key`` and the 16-byte ``nonce``."""
        key_data, key_length = Bytes.readable(key)
        nonce_data, nonce_length = Bytes.readable(nonce)
        out = (ctypes.c_uint8 * 32)()
        Library.default().call("umilib_crypto_chacha20_xchacha20_hchacha20", key_data, key_length, nonce_data, nonce_length, out, 32)
        return bytes(out)


__all__ = ["ChaCha20", "XChaCha20"]
