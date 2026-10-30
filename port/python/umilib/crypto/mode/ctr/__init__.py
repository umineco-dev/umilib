"""CTR (SP 800-38A section 6.5): a stream cipher that refuses to repeat its counter. Mirrors ``umilib::crypto::mode::ctr``."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from umilib.crypto import BlockCipher, BlockCipherClass, Specialization, StreamCipher
from umilib.ffi import Bytes, Handle, Text, U128



class CTR(StreamCipher):
    """CTR over the cipher ``CTR[C]``: a counter of every bit of the block, or of its last bits."""

    PREFIX = "umilib_crypto_mode_ctr_ctr"
    CIPHER: ClassVar[type[BlockCipher] | None] = None

    def __class_getitem__(cls, cipher: type[BlockCipher]) -> Any:
        """The class of CTR over ``cipher``."""
        cipher = BlockCipherClass.require(cipher, "CTR")
        return Specialization.of(cls, (cipher,), {"CIPHER": cipher})

    def __init__(
        self,
        key: bytes | bytearray | memoryview,
        initial: bytes | bytearray | memoryview,
        counter_bits: int | None = None,
    ) -> None:
        """CTR with ``key`` from the counter block ``initial``, whose last ``counter_bits`` bits (1 to the
        block size, by default all) count."""
        cipher = Specialization.require(self.CIPHER, "CTR")
        name, name_length = Text.encode(cipher.C_TYPE)
        key_data, key_length = Bytes.readable(key)
        initial_data, initial_length = Bytes.readable(initial)
        arguments = [name, name_length, key_data, key_length, initial_data, initial_length]
        if counter_bits is None:
            super().__init__(Handle.create(f"{self.PREFIX}_new", *arguments))
        else:
            super().__init__(Handle.create(f"{self.PREFIX}_with_counter_bits", *arguments, counter_bits))

    @classmethod
    def with_counter_bits(
        cls, key: bytes | bytearray | memoryview, initial: bytes | bytearray | memoryview, counter_bits: int
    ) -> Any:
        return cls(key, initial, counter_bits)

    def remaining_bytes(self) -> int | None:
        """The bytes of key stream left before the counter runs out, or ``None`` if the number does not fit
        in 128 bits (counters of 124 bits or more with 16-byte blocks)."""
        has_value = ctypes.c_bool()
        out = U128()
        self.library.call(f"{self.PREFIX}_remaining_bytes", self.handle, ctypes.byref(has_value), ctypes.byref(out))
        return out.to_int() if has_value.value else None


__all__ = ["CTR"]
