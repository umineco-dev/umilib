"""The key-based key derivation functions of NIST SP 800-108r1: counter, feedback and double-pipeline
modes. Mirrors ``umilib::crypto::kbkdf``.

``KBKDF[HMAC[SHA256]](key, 32)`` is ``KBKDF::new(HMAC::<SHA256>::new(key), 32)``;
``KBKDF[CMAC[AES128]]`` takes CMAC.
"""

from __future__ import annotations

import ctypes
import enum
from typing import Any, ClassVar

from umilib.crypto import Primitive, Specialization
from umilib.ffi import Bytes, Handle, Text


class KBKDFCounter(enum.IntEnum):
    """Where the counter goes in the input of each PRF invocation of the feedback and double-pipeline modes."""

    #: No counter: PRF(K(i-1) || fixed).
    Absent = 0
    #: PRF([i] || K(i-1) || fixed).
    BeforeIteration = 1
    #: PRF(K(i-1) || [i] || fixed).
    AfterIteration = 2
    #: PRF(K(i-1) || fixed || [i]).
    AfterFixed = 3


class KBKDF(Primitive):
    """KBKDF over the PRF ``KBKDF[P]``, keyed with K_IN, with a counter of 8, 16, 24 or 32 bits."""

    PREFIX = "umilib_crypto_kbkdf_kbkdf"
    PRF: ClassVar[Any] = None

    @staticmethod
    def names(prf: Any, user: str) -> tuple[str, str]:
        """The C type names of the PRF class ``prf`` (``HMAC[H]`` or ``CMAC[C]``) and of its primitive."""
        primitive = getattr(prf, "PRIMITIVE", None)
        if not (isinstance(prf, type) and getattr(prf, "C_TYPE", "") and primitive is not None):
            raise TypeError(f"{user} needs a PRF class, such as {user}[HMAC[SHA256]] or {user}[CMAC[AES128]]")
        return prf.C_TYPE, primitive.C_TYPE

    def __class_getitem__(cls, prf: Any) -> Any:
        KBKDF.names(prf, "KBKDF")
        return Specialization.of(cls, (prf,), {"PRF": prf})

    def __init__(self, key: bytes | bytearray | memoryview, counter_bits: int) -> None:
        function, primitive = KBKDF.names(Specialization.require(self.PRF, "KBKDF"), "KBKDF")
        function_name, function_length = Text.encode(function)
        primitive_name, primitive_length = Text.encode(primitive)
        data, length = Bytes.readable(key)
        super().__init__(
            Handle.create("umilib_crypto_kbkdf_kbkdf_new", function_name, function_length, primitive_name, primitive_length, data, length, counter_bits)
        )

    def counter(self, before: bytes | bytearray | memoryview, after: bytes | bytearray | memoryview, length: int) -> bytes:
        """The counter mode (section 4.1): K(i) = PRF(before || [i] || after), ``length`` bytes."""
        before_data, before_length = Bytes.readable(before)
        after_data, after_length = Bytes.readable(after)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_kbkdf_kbkdf_counter", self.handle, before_data, before_length, after_data, after_length, out, length)
        return bytes(out)

    def feedback(
        self, iv: bytes | bytearray | memoryview, fixed: bytes | bytearray | memoryview, location: KBKDFCounter, length: int
    ) -> bytes:
        """The feedback mode (section 4.2) from the initial value ``iv``, ``length`` bytes."""
        iv_data, iv_length = Bytes.readable(iv)
        fixed_data, fixed_length = Bytes.readable(fixed)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_kbkdf_kbkdf_feedback", self.handle, iv_data, iv_length, fixed_data, fixed_length, int(location), out, length)
        return bytes(out)

    def double_pipeline(self, fixed: bytes | bytearray | memoryview, location: KBKDFCounter, length: int) -> bytes:
        """The double-pipeline mode (section 4.3), ``length`` bytes."""
        fixed_data, fixed_length = Bytes.readable(fixed)
        out = (ctypes.c_uint8 * length)()
        self.library.call("umilib_crypto_kbkdf_kbkdf_double_pipeline", self.handle, fixed_data, fixed_length, int(location), out, length)
        return bytes(out)


__all__ = ["KBKDF", "KBKDFCounter"]
