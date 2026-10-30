"""The operating system umilib was built for. Mirrors ``umilib::platform::native``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Bytes, Library


class System:
    """The operating system umilib was built for."""

    @staticmethod
    def name() -> str:
        """``linux``, ``android``, ``darwin``, ``windows`` or ``other``."""
        out = ctypes.c_char_p()
        Library.default().call("umilib_platform_native_system_name", ctypes.byref(out))
        return out.value.decode("ascii")


class Random:
    """The system's random bytes (``getrandom``, ``getentropy``, ``ProcessPrng``)."""

    def fill(self, buffer: bytearray | memoryview) -> None:
        """Fills ``buffer`` with random bytes."""
        Library.default().call("umilib_platform_native_random_fill", Bytes.mutable(buffer), len(buffer))

    def bytes(self, length: int) -> bytes:
        """``length`` random bytes."""
        buffer = bytearray(length)
        self.fill(buffer)
        return bytes(buffer)


__all__ = ["Random", "System"]
