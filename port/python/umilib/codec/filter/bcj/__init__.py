"""Branch/call/jump filters of executables (.xz format specification, section 5.3.2).
Mirrors ``umilib::codec::filter::bcj``."""

from __future__ import annotations

import ctypes
import enum

from umilib.codec.filter import Filter
from umilib.ffi import Handle, Library


class BCJArchitecture(enum.IntEnum):
    """The instruction sets of the BCJ filters (their numbers in the C ABI)."""

    X86 = 0
    PowerPC = 1
    IA64 = 2
    ARM = 3
    ARMThumb = 4
    SPARC = 5
    ARM64 = 6
    RISCV = 7

    @property
    def alignment(self) -> int:
        """The alignment of the instructions converted, and of start offsets."""
        return Library.default().value("umilib_codec_filter_bcj_bcj_architecture_alignment", ctypes.c_uint32, int(self))


class BCJFilter(Filter):
    """A BCJ filter of one architecture whose first byte is at ``start_offset``."""

    PREFIX = "umilib_codec_filter_bcj_bcj_filter"

    def __init__(self, architecture: BCJArchitecture, start_offset: int = 0) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", int(architecture), start_offset))

    @property
    def architecture(self) -> BCJArchitecture:
        return BCJArchitecture(self.parameters()[0])

    @property
    def start_offset(self) -> int:
        return self.parameters()[1]

    def parameters(self) -> tuple[int, int]:
        architecture, start_offset = ctypes.c_uint8(), ctypes.c_uint32()
        self.library.call(f"{self.PREFIX}_parameters", self.handle, ctypes.byref(architecture), ctypes.byref(start_offset))
        return architecture.value, start_offset.value


__all__ = ["BCJArchitecture", "BCJFilter"]
