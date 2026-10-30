"""The Delta filter (.xz format specification, section 5.3.3). Mirrors ``umilib::codec::filter::delta``."""

from __future__ import annotations

from umilib.codec.filter import Filter
from umilib.ffi import Handle


class DeltaFilter(Filter):
    """The Delta filter of a distance of 1 to 256 bytes."""

    PREFIX = "umilib_codec_filter_delta_delta_filter"
    MAXIMUM_DISTANCE = 256

    def __init__(self, distance: int) -> None:
        super().__init__(Handle.create(f"{self.PREFIX}_new", distance))
        self.distance = distance


__all__ = ["DeltaFilter"]
