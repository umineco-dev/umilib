"""Tests of umilib.platform.native: the system's random bytes and its name."""

import sys
from collections import Counter

from umilib.platform.native import Random, System


def test_the_system_is_named():
    expected = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform, "other")
    assert System.name() == expected


def test_random_bytes_cover_every_value():
    data = Random().bytes(1 << 18)
    counts = Counter(data)
    assert len(counts) == 256
    assert all(700 < count < 1350 for count in counts.values())
    assert Random().bytes(32) != Random().bytes(32)
    buffer = bytearray(1000)
    Random().fill(buffer)
    assert any(buffer[900:])
