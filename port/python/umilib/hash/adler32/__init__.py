"""Adler-32, the checksum of zlib streams (RFC 1950). Mirrors ``umilib::hash::adler32``."""

from __future__ import annotations

from umilib.hash import Digest


class Adler32(Digest):
    """Adler-32; its digest is the value in big-endian order."""

    PREFIX = "umilib_hash_adler32_adler32"


__all__ = ["Adler32"]
