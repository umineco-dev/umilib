"""Umineco Library: Python bindings of the umilib Rust crate.

Every module mirrors the Rust module of the same path: ``umilib.bytes`` is
``umilib::bytes``, with the same types and methods. The bindings call the
umilib shared library through ``umilib.ffi``.

``umilib.VERSION`` is the version of the loaded shared library.
"""

from __future__ import annotations

import ctypes


def __getattr__(name: str) -> str:
    if name == "VERSION":
        from umilib.ffi import Library

        return ctypes.string_at(Library.default().function("umilib_version")()).decode("utf-8")
    raise AttributeError(f"module 'umilib' has no attribute {name!r}")
