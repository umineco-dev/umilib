"""ANONYMOUS (RFC 4505): a login without credentials, with optional trace information. Mirrors
``umilib::auth::sasl::anonymous``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Buffer, Bytes, Handle, Text

P = "umilib_auth_sasl_anonymous_anonymous_message"


class ANONYMOUSMessage(Handle):
    """The message of ANONYMOUS: the trace information (prepared with the "trace" profile, at most 255
    characters), if any."""

    FREE = f"{P}_free"
    MAXIMUM_CHARACTERS = 255

    @staticmethod
    def new(trace: str | None) -> ANONYMOUSMessage:
        return ANONYMOUSMessage(Handle.create(f"{P}_new", *Text.encode(trace)))

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> ANONYMOUSMessage:
        return ANONYMOUSMessage(Handle.create(f"{P}_decode", *Bytes.readable(message)))

    def encode(self) -> bytes:
        return self.library.output(f"{P}_encode", self.handle)

    @property
    def trace(self) -> str | None:
        data = self.library.optional(f"{P}_trace", Buffer, self.handle)
        return None if data is None else data.decode()

    def is_email(self) -> bool:
        """Whether the trace information has the form of an email address (it holds ``@``)."""
        return self.library.value(f"{P}_is_email", ctypes.c_bool, self.handle)


__all__ = ["ANONYMOUSMessage"]
