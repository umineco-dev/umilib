"""SASL (RFC 4422): the messages of PLAIN, EXTERNAL, ANONYMOUS, SCRAM and OAUTHBEARER. Mirrors ``umilib::auth::sasl``.

Errors are :class:`SASLError` (``Format``, ``Length``), :class:`~umilib.codec.stringprep.StringPrepError` for
strings stringprep refuses, and :class:`~umilib.auth.sasl.scram.SCRAMError` for SCRAM.
"""

from __future__ import annotations

import ctypes
import enum

from umilib.ffi import Buffer, FFIError, Handle, Library, Text


class SASLError(FFIError):
    """A malformed SASL message: ``Format`` or ``Length``."""


Library.register_error("auth.sasl", SASLError)


class SASLMechanism(enum.IntEnum):
    """The mechanisms this module implements, in the order of the Rust ``ALL``."""

    PLAIN = 0
    EXTERNAL = 1
    ANONYMOUS = 2
    SCRAMSHA1 = 3
    SCRAMSHA1PLUS = 4
    SCRAMSHA256 = 5
    SCRAMSHA256PLUS = 6
    OAUTHBEARER = 7

    def registered_name(self) -> str:
        """The name in the IANA registry, as ``SCRAM-SHA-256-PLUS``."""
        return Library.default().output("umilib_auth_sasl_sasl_mechanism_name", int(self)).decode()

    @classmethod
    def from_name(cls, name: str) -> SASLMechanism | None:
        """The mechanism of ``name`` (compared exactly: names are upper case), or ``None``."""
        index = Library.default().optional("umilib_auth_sasl_sasl_mechanism_from_name", ctypes.c_uint8, *Text.encode(name))
        return None if index is None else cls(index)

    @staticmethod
    def is_name(name: str) -> bool:
        """Whether ``name`` has the syntax of a mechanism name (RFC 4422 section 3.1)."""
        return Library.default().value("umilib_auth_sasl_sasl_mechanism_is_name", ctypes.c_bool, *Text.encode(name))

    def is_plus(self) -> bool:
        """Whether the mechanism binds the authentication to the channel (the ``-PLUS`` variants)."""
        return self in (SASLMechanism.SCRAMSHA1PLUS, SASLMechanism.SCRAMSHA256PLUS)


class GS2ChannelBinding(enum.IntEnum):
    """The channel binding flag of a GS2 header: ``n``, ``y``, or ``p`` with a type's name."""

    Unsupported = 0
    NotOffered = 1
    Required = 2

    TLS_UNIQUE = enum.nonmember("tls-unique")
    TLS_SERVER_END_POINT = enum.nonmember("tls-server-end-point")
    TLS_EXPORTER = enum.nonmember("tls-exporter")


class GS2Header(Handle):
    """A GS2 header (RFC 5801 section 4): the non-standard flag, the channel binding flag and the
    authorization identity."""

    FREE = "umilib_auth_sasl_gs2_header_free"

    @staticmethod
    def new(channel_binding: GS2ChannelBinding, name: str | None = None, authzid: str | None = None, nonstandard: bool = False) -> GS2Header:
        """The header of the flag ``channel_binding`` (with the type ``name`` for ``Required``)."""
        return GS2Header(
            Handle.create("umilib_auth_sasl_gs2_header_new", int(channel_binding), *Text.encode(name), nonstandard, *Text.encode(authzid))
        )

    @staticmethod
    def decode(text: str) -> tuple[GS2Header, str]:
        """The header at the start of ``text`` and the rest of the text."""
        data, length = Text.encode(text)
        out_length = ctypes.c_size_t()
        pointer = Handle.create("umilib_auth_sasl_gs2_header_decode", data, length, ctypes.byref(out_length))
        return GS2Header(pointer), text.encode()[out_length.value :].decode()

    def encode(self) -> str:
        return self.library.output("umilib_auth_sasl_gs2_header_encode", self.handle).decode()

    @property
    def channel_binding(self) -> tuple[GS2ChannelBinding, str]:
        """The flag and the type's name (empty unless ``Required``)."""
        kind = ctypes.c_uint8()
        buffer = Buffer()
        self.library.call("umilib_auth_sasl_gs2_header_channel_binding", self.handle, ctypes.byref(kind), ctypes.byref(buffer))
        return GS2ChannelBinding(kind.value), self.library.take(buffer).decode()

    @property
    def nonstandard(self) -> bool:
        return self.library.value("umilib_auth_sasl_gs2_header_nonstandard", ctypes.c_bool, self.handle)

    @property
    def authzid(self) -> str | None:
        data = self.library.optional("umilib_auth_sasl_gs2_header_authzid", Buffer, self.handle)
        return None if data is None else data.decode()


__all__ = ["GS2ChannelBinding", "GS2Header", "SASLError", "SASLMechanism"]
