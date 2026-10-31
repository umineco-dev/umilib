"""PLAIN (RFC 4616): the authorization identity, the authentication identity and the password. Mirrors
``umilib::auth::sasl::plain``."""

from __future__ import annotations

import ctypes

from umilib.codec.stringprep import Unassigned
from umilib.ffi import Buffer, Bytes, Handle, Library, Text


class PLAINMessage(Handle):
    """The message of PLAIN (RFC 4616 section 2). It holds the password in the clear: use it over TLS only."""

    FREE = "umilib_auth_sasl_plain_plain_message_free"

    @staticmethod
    def new(authzid: str | None, authcid: str, password: str) -> PLAINMessage:
        return PLAINMessage(Handle.create("umilib_auth_sasl_plain_plain_message_new", *Text.encode(authzid), *Text.encode(authcid), *Text.encode(password)))

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> PLAINMessage:
        return PLAINMessage(Handle.create("umilib_auth_sasl_plain_plain_message_decode", *Bytes.readable(message)))

    def encode(self) -> bytearray:
        """The bytes of the message, which hold the password (a ``bytearray`` the caller may zeroize)."""
        return self.library.output_secret("umilib_auth_sasl_plain_plain_message_encode", self.handle)

    @property
    def authzid(self) -> str | None:
        data = self.library.optional("umilib_auth_sasl_plain_plain_message_authzid", Buffer, self.handle)
        return None if data is None else data.decode()

    @property
    def authcid(self) -> str:
        return self.library.output("umilib_auth_sasl_plain_plain_message_authcid", self.handle).decode()

    @property
    def password(self) -> str:
        return self.library.output("umilib_auth_sasl_plain_plain_message_password", self.handle).decode()

    def prepared_authcid(self) -> str:
        """The authentication identity prepared with SASLprep as a query."""
        return self.library.output("umilib_auth_sasl_plain_plain_message_prepared_authcid", self.handle).decode()

    def verify_password(self, stored: str) -> bool:
        """Whether the password matches ``stored`` (both prepared with SASLprep, compared in constant time)."""
        return self.library.value("umilib_auth_sasl_plain_plain_message_verify_password", ctypes.c_bool, self.handle, *Text.encode(stored))

    @staticmethod
    def prepare(text: str, unassigned: Unassigned) -> str:
        """``text`` prepared with SASLprep; raises ``Length`` for an empty result."""
        return Library.default().output("umilib_auth_sasl_plain_plain_message_prepare", *Text.encode(text), int(unassigned)).decode()


__all__ = ["PLAINMessage"]
