"""PLAIN (RFC 4616): the authorization identity, the authentication identity and the password. Mirrors
``umilib::auth::sasl::plain``."""

from __future__ import annotations

import ctypes

from umilib.codec.stringprep import Unassigned
from umilib.ffi import Buffer, Bytes, Handle, Library, Text

P = "umilib_auth_sasl_plain_plain_message"


class PLAINMessage(Handle):
    """The message of PLAIN (RFC 4616 section 2). It holds the password in the clear: use it over TLS only."""

    FREE = f"{P}_free"

    @staticmethod
    def new(authzid: str | None, authcid: str, password: str) -> PLAINMessage:
        return PLAINMessage(Handle.create(f"{P}_new", *Text.encode(authzid), *Text.encode(authcid), *Text.encode(password)))

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> PLAINMessage:
        return PLAINMessage(Handle.create(f"{P}_decode", *Bytes.readable(message)))

    def encode(self) -> bytearray:
        """The bytes of the message, which hold the password (a ``bytearray`` the caller may zeroize)."""
        return self.library.output_secret(f"{P}_encode", self.handle)

    @property
    def authzid(self) -> str | None:
        data = self.library.optional(f"{P}_authzid", Buffer, self.handle)
        return None if data is None else data.decode()

    @property
    def authcid(self) -> str:
        return self.library.output(f"{P}_authcid", self.handle).decode()

    @property
    def password(self) -> str:
        return self.library.output(f"{P}_password", self.handle).decode()

    def prepared_authcid(self) -> str:
        """The authentication identity prepared with SASLprep as a query."""
        return self.library.output(f"{P}_prepared_authcid", self.handle).decode()

    def verify_password(self, stored: str) -> bool:
        """Whether the password matches ``stored`` (both prepared with SASLprep, compared in constant time)."""
        return self.library.value(f"{P}_verify_password", ctypes.c_bool, self.handle, *Text.encode(stored))

    @staticmethod
    def prepare(text: str, unassigned: Unassigned) -> str:
        """``text`` prepared with SASLprep; raises ``Length`` for an empty result."""
        return Library.default().output(f"{P}_prepare", *Text.encode(text), int(unassigned)).decode()


__all__ = ["PLAINMessage"]
