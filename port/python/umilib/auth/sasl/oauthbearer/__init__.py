"""OAUTHBEARER (RFC 7628): an OAuth 2.0 bearer token in key/value pairs after a GS2 header. Mirrors
``umilib::auth::sasl::oauthbearer``."""

from __future__ import annotations

import ctypes

from umilib.auth.sasl import GS2Header
from umilib.ffi import Buffer, Bytes, Handle, Library, Text

P = "umilib_auth_sasl_oauthbearer_oauthbearer"


class OAUTHBEARERMessage(Handle):
    """The initial client response of OAUTHBEARER: a GS2 header and ``key=value`` pairs."""

    FREE = f"{P}_message_free"
    #: The response a client sends after an error result.
    DUMMY = b"\x01"

    @staticmethod
    def new(authzid: str | None, token: str, host: str | None = None, port: int | None = None) -> OAUTHBEARERMessage:
        return OAUTHBEARERMessage(
            Handle.create(f"{P}_message_new", *Text.encode(authzid), *Text.encode(token), *Text.encode(host), port or 0, port is not None)
        )

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> OAUTHBEARERMessage:
        return OAUTHBEARERMessage(Handle.create(f"{P}_message_decode", *Bytes.readable(message)))

    def encode(self) -> bytes:
        return self.library.output(f"{P}_message_encode", self.handle)

    @staticmethod
    def is_dummy(message: bytes | bytearray | memoryview) -> bool:
        return Library.default().value(f"{P}_message_is_dummy", ctypes.c_bool, *Bytes.readable(message))

    @property
    def header(self) -> GS2Header:
        return GS2Header(Handle.create(f"{P}_message_header", self.handle))

    def get(self, key: str) -> str | None:
        data = self.library.optional(f"{P}_message_get", Buffer, self.handle, *Text.encode(key))
        return None if data is None else data.decode()

    @property
    def pairs(self) -> list[tuple[str, str]]:
        count = self.library.value(f"{P}_message_pair_count", ctypes.c_size_t, self.handle)
        pairs = []
        for index in range(count):
            key, value = Buffer(), Buffer()
            self.library.call(f"{P}_message_pair", self.handle, index, ctypes.byref(key), ctypes.byref(value))
            pairs.append((self.library.take(key).decode(), self.library.take(value).decode()))
        return pairs

    def auth(self) -> str | None:
        return self.get("auth")

    def host(self) -> str | None:
        return self.get("host")

    def port(self) -> int | None:
        return self.library.optional(f"{P}_message_port", ctypes.c_uint16, self.handle)

    def bearer_token(self) -> str | None:
        data = self.library.optional(f"{P}_message_bearer_token", Buffer, self.handle)
        return None if data is None else data.decode()


class OAUTHBEARERErrorResult(Handle):
    """The error result of a failed exchange: the status, and the scope and OpenID configuration URL, if any."""

    FREE = f"{P}_error_result_free"

    @staticmethod
    def new(status: str, scope: str | None = None, openid_configuration: str | None = None) -> OAUTHBEARERErrorResult:
        return OAUTHBEARERErrorResult(Handle.create(f"{P}_error_result_new", *Text.encode(status), *Text.encode(scope), *Text.encode(openid_configuration)))

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> OAUTHBEARERErrorResult:
        return OAUTHBEARERErrorResult(Handle.create(f"{P}_error_result_decode", *Bytes.readable(message)))

    def encode(self) -> bytes:
        return self.library.output(f"{P}_error_result_encode", self.handle)

    def parts(self) -> tuple[str, str | None, str | None]:
        """The status, the scope and the OpenID configuration URL."""
        status, scope, configuration = Buffer(), Buffer(), Buffer()
        has_scope, has_configuration = ctypes.c_bool(), ctypes.c_bool()
        self.library.call(
            f"{P}_error_result_parts", self.handle, ctypes.byref(status), ctypes.byref(has_scope), ctypes.byref(scope), ctypes.byref(has_configuration), ctypes.byref(configuration)
        )
        status_text, scope_text, configuration_text = (self.library.take(buffer).decode() for buffer in (status, scope, configuration))
        return status_text, scope_text if has_scope.value else None, configuration_text if has_configuration.value else None

    @property
    def status(self) -> str:
        return self.parts()[0]

    @property
    def scope(self) -> str | None:
        return self.parts()[1]

    @property
    def openid_configuration(self) -> str | None:
        return self.parts()[2]


__all__ = ["OAUTHBEARERErrorResult", "OAUTHBEARERMessage"]
