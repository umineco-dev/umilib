"""EXTERNAL (RFC 4422 appendix A): the authorization identity of credentials established outside SASL.
Mirrors ``umilib::auth::sasl::external``."""

from __future__ import annotations

from umilib.ffi import Buffer, Bytes, Handle, Text

P = "umilib_auth_sasl_external_external_message"


class EXTERNALMessage(Handle):
    """The message of EXTERNAL: empty, or the authorization identity."""

    FREE = f"{P}_free"

    @staticmethod
    def new(authzid: str | None) -> EXTERNALMessage:
        return EXTERNALMessage(Handle.create(f"{P}_new", *Text.encode(authzid)))

    @staticmethod
    def decode(message: bytes | bytearray | memoryview) -> EXTERNALMessage:
        return EXTERNALMessage(Handle.create(f"{P}_decode", *Bytes.readable(message)))

    def encode(self) -> bytes:
        return self.library.output(f"{P}_encode", self.handle)

    @property
    def authzid(self) -> str | None:
        data = self.library.optional(f"{P}_authzid", Buffer, self.handle)
        return None if data is None else data.decode()


__all__ = ["EXTERNALMessage"]
