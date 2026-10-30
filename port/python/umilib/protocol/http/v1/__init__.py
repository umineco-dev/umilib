"""HTTP/1.1 (RFC 9112). Mirrors ``umilib::protocol::http::v1``.

An :class:`H1Connection` does no I/O: give it the bytes that arrive with :meth:`H1Connection.receive`
and send what :meth:`H1Connection.transmit` returns; close the byte stream when
:meth:`H1Connection.wants_close`. ``now`` is nanoseconds of a monotonic clock.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.ffi import Bytes, Handle, Structures
from umilib.protocol.http import HTTPConfig, HTTPConnection

P = "umilib_protocol_http_v1"

__all__ = ["H1Connection", "H1Limits"]


@dataclasses.dataclass
class H1Limits:
    """The limits of HTTP/1.1 connections; timeouts in milliseconds, 0 for none."""

    C_TYPE: ClassVar[str] = f"{P}_H1Limits"

    http: HTTPConfig = dataclasses.field(default_factory=HTTPConfig)
    maximum_pipelined: int = 16
    maximum_chunk_line: int = 4 << 10
    idle_timeout: int = 60_000
    head_timeout: int = 30_000
    continue_automatically: bool = True


class H1Connection(Handle, HTTPConnection):
    """An HTTP/1.1 connection of a client or a server."""

    FREE = f"{P}_h1_connection_free"

    def call(self, name: str, *arguments: Any) -> None:
        self.library.call(f"{P}_h1_connection_{name}", self.handle, *arguments)

    @classmethod
    def client(cls, now: int, limits: H1Limits | None = None, scheme: bytes = b"http") -> H1Connection:
        structure = Structures.to_structure(limits or H1Limits())
        return cls(Handle.create(f"{P}_h1_connection_client", ctypes.byref(structure), *Bytes.readable(scheme), now))

    @classmethod
    def server(cls, now: int, limits: H1Limits | None = None, scheme: bytes = b"http") -> H1Connection:
        """A server's connection, whose requests in origin-form are of ``scheme``."""
        structure = Structures.to_structure(limits or H1Limits())
        return cls(Handle.create(f"{P}_h1_connection_server", ctypes.byref(structure), *Bytes.readable(scheme), now))

    def receive(self, data: bytes, now: int) -> None:
        self.call("receive", *Bytes.readable(data), now)

    def receive_close(self, now: int) -> None:
        """Takes the end of the byte stream from the peer."""
        self.call("receive_close", now)

    def wants_receive(self) -> bool:
        return self.library.value(f"{P}_h1_connection_wants_receive", ctypes.c_bool, self.handle)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_h1_connection_transmit", self.handle)

    def wants_close(self) -> bool:
        return self.library.value(f"{P}_h1_connection_wants_close", ctypes.c_bool, self.handle)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_h1_connection_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.call("expire", now)
