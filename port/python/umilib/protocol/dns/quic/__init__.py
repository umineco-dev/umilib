"""DNS over dedicated QUIC connections (RFC 9250): a query and its response a stream, over a
connection of :mod:`umilib.protocol.quic`. Mirrors ``umilib::protocol::dns::quic``."""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import Any

from umilib.ffi import Buffer, Bytes, Handle, Library

P = "umilib_protocol_dns_quic"


class DNSQUICEventKind(enum.IntEnum):
    QUERY = 0
    RESPONSE = 1
    CANCELLED = 2
    QUIC = 3


@dataclasses.dataclass(frozen=True)
class DNSQUICEvent:
    """An event: a query or a response on ``stream`` with its message, a stream cancelled with
    ``error``, or an event of QUIC itself (``quic``)."""

    kind: DNSQUICEventKind
    stream: int
    error: int
    message: bytes
    quic: Any = None


class DNSQUICConnection(Handle):
    """The DNS of a QUIC connection of an endpoint."""

    FREE = f"{P}_dns_quic_connection_free"
    ALPN = b"doq"
    PORT = 853

    def __init__(self, server: bool = False) -> None:
        super().__init__(Handle.create(f"{P}_dns_quic_connection_new", server))

    def send_query(self, connection: Any, query: bytes) -> int:
        """Sends ``query`` on a new stream of ``connection`` (its ID made 0, §4.2.1); the stream."""
        return self.library.value(f"{P}_dns_quic_connection_send_query", ctypes.c_uint64, self.handle, connection.endpoint.handle, connection.handle, *Bytes.readable(query))

    def send_response(self, connection: Any, stream: int, responses: list[bytes]) -> None:
        """Sends ``responses``, all the responses to the query of ``stream`` (one, or the messages of a
        zone transfer), the stream ended after them."""
        framed = b"".join(len(response).to_bytes(2, "big") + response for response in responses)
        self.library.call(f"{P}_dns_quic_connection_send_response", self.handle, connection.endpoint.handle, connection.handle, stream, *Bytes.readable(framed))

    def process(self, connection: Any, now: int) -> None:
        """Takes the events of ``connection``; a breach of RFC 9250 closes it and raises ``Protocol``."""
        self.library.call(f"{P}_dns_quic_connection_process", self.handle, connection.endpoint.handle, connection.handle, now)

    def poll_event(self) -> DNSQUICEvent | None:
        found, structure = ctypes.c_bool(), self.library.type(f"{P}_DNSQUICEvent")()
        quic, message = self.library.type("umilib_protocol_quic_QUICEvent")(), Buffer()
        self.library.call(f"{P}_dns_quic_connection_poll_event", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(quic), ctypes.byref(message))
        data = self.library.take(message)
        if not found.value:
            return None
        kind = DNSQUICEventKind(structure.kind)
        return DNSQUICEvent(kind, structure.stream, structure.error, data, quic if kind == DNSQUICEventKind.QUIC else None)
