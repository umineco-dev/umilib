"""HTTP/3 (RFC 9114) over QUIC. Mirrors ``umilib::protocol::http::v3``.

An :class:`H3Connection` is the state of HTTP/3 on a QUIC connection of a
:class:`~umilib.protocol.quic.QUICEndpoint`; an :class:`H3Session` joins the two and is the
:class:`~umilib.protocol.http.HTTPConnection`. After the endpoint takes datagrams or fires timers,
call :meth:`H3Session.process`; the QUIC events HTTP/3 does not handle come from
:meth:`H3Session.poll_quic_event`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.codec.qpack import QPACKDecoderConfig, QPACKEncoderConfig
from umilib.ffi import Buffer, Handle, Library, Structures
from umilib.protocol.http import HTTPConfig, HTTPConnection
from umilib.protocol.quic import QUICCloseReason, QUICConnection, QUICEvent, QUICEventKind


__all__ = ["H3Config", "H3Connection", "H3Session"]


@dataclasses.dataclass
class H3Config:
    """The configuration of HTTP/3 connections; the defaults are the library's (:meth:`default`)."""

    C_TYPE: ClassVar[str] = "umilib_protocol_http_v3_H3Config"

    http: HTTPConfig
    qpack_encoder: QPACKEncoderConfig
    qpack_decoder: QPACKDecoderConfig
    enable_connect_protocol: bool
    grease: bool

    @classmethod
    def default(cls) -> H3Config:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call("umilib_protocol_http_v3_h3_config_default", ctypes.byref(structure))
        return Structures.from_structure(cls, structure)


class H3Connection(Handle):
    """The state of HTTP/3 on one QUIC connection."""

    FREE = "umilib_protocol_http_v3_h3_connection_free"

    @classmethod
    def client(cls, now: int, config: H3Config | None = None) -> H3Connection:
        return cls(Handle.create("umilib_protocol_http_v3_h3_connection_client", Structures.to_structure(config or H3Config.default()), now))

    @classmethod
    def server(cls, now: int, config: H3Config | None = None) -> H3Connection:
        return cls(Handle.create("umilib_protocol_http_v3_h3_connection_server", Structures.to_structure(config or H3Config.default()), now))


class H3Session(HTTPConnection):
    """An :class:`H3Connection` with its QUIC connection."""

    def __init__(self, connection: H3Connection, quic: QUICConnection) -> None:
        self.connection = connection
        self.quic = quic

    def call(self, name: str, *arguments: Any) -> None:
        Library.default().call(f"umilib_protocol_http_v3_h3_connection_{name}", self.connection, self.quic.endpoint, self.quic.handle, *arguments)

    def process(self, now: int) -> None:
        """Handles what the QUIC connection received: its events, frames and QPACK instructions."""
        self.call("process", now)

    def poll_quic_event(self) -> QUICEvent | None:
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_quic_QUICEvent")()
        buffer = Buffer()
        self.call("poll_quic_event", ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        data = Library.default().take(buffer)
        if not found.value:
            return None
        kind = QUICEventKind(structure.kind)
        reason = QUICCloseReason(structure.reason) if kind == QUICEventKind.CLOSED else None
        return QUICEvent(kind, structure.stream, structure.error, structure.bidirectional, reason, data)
