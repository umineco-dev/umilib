"""WebSocket (RFC 6455) with permessage-deflate (RFC 7692). Mirrors ``umilib::protocol::websocket``.

A :class:`WebSocketConnection` does no I/O: give it the bytes that arrive with
:meth:`WebSocketConnection.receive`, send what :meth:`WebSocketConnection.transmit` returns, and close
the transport when :meth:`WebSocketConnection.wants_close`. ``umilib.protocol.http.websocket`` opens
the connection over HTTP. Errors are :class:`WebSocketError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import os
from typing import ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Structures, Text

P = "umilib_protocol_websocket"

__all__ = [
    "WebSocketCloseCode",
    "WebSocketConfig",
    "WebSocketConnection",
    "WebSocketDeflateParameters",
    "WebSocketError",
    "WebSocketEvent",
    "WebSocketEventKind",
    "WebSocketRole",
    "WebSocketState",
]


class WebSocketError(FFIError):
    """An error of WebSocket: ``Refused`` (the state, message, code or reason does not allow the call)
    or ``Config``."""


Library.register_error("protocol.websocket", WebSocketError)


class WebSocketCloseCode(enum.IntEnum):
    """The status codes of RFC 6455 §7.4.1; others of 3000 to 4999 are the applications'."""

    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011


class WebSocketRole(enum.Enum):
    CLIENT = "client"
    SERVER = "server"


class WebSocketState(enum.IntEnum):
    OPEN = 0
    CLOSING = 1
    CLOSED = 2


class WebSocketEventKind(enum.IntEnum):
    TEXT = 0
    BINARY = 1
    PING = 2
    PONG = 3
    CLOSED = 4


@dataclasses.dataclass(frozen=True)
class WebSocketEvent:
    """A message (the text as UTF-8 bytes), a Ping or Pong, or the end with its code and reason."""

    kind: WebSocketEventKind
    data: bytes = b""
    code: int = 0

    @property
    def text(self) -> str:
        return self.data.decode("utf-8")


@dataclasses.dataclass
class WebSocketConfig:
    C_TYPE: ClassVar[str] = f"{P}_WebSocketConfig"

    maximum_message_size: int = 16 << 20
    maximum_frame_size: int = 64 << 10
    deflate_level: int = 6
    maximum_events: int = 4096


@dataclasses.dataclass(frozen=True)
class WebSocketDeflateParameters:
    """The parameters of permessage-deflate (RFC 7692 §7.1). ``client_max_window_bits`` is ``None``
    when absent and ``0`` for the parameter without a value."""

    server_no_context_takeover: bool = False
    client_no_context_takeover: bool = False
    server_max_window_bits: int | None = None
    client_max_window_bits: int | None = None

    def to_structure(self) -> ctypes.Structure:
        structure = Library.default().type(f"{P}_WebSocketDeflateParameters")()
        Fields.assign(structure, "server_no_context_takeover", self.server_no_context_takeover)
        Fields.assign(structure, "client_no_context_takeover", self.client_no_context_takeover)
        Fields.assign(structure, "server_max_window_bits", self.server_max_window_bits or 0)
        Fields.assign(structure, "has_client_max_window_bits", self.client_max_window_bits is not None)
        Fields.assign(structure, "client_max_window_bits", self.client_max_window_bits or 0)
        return structure

    @classmethod
    def from_structure(cls, structure: ctypes.Structure) -> WebSocketDeflateParameters:
        return cls(
            server_no_context_takeover=structure.server_no_context_takeover,
            client_no_context_takeover=structure.client_no_context_takeover,
            server_max_window_bits=structure.server_max_window_bits or None,
            client_max_window_bits=structure.client_max_window_bits if structure.has_client_max_window_bits else None,
        )

    @staticmethod
    def pointer(parameters: WebSocketDeflateParameters | None) -> object:
        """The argument of optional parameters: a reference, or null."""
        return ctypes.byref(parameters.to_structure()) if parameters is not None else None

    def accept(self) -> WebSocketDeflateParameters:
        """The parameters a server accepts for this offer."""
        out = Library.default().type(f"{P}_WebSocketDeflateParameters")()
        Library.default().call(f"{P}_websocket_deflate_parameters_accept", ctypes.byref(self.to_structure()), ctypes.byref(out))
        return WebSocketDeflateParameters.from_structure(out)


class WebSocketConnection(Handle):
    """A WebSocket connection of a client (whose frames are masked) or a server."""

    FREE = f"{P}_websocket_connection_free"

    def __init__(
        self,
        role: WebSocketRole,
        config: WebSocketConfig | None = None,
        deflate: WebSocketDeflateParameters | None = None,
        seed: bytes | None = None,
    ) -> None:
        """A connection with permessage-deflate of the agreed ``deflate``, if any."""
        super().__init__(
            Handle.create(
                f"{P}_websocket_connection_new", role == WebSocketRole.SERVER, Structures.to_structure(config or WebSocketConfig()),
                WebSocketDeflateParameters.pointer(deflate), *Bytes.readable(seed or os.urandom(48)),
            )  # fmt: skip
        )

    def receive(self, data: bytes) -> None:
        self.library.call(f"{P}_websocket_connection_receive", self.handle, *Bytes.readable(data))

    def receive_close(self) -> None:
        """Takes the end of the transport."""
        self.library.call(f"{P}_websocket_connection_receive_close", self.handle)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_websocket_connection_transmit", self.handle)

    def wants_close(self) -> bool:
        return self.library.value(f"{P}_websocket_connection_wants_close", ctypes.c_bool, self.handle)

    def wants_receive(self) -> bool:
        """Whether to read more from the transport: false while events wait up to their limit."""
        return self.library.value(f"{P}_websocket_connection_wants_receive", ctypes.c_bool, self.handle)

    @property
    def state(self) -> WebSocketState:
        return WebSocketState(self.library.value(f"{P}_websocket_connection_state", ctypes.c_uint8, self.handle))

    def send_text(self, text: str) -> None:
        self.library.call(f"{P}_websocket_connection_send_text", self.handle, *Text.encode(text))

    def send_binary(self, data: bytes) -> None:
        self.library.call(f"{P}_websocket_connection_send_binary", self.handle, *Bytes.readable(data))

    def send_ping(self, data: bytes = b"") -> None:
        self.library.call(f"{P}_websocket_connection_send_ping", self.handle, *Bytes.readable(data))

    def close(self, code: int = WebSocketCloseCode.NORMAL, reason: str = "") -> None:
        """Starts the closing handshake (RFC 6455 §7.1.2)."""
        self.library.call(f"{P}_websocket_connection_close", self.handle, int(code), *Text.encode(reason))

    def poll_event(self) -> WebSocketEvent | None:
        found = ctypes.c_bool()
        structure = Library.default().type(f"{P}_WebSocketEvent")()
        buffer = Buffer()
        self.library.call(f"{P}_websocket_connection_poll_event", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        data = self.library.take(buffer)
        return WebSocketEvent(WebSocketEventKind(structure.kind), data, structure.code) if found.value else None
