"""HTTP (RFC 9110): the semantics every version shares, without I/O. Mirrors ``umilib::protocol::http``.

Requests and responses (:class:`HTTPRequest`, :class:`HTTPResponse`) carry their fields in
:class:`HTTPFields`; :class:`HTTPRule` routes requests. :class:`HTTPConnection` is the interface of
the connections of every version: ``v1`` (HTTP/1.1), ``v2`` (HTTP/2) and ``v3`` (HTTP/3);
``websocket`` opens WebSocket connections over them. Errors are :class:`HTTPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library


__all__ = [
    "HTTPConfig",
    "HTTPConnection",
    "HTTPError",
    "HTTPErrorKind",
    "HTTPEvent",
    "HTTPEventKind",
    "HTTPFields",
    "HTTPRequest",
    "HTTPReset",
    "HTTPResponse",
    "HTTPRule",
    "HTTPStatus",
    "HTTPVersion",
]


class HTTPError(FFIError):
    """An error of HTTP: ``Malformed``, ``TooLarge``, ``ContentCoding``, ``Protocol``, ``State``,
    ``Config``, ``InvalidPattern`` or ``NoSuchField``."""


Library.register_error("protocol.http", HTTPError)


@dataclasses.dataclass(frozen=True)
class HTTPVersion:
    major: int
    minor: int


HTTPVersion.HTTP1_0 = HTTPVersion(1, 0)  # type: ignore[attr-defined]
HTTPVersion.HTTP1_1 = HTTPVersion(1, 1)  # type: ignore[attr-defined]
HTTPVersion.HTTP2 = HTTPVersion(2, 0)  # type: ignore[attr-defined]
HTTPVersion.HTTP3 = HTTPVersion(3, 0)  # type: ignore[attr-defined]


class HTTPStatus(int):
    """A status code (RFC 9110 §15)."""

    @property
    def reason(self) -> str:
        """The reason phrase of the code, empty if it has none."""
        return Library.default().output("umilib_protocol_http_http_status_reason", int(self)).decode("ascii")


@dataclasses.dataclass
class HTTPConfig:
    """The limits every version keeps on what a peer sends."""

    C_TYPE: ClassVar[str] = "umilib_protocol_http_HTTPConfig"

    maximum_field_section_size: int = 1 << 16
    maximum_target_length: int = 8 << 10
    maximum_buffered_content: int = 1 << 20
    maximum_events: int = 4096


class HTTPFields(Handle):
    """A header or trailer section: field lines in their order, names lowercased (RFC 9110 §5)."""

    FREE = "umilib_protocol_http_http_fields_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_protocol_http_http_fields_new"))

    @classmethod
    def of(cls, lines: list[tuple[bytes, bytes]]) -> HTTPFields:
        fields = cls()
        for name, value in lines:
            fields.append(name, value)
        return fields

    def append(self, name: bytes, value: bytes) -> None:
        self.library.call("umilib_protocol_http_http_fields_append", self.handle, *Bytes.readable(name), *Bytes.readable(value))

    def set(self, name: bytes, value: bytes) -> None:
        """Replaces the lines of ``name`` with one of ``value``."""
        self.library.call("umilib_protocol_http_http_fields_set", self.handle, *Bytes.readable(name), *Bytes.readable(value))

    def remove(self, name: bytes) -> bool:
        return self.library.value("umilib_protocol_http_http_fields_remove", ctypes.c_bool, self.handle, *Bytes.readable(name))

    def get(self, name: bytes) -> bytes | None:
        """The values of the lines of ``name`` joined by ", " (RFC 9110 §5.3), or ``None``."""
        return self.library.optional("umilib_protocol_http_http_fields_get", Buffer, self.handle, *Bytes.readable(name))

    def __len__(self) -> int:
        return self.library.value("umilib_protocol_http_http_fields_count", ctypes.c_size_t, self.handle)

    def line(self, index: int) -> tuple[bytes, bytes, bool]:
        """The name, value and sensitivity of the line ``index``."""
        name, value, sensitive = Buffer(), Buffer(), ctypes.c_bool()
        self.library.call("umilib_protocol_http_http_fields_line", self.handle, index, ctypes.byref(name), ctypes.byref(value), ctypes.byref(sensitive))
        return self.library.take(name), self.library.take(value), sensitive.value

    def lines(self) -> list[tuple[bytes, bytes]]:
        return [self.line(index)[:2] for index in range(len(self))]

    def set_sensitive(self, index: int, sensitive: bool) -> None:
        """Marks the line ``index`` never to be indexed by HPACK or QPACK."""
        self.library.call("umilib_protocol_http_http_fields_set_sensitive", self.handle, index, sensitive)


class HTTPRequest(Handle):
    """The head of a request as every version carries it."""

    FREE = "umilib_protocol_http_http_request_free"

    @classmethod
    def new(cls, method: bytes, scheme: bytes, authority: bytes, path: bytes) -> HTTPRequest:
        return cls(Handle.create("umilib_protocol_http_http_request_new", *Bytes.readable(method), *Bytes.readable(scheme), *Bytes.readable(authority), *Bytes.readable(path)))

    @classmethod
    def connect(cls, authority: bytes) -> HTTPRequest:
        """A CONNECT request for a tunnel to ``authority`` (RFC 9110 §9.3.6)."""
        return cls(Handle.create("umilib_protocol_http_http_request_connect", *Bytes.readable(authority)))

    @property
    def method(self) -> bytes:
        return self.library.output("umilib_protocol_http_http_request_method", self.handle)

    @property
    def scheme(self) -> bytes | None:
        return self.library.optional("umilib_protocol_http_http_request_scheme", Buffer, self.handle)

    def host(self) -> bytes | None:
        """The authority of the target, else of the Host field."""
        return self.library.optional("umilib_protocol_http_http_request_host", Buffer, self.handle)

    @property
    def path(self) -> bytes:
        return self.library.output("umilib_protocol_http_http_request_path", self.handle)

    @property
    def protocol(self) -> bytes | None:
        """The protocol of an extended CONNECT (RFC 8441 §4)."""
        return self.library.optional("umilib_protocol_http_http_request_protocol", Buffer, self.handle)

    @protocol.setter
    def protocol(self, protocol: bytes | None) -> None:
        data, length = Bytes.readable(protocol) if protocol is not None else (None, 0)
        self.library.call("umilib_protocol_http_http_request_set_protocol", self.handle, data, length)

    @property
    def fields(self) -> HTTPFields:
        """A copy of the header fields; assign to change them."""
        return HTTPFields(Handle.create("umilib_protocol_http_http_request_fields", self.handle))

    @fields.setter
    def fields(self, fields: HTTPFields) -> None:
        self.library.call("umilib_protocol_http_http_request_set_fields", self.handle, fields)

    def check(self) -> None:
        """Checks the rules of the head every version shares (RFC 9110 §7.1, §9.3.6, RFC 8441 §4)."""
        self.library.call("umilib_protocol_http_http_request_check", self.handle)


class HTTPResponse(Handle):
    """The head of a response."""

    FREE = "umilib_protocol_http_http_response_free"

    @classmethod
    def new(cls, status: int) -> HTTPResponse:
        return cls(Handle.create("umilib_protocol_http_http_response_new", status))

    @property
    def status(self) -> HTTPStatus:
        return HTTPStatus(self.library.value("umilib_protocol_http_http_response_status", ctypes.c_uint16, self.handle))

    @property
    def fields(self) -> HTTPFields:
        """A copy of the header fields; assign to change them."""
        return HTTPFields(Handle.create("umilib_protocol_http_http_response_fields", self.handle))

    @fields.setter
    def fields(self, fields: HTTPFields) -> None:
        self.library.call("umilib_protocol_http_http_response_set_fields", self.handle, fields)


class HTTPRule(Handle):
    """The rule of a router that routes requests by host (without case or port), path (with its query,
    not decoded), method and fields. Patterns are the text of ``umilib.service.Pattern``: ``*``,
    ``prefix*``, ``*suffix`` or exact bytes."""

    FREE = "umilib_protocol_http_http_rule_free"

    @classmethod
    def new(cls, host: bytes = b"*", path: bytes = b"*") -> HTTPRule:
        return cls(Handle.create("umilib_protocol_http_http_rule_new", *Bytes.readable(host), *Bytes.readable(path)))

    def with_method(self, method: bytes) -> HTTPRule:
        """These requests, of ``method`` only."""
        self.library.call("umilib_protocol_http_http_rule_set_method", self.handle, *Bytes.readable(method))
        return self

    def with_field(self, name: bytes, value: bytes) -> HTTPRule:
        """These requests, with a field ``name`` whose value the pattern ``value`` matches."""
        self.library.call("umilib_protocol_http_http_rule_add_field", self.handle, *Bytes.readable(name), *Bytes.readable(value))
        return self

    def matches(self, request: HTTPRequest) -> bool:
        return self.library.value("umilib_protocol_http_http_rule_matches", ctypes.c_bool, self.handle, request)


class HTTPEventKind(enum.IntEnum):
    REQUEST = 0
    RESPONSE = 1
    DATA = 2
    TRAILERS = 3
    END = 4
    RESET = 5
    WRITABLE = 6
    GO_AWAY = 7
    CLOSED = 8


class HTTPErrorKind(enum.IntEnum):
    """The variant of the error a ``CLOSED`` event reports."""

    MALFORMED = 1
    TOO_LARGE = 2
    CONTENT_CODING = 3
    PROTOCOL = 4
    STATE = 5
    CONFIG = 6


class HTTPReset(enum.IntEnum):
    """Why this end abandons a stream."""

    CANCEL = 0
    REFUSED = 1
    INTERNAL = 2
    NO_ERROR = 3


@dataclasses.dataclass
class HTTPEvent:
    """What a connection tells its application: the kind, the stream (the last one of ``GO_AWAY``),
    whether a head ends its message, the version's error code of ``RESET`` or of a ``PROTOCOL`` error,
    the error of ``CLOSED`` (``None`` if it closed cleanly), and the request, response or trailers."""

    kind: HTTPEventKind
    stream: int = 0
    end: bool = False
    code: int = 0
    error: HTTPErrorKind | None = None
    request: HTTPRequest | None = None
    response: HTTPResponse | None = None
    fields: HTTPFields | None = None


class HTTPConnection:
    """A connection of any version, as its application sees it: it sends and receives messages on
    streams, without I/O. A subclass names its C functions by :meth:`call`."""

    def call(self, name: str, *arguments: Any) -> None:
        """Calls the C function of the connection's ``name``."""
        raise NotImplementedError

    def send_request(self, request: HTTPRequest, end: bool = True) -> int:
        """Starts an exchange; its stream."""
        stream = ctypes.c_uint64()
        self.call("send_request", request, end, ctypes.byref(stream))
        return stream.value

    def send_response(self, stream: int, response: HTTPResponse, end: bool = False) -> None:
        self.call("send_response", stream, response, end)

    def send_data(self, stream: int, data: bytes, end: bool = False) -> int:
        """Writes content; how much was taken."""
        count = ctypes.c_size_t()
        self.call("send_data", stream, *Bytes.readable(data), end, ctypes.byref(count))
        return count.value

    def send_trailers(self, stream: int, trailers: HTTPFields) -> None:
        self.call("send_trailers", stream, trailers)

    def read_data(self, stream: int, size: int = 1 << 16) -> bytes:
        """Up to ``size`` bytes of content that arrived."""
        out = (ctypes.c_uint8 * max(size, 1))()
        count = ctypes.c_size_t()
        self.call("read_data", stream, out, size, ctypes.byref(count))
        return bytes(out[: count.value])

    def reset(self, stream: int, reason: HTTPReset = HTTPReset.CANCEL) -> None:
        self.call("reset", stream, int(reason))

    def poll_event(self) -> HTTPEvent | None:
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_http_HTTPEvent")()
        request, response, fields = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        self.call("poll_event", ctypes.byref(found), ctypes.byref(structure), ctypes.byref(request), ctypes.byref(response), ctypes.byref(fields))
        if not found.value:
            return None
        return HTTPEvent(
            kind=HTTPEventKind(structure.kind),
            stream=structure.stream,
            end=structure.end,
            code=structure.code,
            error=HTTPErrorKind(structure.error) if structure.error else None,
            request=HTTPRequest(request.value) if request.value else None,
            response=HTTPResponse(response.value) if response.value else None,
            fields=HTTPFields(fields.value) if fields.value else None,
        )

    def shutdown(self) -> None:
        """Takes no new exchanges: those under way finish, then the connection closes."""
        self.call("shutdown")

    def is_closed(self) -> bool:
        closed = ctypes.c_bool()
        self.call("is_closed", ctypes.byref(closed))
        return closed.value

    def version(self) -> HTTPVersion:
        major, minor = ctypes.c_uint8(), ctypes.c_uint8()
        self.call("version", ctypes.byref(major), ctypes.byref(minor))
        return HTTPVersion(major.value, minor.value)
