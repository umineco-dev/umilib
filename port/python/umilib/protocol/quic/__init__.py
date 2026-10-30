"""QUIC versions 1 and 2 (RFC 9000, RFC 9001, RFC 9002, RFC 9369), with Version Negotiation (RFC
9368), DATAGRAM frames (RFC 9221) and the greasing of the QUIC bit (RFC 9287). Mirrors
``umilib::protocol::quic``.

A :class:`QUICEndpoint` does no I/O: give it each datagram that arrives with
:meth:`QUICEndpoint.receive`, send what :meth:`QUICEndpoint.transmit` returns until it returns
``None``, and call :meth:`QUICEndpoint.expire` at :meth:`QUICEndpoint.poll_timeout`. Its
connections are :class:`QUICConnection` objects named by numbers. ``now`` is nanoseconds of a
monotonic clock; ``time`` seconds since 1970, for certificates and tokens. Errors are :class:`QUICError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import os
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Text, Words
from umilib.protocol.ip import IPEndpoint
from umilib.protocol.tls import TLSClientConfig, TLSServerConfig

P = "umilib_protocol_quic"

__all__ = [
    "QUICCloseReason",
    "QUICConfig",
    "QUICConnection",
    "QUICConnectionState",
    "QUICECN",
    "QUICEndpoint",
    "QUICError",
    "QUICEvent",
    "QUICEventKind",
    "QUICLimits",
    "QUICSession",
    "QUICVersion",
]


class QUICError(FFIError):
    """An error of QUIC: ``InvalidPacket``, ``Transport`` (the peer broke the protocol), ``State``,
    ``Config``, ``Random`` or ``UnknownConnection``."""


Library.register_error("protocol.quic", QUICError)


class QUICVersion(int):
    """A QUIC version (RFC 8999 §5.1)."""

    V1: ClassVar[QUICVersion]
    V2: ClassVar[QUICVersion]


QUICVersion.V1, QUICVersion.V2 = QUICVersion(0x0000_0001), QUICVersion(0x6B33_43CF)


class QUICECN(enum.IntEnum):
    """The ECN codepoint of a datagram (RFC 3168 §5)."""

    NOT_ECT = 0
    ECT1 = 1
    ECT0 = 2
    CE = 3


class QUICConnectionState(enum.IntEnum):
    HANDSHAKING = 0
    ESTABLISHED = 1
    CLOSING = 2
    DRAINING = 3
    CLOSED = 4


class QUICEventKind(enum.IntEnum):
    CONNECTED = 0
    HANDSHAKE_CONFIRMED = 1
    STREAM_OPENED = 2
    STREAM_READABLE = 3
    STREAM_WRITABLE = 4
    STREAM_RESET = 5
    STOP_SENDING = 6
    STREAMS_AVAILABLE = 7
    DATAGRAM = 8
    NEW_TOKEN = 9
    ZERO_RTT_REJECTED = 10
    CLOSED = 11


class QUICCloseReason(enum.IntEnum):
    LOCAL = 0
    LOCAL_APPLICATION = 1
    PEER = 2
    PEER_APPLICATION = 3
    IDLE_TIMEOUT = 4
    STATELESS_RESET = 5
    VERSION_NEGOTIATION = 6


@dataclasses.dataclass(frozen=True)
class QUICEvent:
    """What happened on a connection: the kind, the stream and error where they apply, the kind of
    stream of ``STREAMS_AVAILABLE``, the reason of ``CLOSED``, and the token or reason phrase."""

    kind: QUICEventKind
    stream: int = 0
    error: int = 0
    bidirectional: bool = False
    reason: QUICCloseReason | None = None
    data: bytes = b""


@dataclasses.dataclass
class QUICLimits:
    """The limits and flags of a :class:`QUICConfig`; durations in milliseconds."""

    FIELDS: ClassVar[tuple[str, ...]] = (
        "connection_id_length", "max_idle_timeout", "max_udp_payload_size", "datagram_size", "initial_max_data",
        "initial_max_stream_data_bidi_local", "initial_max_stream_data_bidi_remote", "initial_max_stream_data_uni",
        "initial_max_streams_bidi", "initial_max_streams_uni", "ack_delay_exponent", "max_ack_delay",
        "active_connection_id_limit", "initial_rtt", "max_datagram_frame_size", "disable_active_migration", "pacing",
        "grease_quic_bit", "spin_bit", "grease_transport_parameters", "maximum_crypto_buffer", "maximum_send_buffer",
        "maximum_datagrams",
    )  # fmt: skip

    connection_id_length: int = 8
    max_idle_timeout: int = 30_000
    max_udp_payload_size: int = 65_527
    datagram_size: int = 1200
    initial_max_data: int = 1 << 20
    initial_max_stream_data_bidi_local: int = 1 << 18
    initial_max_stream_data_bidi_remote: int = 1 << 18
    initial_max_stream_data_uni: int = 1 << 18
    initial_max_streams_bidi: int = 100
    initial_max_streams_uni: int = 100
    ack_delay_exponent: int = 3
    max_ack_delay: int = 25
    active_connection_id_limit: int = 4
    initial_rtt: int = 333
    max_datagram_frame_size: int = 0
    disable_active_migration: bool = False
    pacing: bool = True
    grease_quic_bit: bool = True
    spin_bit: bool = True
    grease_transport_parameters: bool = True
    maximum_crypto_buffer: int = 1 << 16
    maximum_send_buffer: int = 1 << 20
    maximum_datagrams: int = 64


@dataclasses.dataclass(frozen=True)
class QUICSession:
    """Where a connection stands."""

    state: QUICConnectionState
    version: QUICVersion
    handshake_complete: bool
    handshake_confirmed: bool
    zero_rtt_rejected: bool


class QUICConfig(Handle):
    """The configuration of QUIC connections: versions, limits and flags."""

    FREE = f"{P}_quic_config_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create(f"{P}_quic_config_new"))

    def set_versions(self, versions: list[int]) -> None:
        array = Words.array(ctypes.c_uint32, [int(version) for version in versions], len(versions)) if versions else None
        self.library.call(f"{P}_quic_config_set_versions", self.handle, array, len(versions))

    def set_reset_key(self, key: bytes | None) -> None:
        """The 32-byte key of stateless reset tokens (RFC 9000 §10.3.2), or none."""
        if key is not None and len(key) != 32:
            raise ValueError("a reset key is 32 bytes")
        self.library.call(f"{P}_quic_config_set_reset_key", self.handle, key)

    @property
    def limits(self) -> QUICLimits:
        structure = Library.default().type(f"{P}_QUICLimits")()
        self.library.call(f"{P}_quic_config_limits", self.handle, ctypes.byref(structure))
        return QUICLimits(**{field: getattr(structure, field) for field in QUICLimits.FIELDS})

    @limits.setter
    def limits(self, limits: QUICLimits) -> None:
        structure = Library.default().type(f"{P}_QUICLimits")()
        for field in QUICLimits.FIELDS:
            Fields.assign(structure, field, getattr(limits, field))
        self.library.call(f"{P}_quic_config_set_limits", self.handle, ctypes.byref(structure))


class QUICEndpoint(Handle):
    """A QUIC endpoint without I/O (RFC 9000 §5.2): the connections of one socket."""

    FREE = f"{P}_quic_endpoint_free"

    def __init__(
        self,
        config: QUICConfig,
        tls: TLSServerConfig | None = None,
        token_key: bytes | None = None,
        retry: bool = False,
        seed: bytes | None = None,
    ) -> None:
        """An endpoint that accepts connections with ``tls`` (only connects without it); with the
        32-byte ``token_key`` it validates addresses, with a Retry first if ``retry`` (RFC 9000 §8.1)."""
        if token_key is not None and len(token_key) != 32:
            raise ValueError("a token key is 32 bytes")
        super().__init__(
            Handle.create(f"{P}_quic_endpoint_new", config, tls, token_key, retry, *Bytes.readable(seed or os.urandom(48)))
        )

    def connect(
        self,
        tls: TLSClientConfig,
        server_name: str | None,
        remote: IPEndpoint,
        now: int,
        time: int,
        token: bytes | None = None,
        seed: bytes | None = None,
    ) -> QUICConnection:
        """Opens a connection to ``remote`` as ``server_name``, with a NEW_TOKEN ``token`` of the server if any."""
        handle = ctypes.c_uint64()
        self.library.call(
            f"{P}_quic_endpoint_connect", self.handle, tls, *Text.encode(server_name or ""), ctypes.byref(remote.to_structure()),
            *Bytes.readable(token or b""), *Bytes.readable(seed or os.urandom(48)), now, time, ctypes.byref(handle),
        )  # fmt: skip
        return QUICConnection(self, handle.value)

    def receive(self, datagram: bytes, remote: IPEndpoint, now: int, time: int, ecn: QUICECN = QUICECN.NOT_ECT) -> QUICConnection | None:
        """Takes a datagram from ``remote``; the connection that took it, if any."""
        found, handle = ctypes.c_bool(), ctypes.c_uint64()
        self.library.call(
            f"{P}_quic_endpoint_receive", self.handle, *Bytes.readable(datagram), ctypes.byref(remote.to_structure()), int(ecn), now,
            time, ctypes.byref(found), ctypes.byref(handle),
        )  # fmt: skip
        return QUICConnection(self, handle.value) if found.value else None

    def transmit(self, now: int) -> tuple[IPEndpoint, bytes] | None:
        """The next datagram to send and its destination, or ``None``."""
        found = ctypes.c_bool()
        destination = Library.default().type("umilib_protocol_ip_IPEndpoint")()
        buffer = Buffer()
        self.library.call(f"{P}_quic_endpoint_transmit", self.handle, now, ctypes.byref(found), ctypes.byref(destination), ctypes.byref(buffer))
        data = self.library.take(buffer)
        return (IPEndpoint.from_structure(destination), data) if found.value else None

    def poll_timeout(self) -> int | None:
        """When :meth:`expire` is next due, in nanoseconds."""
        return self.library.optional(f"{P}_quic_endpoint_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int, time: int) -> None:
        self.library.call(f"{P}_quic_endpoint_expire", self.handle, now, time)

    def accept(self) -> QUICConnection | None:
        """The next connection accepted."""
        handle = self.library.optional(f"{P}_quic_endpoint_accept", ctypes.c_uint64, self.handle)
        return None if handle is None else QUICConnection(self, handle)


class QUICConnection:
    """A connection of a :class:`QUICEndpoint`, named by its number."""

    def __init__(self, endpoint: QUICEndpoint, handle: int) -> None:
        self.endpoint = endpoint
        self.handle = handle

    def call(self, name: str, *arguments: Any) -> None:
        self.endpoint.library.call(f"{P}_quic_connection_{name}", self.endpoint.handle, self.handle, *arguments)

    @property
    def session(self) -> QUICSession:
        structure = Library.default().type(f"{P}_QUICSession")()
        self.call("session", ctypes.byref(structure))
        return QUICSession(
            state=QUICConnectionState(structure.state),
            version=QUICVersion(structure.version),
            handshake_complete=structure.handshake_complete,
            handshake_confirmed=structure.handshake_confirmed,
            zero_rtt_rejected=structure.zero_rtt_rejected,
        )

    @property
    def protocol(self) -> bytes:
        buffer = Buffer()
        self.call("protocol", ctypes.byref(buffer))
        return self.endpoint.library.take(buffer)

    def poll_event(self) -> QUICEvent | None:
        found = ctypes.c_bool()
        structure = Library.default().type(f"{P}_QUICEvent")()
        buffer = Buffer()
        self.call("poll_event", ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        data = self.endpoint.library.take(buffer)
        if not found.value:
            return None
        kind = QUICEventKind(structure.kind)
        reason = QUICCloseReason(structure.reason) if kind == QUICEventKind.CLOSED else None
        return QUICEvent(kind, structure.stream, structure.error, structure.bidirectional, reason, data)

    def open_stream(self, bidirectional: bool) -> int:
        stream = ctypes.c_uint64()
        self.call("open_stream", bidirectional, ctypes.byref(stream))
        return stream.value

    def stream_send(self, stream: int, data: bytes, fin: bool = False) -> int:
        """Writes ``data`` to the stream, as much as it takes; ends it after all of it if ``fin``."""
        count = ctypes.c_size_t()
        self.call("stream_send", stream, *Bytes.readable(data), fin, ctypes.byref(count))
        return count.value

    def stream_read(self, stream: int, size: int) -> tuple[bytes, bool]:
        """Up to ``size`` bytes of the stream, and whether it ended."""
        out = (ctypes.c_uint8 * max(size, 1))()
        count, fin = ctypes.c_size_t(), ctypes.c_bool()
        self.call("stream_read", stream, out, size, ctypes.byref(count), ctypes.byref(fin))
        return bytes(out[: count.value]), fin.value

    def stream_reset(self, stream: int, error: int) -> None:
        self.call("stream_reset", stream, error)

    def stream_stop(self, stream: int, error: int) -> None:
        self.call("stream_stop", stream, error)

    def send_datagram(self, data: bytes) -> None:
        self.call("send_datagram", *Bytes.readable(data))

    def read_datagram(self) -> bytes | None:
        found = ctypes.c_bool()
        buffer = Buffer()
        self.call("read_datagram", ctypes.byref(found), ctypes.byref(buffer))
        data = self.endpoint.library.take(buffer)
        return data if found.value else None

    def close(self, error: int, reason: bytes, now: int) -> None:
        """Closes with the application's ``error`` (RFC 9000 §10.2)."""
        self.call("close", error, *Bytes.readable(reason), now)

    def update_keys(self, now: int) -> None:
        self.call("update_keys", now)

    def ping(self) -> None:
        self.call("ping")

    def migrate(self, now: int) -> None:
        """Moves to a new local address; the next datagrams come from it (RFC 9000 §9.2)."""
        self.call("migrate", now)
