"""The Transmission Control Protocol (RFC 9293) over IPv4 and IPv6: segments and their options (RFC 9293
§3.1, RFC 7323, RFC 2018), initial sequence numbers (RFC 6528), the retransmission timer (RFC 6298),
congestion control (RFC 5681, RFC 9438), the connection without I/O and its state machine (RFC 9293
§3.10, with RFC 5961, RFC 6582, RFC 6675 and RFC 3168), the listener of passive opens, and the rule that
routes connections. Mirrors ``umilib::protocol::tcp``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`.
Errors are :class:`TCPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from collections.abc import Iterator
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds
from umilib.protocol.ip import IPAddress, IPEndpoint, IPEndpointPattern


class TCPError(FFIError):
    """An error of TCP: ``Length``, ``Checksum``, ``Option``, ``Family``, ``Address``, ``State`` or ``Config``."""


Library.register_error("protocol.tcp", TCPError)


class TCPSequence(int):
    """A sequence number (RFC 9293 §3.4): 32 bits, compared modulo 2^32. It has no order of its own."""

    def __new__(cls, value: int) -> TCPSequence:
        return super().__new__(cls, value & 0xFFFFFFFF)

    def add(self, count: int) -> TCPSequence:
        return TCPSequence(int(self) + count)

    def sub(self, count: int) -> TCPSequence:
        return TCPSequence(int(self) - count)

    def distance(self, earlier: int) -> int:
        """How far this number is after ``earlier``, modulo 2^32."""
        return Library.default().function("umilib_protocol_tcp_tcp_sequence_distance")(int(self), int(earlier))

    def is_before(self, other: int) -> bool:
        return bool(Library.default().function("umilib_protocol_tcp_tcp_sequence_is_before")(int(self), int(other)))

    def is_after(self, other: int) -> bool:
        return TCPSequence(other).is_before(self)

    def is_at_or_before(self, other: int) -> bool:
        return not self.is_after(other)

    def is_at_or_after(self, other: int) -> bool:
        return not self.is_before(other)

    def is_in(self, start: int, end: int) -> bool:
        """Whether this number is in ``[start, end)``."""
        return self.is_at_or_after(start) and self.is_before(end)

    def __repr__(self) -> str:
        return f"TCPSequence({int(self)})"


class TCPFlags(int):
    """The control bits of a segment (RFC 9293 §3.1, RFC 3168 §6.1)."""

    NONE: ClassVar[TCPFlags]
    FIN: ClassVar[TCPFlags]
    SYN: ClassVar[TCPFlags]
    RST: ClassVar[TCPFlags]
    PSH: ClassVar[TCPFlags]
    ACK: ClassVar[TCPFlags]
    URG: ClassVar[TCPFlags]
    ECE: ClassVar[TCPFlags]
    CWR: ClassVar[TCPFlags]

    def __new__(cls, value: int) -> TCPFlags:
        if not 0 <= value <= 0xFF:
            raise ValueError("the flags are 8 bits")
        return super().__new__(cls, value)

    def contains(self, other: int) -> bool:
        return int(self) & int(other) == int(other)

    def intersects(self, other: int) -> bool:
        return int(self) & int(other) != 0

    def union(self, other: int) -> TCPFlags:
        return TCPFlags(int(self) | int(other))

    def difference(self, other: int) -> TCPFlags:
        return TCPFlags(int(self) & ~int(other) & 0xFF)

    def __repr__(self) -> str:
        return f"TCPFlags({int(self):#04x})"


for _name, _value in [("NONE", 0), ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80)]:
    setattr(TCPFlags, _name, TCPFlags(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class TCPHeader:
    """The fixed 20 bytes of a TCP header (RFC 9293 §3.1), its fields as they are: nothing is checked
    but its length. :class:`TCPSegment` reads and writes a segment with its rules."""

    LENGTH: ClassVar[int] = 20
    FIELDS: ClassVar[tuple[str, ...]] = (
        "source_port", "destination_port", "sequence", "acknowledgment", "data_offset", "reserved", "flags", "window",
        "checksum", "urgent_pointer",
    )  # fmt: skip

    source_port: int
    destination_port: int
    sequence: int
    acknowledgment: int
    data_offset: int
    reserved: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> TCPHeader:
        """The header at the start of ``data``; raises ``Length`` if it has fewer than 20 bytes."""
        structure = Library.default().type("umilib_protocol_tcp_TCPHeader")()
        Library.default().call("umilib_protocol_tcp_tcp_header_decode", *Bytes.readable(data), ctypes.byref(structure))
        values = {name: getattr(structure, name) for name in TCPHeader.FIELDS}
        values["sequence"], values["acknowledgment"] = TCPSequence(values["sequence"]), TCPSequence(values["acknowledgment"])
        values["flags"] = TCPFlags(values["flags"])
        return cls(**values)

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_tcp_TCPHeader")()
        for name in TCPHeader.FIELDS:
            Fields.assign(structure, name, int(getattr(self, name)))
        return structure

    def to_bytes(self) -> bytes:
        return Library.default().output("umilib_protocol_tcp_tcp_header_encode", self.to_structure())

    def encode(self) -> bytes:
        return self.to_bytes()


class TCPOptionKind(int):
    """The kind of a TCP option (the IANA registry "TCP Option Kind Numbers")."""

    END: ClassVar[TCPOptionKind]
    NOP: ClassVar[TCPOptionKind]
    MSS: ClassVar[TCPOptionKind]
    WINDOW_SCALE: ClassVar[TCPOptionKind]
    SACK_PERMITTED: ClassVar[TCPOptionKind]
    SACK: ClassVar[TCPOptionKind]
    TIMESTAMPS: ClassVar[TCPOptionKind]
    FAST_OPEN: ClassVar[TCPOptionKind]

    def __new__(cls, value: int) -> TCPOptionKind:
        if not 0 <= value <= 0xFF:
            raise ValueError("a kind is 0 to 255")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"TCPOptionKind({int(self)})"


for _name, _value in [("END", 0), ("NOP", 1), ("MSS", 2), ("WINDOW_SCALE", 3), ("SACK_PERMITTED", 4), ("SACK", 5), ("TIMESTAMPS", 8), ("FAST_OPEN", 34)]:
    setattr(TCPOptionKind, _name, TCPOptionKind(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class TCPOption:
    """One option: its kind and the bytes after its kind and length octets."""

    kind: TCPOptionKind
    data: bytes

    @staticmethod
    def encode(kind: int, data: bytes = b"") -> bytes:
        """The bytes of an option of ``kind`` with ``data``; raises ``Option`` for data that does not fit."""
        return Library.default().output("umilib_protocol_tcp_tcp_option_encode", int(kind), *Bytes.readable(data))


class TCPOptions:
    """The options of a segment, in order, No-Operation included; an illegal length raises ``Option``."""

    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)

    def __iter__(self) -> Iterator[TCPOption]:
        library = Library.default()
        index = 0
        while True:
            found, kind, data = ctypes.c_bool(), ctypes.c_uint8(), Buffer()
            library.call("umilib_protocol_tcp_tcp_options_get", self.data, len(self.data), index, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(data))
            value = library.take(data)
            if not found.value:
                return
            yield TCPOption(TCPOptionKind(kind.value), value)
            index += 1

    @staticmethod
    def check(data: bytes) -> None:
        for _ in TCPOptions(data):
            pass


@dataclasses.dataclass(frozen=True)
class TCPSACKBlock:
    """A block of a SACK option (RFC 2018 §3): the data from ``left`` up to ``right`` was received."""

    left: int
    right: int


@dataclasses.dataclass(frozen=True)
class TCPTimestamps:
    """The values of a Timestamps option (RFC 7323 §3.2): TSval and TSecr."""

    value: int
    echo_reply: int


@dataclasses.dataclass(frozen=True)
class TCPOptionSet:
    """The options this crate understands: Maximum Segment Size, Window Scale, SACK-Permitted, SACK
    and Timestamps."""

    MAXIMUM_WINDOW_SCALE: ClassVar[int] = 14
    MAXIMUM_SACK_BLOCKS: ClassVar[int] = 4
    MAXIMUM_LENGTH: ClassVar[int] = 40

    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool = False
    timestamps: TCPTimestamps | None = None
    sack_blocks: tuple[TCPSACKBlock, ...] = ()

    @classmethod
    def decode(cls, data: bytes) -> TCPOptionSet:
        """The options of ``data``; raises ``Option`` for an illegal length."""
        structure = Library.default().type("umilib_protocol_tcp_TCPOptionSet")()
        Library.default().call("umilib_protocol_tcp_tcp_option_set_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> TCPOptionSet:
        blocks = tuple(TCPSACKBlock(TCPSequence(block.left), TCPSequence(block.right)) for block in list(structure.sack_blocks)[: structure.sack_count])
        return cls(
            structure.mss if structure.has_mss else None,
            structure.window_scale if structure.has_window_scale else None,
            bool(structure.sack_permitted),
            TCPTimestamps(structure.timestamps.value, structure.timestamps.echo_reply) if structure.has_timestamps else None,
            blocks,
        )

    def to_structure(self) -> Any:
        library = Library.default()
        structure = library.type("umilib_protocol_tcp_TCPOptionSet")()
        structure.has_mss = self.mss is not None
        Fields.assign(structure, "mss", self.mss or 0)
        structure.has_window_scale = self.window_scale is not None
        Fields.assign(structure, "window_scale", self.window_scale or 0)
        structure.sack_permitted = self.sack_permitted
        structure.has_timestamps = self.timestamps is not None
        if self.timestamps is not None:
            structure.timestamps = library.type("umilib_protocol_tcp_TCPTimestamps")(self.timestamps.value, self.timestamps.echo_reply)
        blocks = self.sack()
        for index, block in enumerate(blocks):
            structure.sack_blocks[index] = library.type("umilib_protocol_tcp_TCPSACKBlock")(int(block.left), int(block.right))
        structure.sack_count = len(blocks)
        return structure

    def sack(self) -> tuple[TCPSACKBlock, ...]:
        return self.sack_blocks[: TCPOptionSet.MAXIMUM_SACK_BLOCKS]

    def with_sack(self, blocks: tuple[TCPSACKBlock, ...] | list[TCPSACKBlock]) -> TCPOptionSet:
        return dataclasses.replace(self, sack_blocks=tuple(blocks)[: TCPOptionSet.MAXIMUM_SACK_BLOCKS])

    def encode(self) -> bytes:
        """The options as Linux lays them out; raises ``Option`` if they do not fit 40 bytes."""
        return Library.default().output("umilib_protocol_tcp_tcp_option_set_encode", ctypes.byref(self.to_structure()))

    def length(self) -> int:
        """The bytes :meth:`encode` writes, which may be more than the 40 the header holds."""
        sack = self.sack()
        return (
            (4 if self.mss is not None else 0) + (12 if self.timestamps is not None else 0)
            + (4 if self.sack_permitted and self.timestamps is None else 0) + (4 if self.window_scale is not None else 0)
            + (4 + 8 * len(sack) if sack else 0)
        )  # fmt: skip


@dataclasses.dataclass(frozen=True)
class TCPSegment:
    """A TCP segment (RFC 9293 §3.1): its fields, its options as bytes and its data. The data offset and
    the checksum are checked when read and computed when written, over the pseudo-header of the
    addresses that carry the segment."""

    FIELDS: ClassVar[tuple[str, ...]] = ("source_port", "destination_port", "sequence", "acknowledgment", "flags", "window", "urgent_pointer")

    source_port: int = 0
    destination_port: int = 0
    sequence: int = 0
    acknowledgment: int = 0
    flags: int = 0
    window: int = 0
    urgent_pointer: int = 0
    options: bytes = b""
    payload: bytes = b""

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_tcp_TCPSegment")()
        for name in TCPSegment.FIELDS:
            Fields.assign(structure, name, int(getattr(self, name)))
        return structure

    @classmethod
    def from_structure(cls, structure: Any, options: bytes = b"", payload: bytes = b"") -> TCPSegment:
        return cls(
            structure.source_port, structure.destination_port, TCPSequence(structure.sequence), TCPSequence(structure.acknowledgment),
            TCPFlags(structure.flags), structure.window, structure.urgent_pointer, options, payload,
        )  # fmt: skip

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview, source: IPAddress, destination: IPAddress) -> TCPSegment:
        """The segment of ``data``, carried from ``source`` to ``destination``; raises ``Length``,
        ``Checksum``, ``Option`` or ``Family``."""
        data = bytes(data)
        structure = Library.default().type("umilib_protocol_tcp_TCPSegment")()
        offsets = [ctypes.c_size_t() for _ in range(4)]
        Library.default().call(
            "umilib_protocol_tcp_tcp_segment_decode", data, len(data), source.octets, source.LENGTH, destination.octets, destination.LENGTH,
            ctypes.byref(structure), *[ctypes.byref(offset) for offset in offsets],
        )  # fmt: skip
        options_offset, options_length, payload_offset, payload_length = (offset.value for offset in offsets)
        return cls.from_structure(structure, data[options_offset : options_offset + options_length], data[payload_offset : payload_offset + payload_length])

    def encode(self, source: IPAddress, destination: IPAddress) -> bytes:
        return Library.default().output(
            "umilib_protocol_tcp_tcp_segment_encode", ctypes.byref(self.to_structure()), *Bytes.readable(self.options), *Bytes.readable(self.payload),
            source.octets, source.LENGTH, destination.octets, destination.LENGTH,
        )  # fmt: skip

    def option_set(self) -> TCPOptionSet:
        return TCPOptionSet.decode(self.options)

    def length(self) -> int:
        return 20 + -(-len(self.options) // 4) * 4 + len(self.payload)

    def sequence_length(self) -> int:
        """SEG.LEN (RFC 9293 §3.4): the data, and one for each of SYN and FIN."""
        flags = TCPFlags(int(self.flags))
        return len(self.payload) + flags.contains(TCPFlags.SYN) + flags.contains(TCPFlags.FIN)

    @classmethod
    def reset(cls, source_port: int, destination_port: int, sequence: int, acknowledgment: int | None = None) -> TCPSegment:
        """A reset of ``sequence``, acknowledging ``acknowledgment`` if given."""
        flags = TCPFlags.RST.union(TCPFlags.ACK) if acknowledgment is not None else TCPFlags.RST
        return cls(source_port, destination_port, TCPSequence(sequence), TCPSequence(acknowledgment or 0), flags)

    def reset_reply(self) -> TCPSegment | None:
        """The reset that answers this segment when no connection exists (RFC 9293 §3.10.7.1)."""
        found, structure = ctypes.c_bool(), Library.default().type("umilib_protocol_tcp_TCPSegment")()
        Library.default().call(
            "umilib_protocol_tcp_tcp_segment_reset_reply", ctypes.byref(self.to_structure()), *Bytes.readable(self.options), *Bytes.readable(self.payload),
            ctypes.byref(found), ctypes.byref(structure),
        )  # fmt: skip
        return TCPSegment.from_structure(structure) if found.value else None


class TCPISNGenerator(Handle):
    """The generator of initial sequence numbers of RFC 6528 under a secret key of 16 bytes."""

    FREE = "umilib_protocol_tcp_tcp_isn_generator_free"
    TICK: ClassVar[datetime.timedelta] = datetime.timedelta(microseconds=4)

    def __init__(self, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("the key has 16 bytes")
        super().__init__(Handle.create("umilib_protocol_tcp_tcp_isn_generator_new", bytes(key)))

    def generate(self, local: IPEndpoint, remote: IPEndpoint, now: int) -> TCPSequence:
        out = ctypes.c_uint32()
        self.library.call("umilib_protocol_tcp_tcp_isn_generator_generate", self.handle, ctypes.byref(local.to_structure()), ctypes.byref(remote.to_structure()), now, ctypes.byref(out))
        return TCPSequence(out.value)


class TCPRetransmissionTimer:
    """The retransmission timer of RFC 6298: SRTT, RTTVAR, the RTO and its backoff."""

    SYN_LOSS_TIMEOUT: ClassVar[datetime.timedelta] = datetime.timedelta(seconds=3)

    def __init__(self, initial: datetime.timedelta, minimum: datetime.timedelta, maximum: datetime.timedelta, granularity: datetime.timedelta) -> None:
        self.structure = Library.default().type("umilib_protocol_tcp_TCPRetransmissionTimer")()
        Library.default().call(
            "umilib_protocol_tcp_tcp_retransmission_timer_new", *(Nanoseconds.from_timedelta(value) for value in (initial, minimum, maximum, granularity)),
            ctypes.byref(self.structure),
        )  # fmt: skip

    @property
    def smoothed(self) -> datetime.timedelta | None:
        return Nanoseconds.to_timedelta(self.structure.smoothed) if self.structure.has_smoothed else None

    @property
    def variation(self) -> datetime.timedelta:
        return Nanoseconds.to_timedelta(self.structure.variation)

    @property
    def backoff(self) -> int:
        return self.structure.backoff

    def sample(self, rtt: datetime.timedelta) -> None:
        Library.default().call("umilib_protocol_tcp_tcp_retransmission_timer_sample", ctypes.byref(self.structure), Nanoseconds.from_timedelta(rtt))

    def expire(self) -> None:
        Library.default().call("umilib_protocol_tcp_tcp_retransmission_timer_expire", ctypes.byref(self.structure))

    def restore_after_syn_loss(self) -> None:
        Library.default().call("umilib_protocol_tcp_tcp_retransmission_timer_restore_after_syn_loss", ctypes.byref(self.structure))

    def current(self) -> datetime.timedelta:
        return Nanoseconds.to_timedelta(Library.default().function("umilib_protocol_tcp_tcp_retransmission_timer_current")(self.structure))


class TCPCongestionKind(enum.IntEnum):
    NEW_RENO = 0
    CUBIC = 1


class TCPCongestion(Handle):
    """A congestion control (RFC 5681, RFC 9438): cwnd and ssthresh in bytes."""

    FREE = "umilib_protocol_tcp_tcp_congestion_free"

    def __init__(self, kind: TCPCongestionKind, window: int) -> None:
        super().__init__(Handle.create("umilib_protocol_tcp_tcp_congestion_new", int(kind), window))

    @staticmethod
    def initial_window(mss: int) -> int:
        """The initial window of RFC 5681 §3.1 for ``mss``."""
        return Library.default().function("umilib_protocol_tcp_tcp_congestion_initial_window")(mss)

    def windows(self) -> tuple[int, int]:
        window, threshold = ctypes.c_uint32(), ctypes.c_uint32()
        self.library.call("umilib_protocol_tcp_tcp_congestion_window", self.handle, ctypes.byref(window), ctypes.byref(threshold))
        return window.value, threshold.value

    def window(self) -> int:
        return self.windows()[0]

    def threshold(self) -> int:
        return self.windows()[1]

    def set_window(self, window: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_congestion_set_window", self.handle, window)

    def acknowledge(self, acknowledged: int, mss: int, rtt: datetime.timedelta, limited: bool, now: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_congestion_acknowledge", self.handle, acknowledged, mss, Nanoseconds.from_timedelta(rtt), limited, now)

    def congestion(self, in_flight: int, mss: int, ecn: bool, now: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_congestion_congestion", self.handle, in_flight, mss, ecn, now)

    def timeout(self, in_flight: int, mss: int, now: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_congestion_timeout", self.handle, in_flight, mss, now)

    def restart(self, restart: int, now: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_congestion_restart", self.handle, restart, now)


class TCPECNMode(enum.IntEnum):
    """Whether a connection uses ECN (RFC 3168)."""

    OFF = 0
    ACCEPT = 1
    REQUEST = 2


@dataclasses.dataclass(frozen=True)
class TCPConfig:
    """The parameters of a connection; the defaults follow RFC 9293 and the RFCs it relies on."""

    DURATIONS: ClassVar[tuple[str, ...]] = (
        "delayed_ack", "initial_rto", "minimum_rto", "maximum_rto", "clock_granularity", "user_timeout", "connect_timeout",
        "keepalive_idle", "keepalive_interval", "time_wait",
    )  # fmt: skip
    INTEGERS: ClassVar[tuple[str, ...]] = ("mtu", "send_buffer", "receive_buffer", "retries", "keepalive_probes", "challenge_acks")
    BOOLEANS: ClassVar[tuple[str, ...]] = ("window_scale", "timestamps", "sack", "nagle", "keepalive", "hard_error_abort")

    mtu: int = 1500
    send_buffer: int = 256 * 1024
    receive_buffer: int = 256 * 1024
    window_scale: bool = True
    timestamps: bool = True
    sack: bool = True
    ecn: TCPECNMode = TCPECNMode.ACCEPT
    nagle: bool = True
    delayed_ack: datetime.timedelta = datetime.timedelta(milliseconds=40)
    initial_rto: datetime.timedelta = datetime.timedelta(seconds=1)
    minimum_rto: datetime.timedelta = datetime.timedelta(seconds=1)
    maximum_rto: datetime.timedelta = datetime.timedelta(seconds=60)
    clock_granularity: datetime.timedelta = datetime.timedelta(milliseconds=1)
    congestion: TCPCongestionKind = TCPCongestionKind.CUBIC
    initial_window: int | None = None
    retries: int = 3
    user_timeout: datetime.timedelta = datetime.timedelta(seconds=100)
    connect_timeout: datetime.timedelta = datetime.timedelta(seconds=180)
    keepalive: bool = False
    keepalive_idle: datetime.timedelta = datetime.timedelta(hours=2)
    keepalive_interval: datetime.timedelta = datetime.timedelta(seconds=75)
    keepalive_probes: int = 9
    time_wait: datetime.timedelta = datetime.timedelta(seconds=240)
    challenge_acks: int = 1000
    hard_error_abort: bool = False

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_tcp_TCPConfig")()
        for name in TCPConfig.INTEGERS:
            Fields.assign(structure, name, getattr(self, name))
        for name in TCPConfig.BOOLEANS:
            setattr(structure, name, bool(getattr(self, name)))
        for name in TCPConfig.DURATIONS:
            Fields.assign(structure, name, Nanoseconds.from_timedelta(getattr(self, name)))
        structure.ecn, structure.congestion = int(self.ecn), int(self.congestion)
        structure.has_initial_window = self.initial_window is not None
        Fields.assign(structure, "initial_window", self.initial_window or 0)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> TCPConfig:
        values: dict[str, Any] = {name: getattr(structure, name) for name in TCPConfig.INTEGERS}
        values |= {name: bool(getattr(structure, name)) for name in TCPConfig.BOOLEANS}
        values |= {name: Nanoseconds.to_timedelta(getattr(structure, name)) for name in TCPConfig.DURATIONS}
        values["ecn"], values["congestion"] = TCPECNMode(structure.ecn), TCPCongestionKind(structure.congestion)
        values["initial_window"] = structure.initial_window if structure.has_initial_window else None
        return cls(**values)

    @classmethod
    def default(cls) -> TCPConfig:
        """The defaults as the library has them."""
        structure = Library.default().type("umilib_protocol_tcp_TCPConfig")()
        Library.default().call("umilib_protocol_tcp_tcp_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)


class TCPState(enum.IntEnum):
    """The state of a connection (RFC 9293 §3.3.2)."""

    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10

    def is_synchronized(self) -> bool:
        return self not in (TCPState.CLOSED, TCPState.LISTEN, TCPState.SYN_SENT, TCPState.SYN_RECEIVED)

    def can_send(self) -> bool:
        return self in (TCPState.SYN_SENT, TCPState.SYN_RECEIVED, TCPState.ESTABLISHED, TCPState.CLOSE_WAIT)

    def can_receive(self) -> bool:
        return self in (TCPState.SYN_RECEIVED, TCPState.ESTABLISHED, TCPState.FIN_WAIT_1, TCPState.FIN_WAIT_2)


class TCPCloseReason(enum.IntEnum):
    """Why a connection closed (RFC 9293 MUST-12)."""

    NORMAL = 0
    RESET = 1
    REFUSED = 2
    TIMEOUT = 3
    ABORTED = 4
    UNREACHABLE = 5


@dataclasses.dataclass(frozen=True)
class TCPEvent:
    """What happened to a connection: ``name`` is that of the Rust variant, and ``reason`` that of ``Closed``."""

    NAMES: ClassVar[tuple[str, ...]] = ("Connected", "Readable", "Writable", "Urgent", "PeerClosed", "Trouble", "Closed")
    CONNECTED: ClassVar[TCPEvent]
    READABLE: ClassVar[TCPEvent]
    WRITABLE: ClassVar[TCPEvent]
    URGENT: ClassVar[TCPEvent]
    PEER_CLOSED: ClassVar[TCPEvent]
    TROUBLE: ClassVar[TCPEvent]

    name: str
    reason: TCPCloseReason | None = None

    @classmethod
    def closed(cls, reason: TCPCloseReason) -> TCPEvent:
        return cls("Closed", reason)


for _attribute, _event in zip(("CONNECTED", "READABLE", "WRITABLE", "URGENT", "PEER_CLOSED", "TROUBLE"), TCPEvent.NAMES):
    setattr(TCPEvent, _attribute, TCPEvent(_event))
del _attribute, _event


@dataclasses.dataclass(frozen=True)
class TCPICMPError:
    """An ICMP error about a segment a connection sent (RFC 9293 §3.9.2.2): soft, hard, or Packet Too Big with an MTU."""

    SOFT: ClassVar[TCPICMPError]
    HARD: ClassVar[TCPICMPError]

    kind: int
    mtu: int = 0

    @classmethod
    def packet_too_big(cls, mtu: int) -> TCPICMPError:
        return cls(2, mtu)


TCPICMPError.SOFT = TCPICMPError(0)
TCPICMPError.HARD = TCPICMPError(1)


@dataclasses.dataclass(frozen=True)
class TCPTransmission:
    """What a transmission wrote: its length, and whether its IP header is to carry ECT(0)."""

    length: int
    ect: bool


@dataclasses.dataclass(frozen=True)
class TCPConnectionInfo:
    """What a connection's state machine holds that an application may read."""

    state: TCPState
    passive: bool
    iss: TCPSequence
    send_unacknowledged: TCPSequence
    send_next: TCPSequence
    send_maximum: TCPSequence
    send_window: int
    maximum_send_window: int
    irs: TCPSequence
    receive_next: TCPSequence
    peer_mss: int
    mtu: int
    window_scaling: bool
    send_scale: int
    receive_scale: int
    sack: bool
    timestamps: bool
    ecn: bool
    congestion_window: int
    congestion_threshold: int
    in_recovery: bool
    smoothed_rtt: datetime.timedelta | None


class TCPConnection(Handle):
    """A TCP connection (RFC 9293) without I/O: give it the segments that arrive and the time, and
    call :meth:`transmit` until it returns ``None`` after each input and at :meth:`poll_timeout`."""

    FREE = "umilib_protocol_tcp_tcp_connection_free"

    @classmethod
    def connect(cls, config: TCPConfig, local: IPEndpoint, remote: IPEndpoint, iss: int, now: int) -> TCPConnection:
        """An active open; raises ``Address`` for a remote address that names no single host (MUST-46)."""
        return cls(Handle.create(
            "umilib_protocol_tcp_tcp_connection_connect", ctypes.byref(config.to_structure()), ctypes.byref(local.to_structure()),
            ctypes.byref(remote.to_structure()), int(iss), now,
        ))  # fmt: skip

    @classmethod
    def accept(cls, config: TCPConfig, local: IPEndpoint, remote: IPEndpoint, syn: TCPSegment, iss: int, now: int) -> TCPConnection:
        """A passive open from the SYN ``syn``: the connection is in SYN-RECEIVED."""
        return cls(Handle.create(
            "umilib_protocol_tcp_tcp_connection_accept", ctypes.byref(config.to_structure()), ctypes.byref(local.to_structure()),
            ctypes.byref(remote.to_structure()), ctypes.byref(syn.to_structure()), *Bytes.readable(syn.options),
            *Bytes.readable(syn.payload), int(iss), now,
        ))  # fmt: skip

    def receive(self, segment: TCPSegment, ce: bool, now: int) -> None:
        """Processes a segment that arrived at ``now``; ``ce`` is whether its IP header carried CE."""
        self.library.call(
            "umilib_protocol_tcp_tcp_connection_receive", self.handle, ctypes.byref(segment.to_structure()), *Bytes.readable(segment.options),
            *Bytes.readable(segment.payload), ce, now,
        )  # fmt: skip

    def transmit(self, now: int) -> tuple[bytes, TCPTransmission] | None:
        """The next segment due at ``now``, and what it is."""
        found, data, ect = ctypes.c_bool(), Buffer(), ctypes.c_bool()
        self.library.call("umilib_protocol_tcp_tcp_connection_transmit", self.handle, now, ctypes.byref(found), ctypes.byref(data), ctypes.byref(ect))
        value = self.library.take(data)
        return (value, TCPTransmission(len(value), ect.value)) if found.value else None

    def poll_timeout(self) -> int | None:
        return self.library.optional("umilib_protocol_tcp_tcp_connection_poll_timeout", ctypes.c_uint64, self.handle)

    def poll_event(self) -> TCPEvent | None:
        found, kind, reason = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint8()
        self.library.call("umilib_protocol_tcp_tcp_connection_poll_event", self.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(reason))
        if not found.value:
            return None
        name = TCPEvent.NAMES[kind.value]
        return TCPEvent.closed(TCPCloseReason(reason.value)) if name == "Closed" else TCPEvent(name)

    def send(self, data: bytes) -> int:
        """Takes as much of ``data`` as fits and returns how much; raises ``State`` once closed."""
        return self.library.value("umilib_protocol_tcp_tcp_connection_send", ctypes.c_size_t, self.handle, *Bytes.readable(data), False)

    def send_urgent(self, data: bytes) -> int:
        return self.library.value("umilib_protocol_tcp_tcp_connection_send", ctypes.c_size_t, self.handle, *Bytes.readable(data), True)

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes of what arrived."""
        out = (ctypes.c_uint8 * max(size, 1))()
        count = self.library.value("umilib_protocol_tcp_tcp_connection_read", ctypes.c_size_t, self.handle, out, size)
        return bytes(out[:count])

    def sizes(self) -> tuple[int, int, int]:
        readable, writable, urgent = ctypes.c_size_t(), ctypes.c_size_t(), ctypes.c_uint32()
        self.library.call("umilib_protocol_tcp_tcp_connection_sizes", self.handle, ctypes.byref(readable), ctypes.byref(writable), ctypes.byref(urgent))
        return readable.value, writable.value, urgent.value

    def readable(self) -> int:
        return self.sizes()[0]

    def writable(self) -> int:
        return self.sizes()[1]

    def urgent_remaining(self) -> int:
        """The urgent bytes not yet read (MUST-33)."""
        return self.sizes()[2]

    def close(self) -> None:
        """Closes the sending half: a FIN follows the data. :meth:`free` releases the object."""
        self.library.call("umilib_protocol_tcp_tcp_connection_close", self.handle)

    def abort(self) -> None:
        self.library.call("umilib_protocol_tcp_tcp_connection_abort", self.handle)

    def accepts_syn(self, syn: TCPSegment) -> bool:
        """Whether the SYN ``syn`` may open a new incarnation of this connection in TIME-WAIT (RFC 6191 §2)."""
        return self.library.value(
            "umilib_protocol_tcp_tcp_connection_accepts_syn", ctypes.c_bool, self.handle, ctypes.byref(syn.to_structure()),
            *Bytes.readable(syn.options), *Bytes.readable(syn.payload),
        )  # fmt: skip

    def receive_error(self, error: TCPICMPError, sequence: int, now: int) -> None:
        self.library.call("umilib_protocol_tcp_tcp_connection_receive_error", self.handle, error.kind, error.mtu, int(sequence), now)

    def info(self) -> TCPConnectionInfo:
        structure = self.library.type("umilib_protocol_tcp_TCPConnectionInfo")()
        self.library.call("umilib_protocol_tcp_tcp_connection_info", self.handle, ctypes.byref(structure))
        sequences = ("iss", "send_unacknowledged", "send_next", "send_maximum", "irs", "receive_next")
        values: dict[str, Any] = {name: getattr(structure, name) for name, _ in structure._fields_ if name != "timer"}
        values |= {name: TCPSequence(values[name]) for name in sequences}
        values["state"] = TCPState(structure.state)
        for name in ("passive", "window_scaling", "sack", "timestamps", "ecn", "in_recovery"):
            values[name] = bool(values[name])
        timer = structure.timer
        values["smoothed_rtt"] = Nanoseconds.to_timedelta(timer.smoothed) if timer.has_smoothed else None
        return TCPConnectionInfo(**values)

    @property
    def state(self) -> TCPState:
        return self.info().state

    @property
    def config(self) -> TCPConfig:
        structure = self.library.type("umilib_protocol_tcp_TCPConfig")()
        self.library.call("umilib_protocol_tcp_tcp_connection_config", self.handle, ctypes.byref(structure))
        return TCPConfig.from_structure(structure)

    def set_config(self, config: TCPConfig, now: int) -> None:
        """Changes the parameters, such as Nagle (MUST-17) or keep-alives (MUST-24)."""
        self.library.call("umilib_protocol_tcp_tcp_connection_set_config", self.handle, ctypes.byref(config.to_structure()), now)

    def endpoints(self) -> tuple[IPEndpoint, IPEndpoint]:
        local, remote = self.library.type("umilib_protocol_ip_IPEndpoint")(), self.library.type("umilib_protocol_ip_IPEndpoint")()
        self.library.call("umilib_protocol_tcp_tcp_connection_endpoints", self.handle, ctypes.byref(local), ctypes.byref(remote))
        return IPEndpoint.from_structure(local), IPEndpoint.from_structure(remote)

    @property
    def local(self) -> IPEndpoint:
        return self.endpoints()[0]

    @property
    def remote(self) -> IPEndpoint:
        return self.endpoints()[1]


class TCPListener(Handle):
    """A passive OPEN (RFC 9293 §3.10.1): the connections for the endpoints of ``local``, being set up
    or established, from their SYN until they are accepted; until then the listener gives them their
    segments and timers."""

    FREE = "umilib_protocol_tcp_tcp_listener_free"

    def __init__(self, config: TCPConfig, local: IPEndpointPattern, backlog: int, key: bytes) -> None:
        if len(key) != 16:
            raise ValueError("the key has 16 bytes")
        super().__init__(Handle.create("umilib_protocol_tcp_tcp_listener_new", ctypes.byref(config.to_structure()), ctypes.byref(local.to_structure()), backlog, bytes(key)))

    def matches(self, local: IPEndpoint) -> bool:
        """Whether the local endpoint ``local`` is one of the listener's."""
        return self.library.value("umilib_protocol_tcp_tcp_listener_matches", ctypes.c_bool, self.handle, ctypes.byref(local.to_structure()))

    def receive(self, segment: TCPSegment, local: IPEndpoint, remote: IPEndpoint, ce: bool, now: int) -> None:
        self.library.call(
            "umilib_protocol_tcp_tcp_listener_receive", self.handle, ctypes.byref(segment.to_structure()), *Bytes.readable(segment.options),
            *Bytes.readable(segment.payload), ctypes.byref(local.to_structure()), ctypes.byref(remote.to_structure()), ce, now,
        )  # fmt: skip

    def transmit(self, now: int) -> tuple[IPEndpoint, IPEndpoint, bytes, TCPTransmission] | None:
        """The next segment due at ``now``, with the endpoints it goes from and to."""
        found, ect, data = ctypes.c_bool(), ctypes.c_bool(), Buffer()
        local, remote = self.library.type("umilib_protocol_ip_IPEndpoint")(), self.library.type("umilib_protocol_ip_IPEndpoint")()
        self.library.call(
            "umilib_protocol_tcp_tcp_listener_transmit", self.handle, now, ctypes.byref(found), ctypes.byref(local), ctypes.byref(remote),
            ctypes.byref(data), ctypes.byref(ect),
        )  # fmt: skip
        value = self.library.take(data)
        if not found.value:
            return None
        return IPEndpoint.from_structure(local), IPEndpoint.from_structure(remote), value, TCPTransmission(len(value), ect.value)

    def accept(self) -> TCPConnection | None:
        found, pointer = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call("umilib_protocol_tcp_tcp_listener_accept", self.handle, ctypes.byref(found), ctypes.byref(pointer))
        return TCPConnection(pointer.value) if found.value else None

    def counts(self) -> tuple[int | None, int, int]:
        found, deadline, pending, ready = ctypes.c_bool(), ctypes.c_uint64(), ctypes.c_size_t(), ctypes.c_size_t()
        self.library.call("umilib_protocol_tcp_tcp_listener_poll_timeout", self.handle, ctypes.byref(found), ctypes.byref(deadline), ctypes.byref(pending), ctypes.byref(ready))
        return (deadline.value if found.value else None), pending.value, ready.value

    def poll_timeout(self) -> int | None:
        return self.counts()[0]

    @property
    def pending(self) -> int:
        """The connections being set up."""
        return self.counts()[1]

    @property
    def ready(self) -> int:
        """The connections established and not yet accepted."""
        return self.counts()[2]


@dataclasses.dataclass(frozen=True)
class TCPRule:
    """The rule of a router that routes connections by their local and remote endpoints."""

    local: IPEndpointPattern = IPEndpointPattern.ANY
    remote: IPEndpointPattern = IPEndpointPattern.ANY

    @classmethod
    def new(cls, local: IPEndpointPattern) -> TCPRule:
        return cls(local)

    def with_remote(self, remote: IPEndpointPattern) -> TCPRule:
        return dataclasses.replace(self, remote=remote)

    def matches(self, connection: Any) -> bool:
        """Whether a connection (anything with ``local`` and ``remote`` endpoints) is the rule's."""
        rule = Library.default().type("umilib_protocol_tcp_TCPRule")(self.local.to_structure(), self.remote.to_structure())
        return Library.default().value(
            "umilib_protocol_tcp_tcp_rule_matches", ctypes.c_bool, ctypes.byref(rule), ctypes.byref(connection.local.to_structure()),
            ctypes.byref(connection.remote.to_structure()),
        )  # fmt: skip


__all__ = [
    "TCPCloseReason", "TCPCongestion", "TCPCongestionKind", "TCPConfig", "TCPConnection", "TCPConnectionInfo", "TCPECNMode",
    "TCPError", "TCPEvent", "TCPFlags", "TCPHeader", "TCPICMPError", "TCPISNGenerator", "TCPListener", "TCPOption",
    "TCPOptionKind", "TCPOptionSet", "TCPOptions", "TCPRetransmissionTimer", "TCPRule", "TCPSACKBlock", "TCPSegment",
    "TCPSequence", "TCPState", "TCPTimestamps", "TCPTransmission",
]  # fmt: skip
