"""IPv4 (RFC 791): the header with its options and checksum, the fragmentation of datagrams for an
MTU and their reassembly (RFC 815, RFC 1122 §3.3.2), without I/O. Mirrors ``umilib::protocol::ip::v4``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`.
Errors are :class:`IPv4Error`, and :class:`~umilib.protocol.ip.IPError` for fragments the reassembly
buffer refuses.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
from collections.abc import Iterator
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds
from umilib.protocol.ip import IPProtocol, IPv4Address


class IPv4Error(FFIError):
    """An error of an IPv4 packet: ``Version``, ``Length``, ``Checksum``, ``Option``, ``Fragment``, ``Limit`` or ``Expired``."""


Library.register_error("protocol.ip.v4", IPv4Error)


class IPv4OptionKind(int):
    """The option-type octet of an option (RFC 791 §3.1): copied flag, class and number."""

    END_OF_OPTIONS: ClassVar[IPv4OptionKind]
    NO_OPERATION: ClassVar[IPv4OptionKind]
    RECORD_ROUTE: ClassVar[IPv4OptionKind]
    TIMESTAMP: ClassVar[IPv4OptionKind]
    SECURITY: ClassVar[IPv4OptionKind]
    LOOSE_SOURCE_ROUTE: ClassVar[IPv4OptionKind]
    STREAM_IDENTIFIER: ClassVar[IPv4OptionKind]
    STRICT_SOURCE_ROUTE: ClassVar[IPv4OptionKind]
    ROUTER_ALERT: ClassVar[IPv4OptionKind]

    def __new__(cls, value: int) -> IPv4OptionKind:
        if not 0 <= value <= 255:
            raise ValueError("an option type is 0 to 255")
        return super().__new__(cls, value)

    def is_copied(self) -> bool:
        return bool(Library.default().function("umilib_protocol_ip_v4_ipv4_option_kind_is_copied")(int(self)))

    def class_(self) -> int:
        """The class: 0 for control, 2 for debugging and measurement (``class`` in Rust)."""
        return Library.default().function("umilib_protocol_ip_v4_ipv4_option_kind_class")(int(self))

    def number(self) -> int:
        return Library.default().function("umilib_protocol_ip_v4_ipv4_option_kind_number")(int(self))

    def is_single_octet(self) -> bool:
        return int(self) <= 1

    def __repr__(self) -> str:
        return f"IPv4OptionKind({int(self)})"


for _name, _value in [
    ("END_OF_OPTIONS", 0), ("NO_OPERATION", 1), ("RECORD_ROUTE", 7), ("TIMESTAMP", 68), ("SECURITY", 130),
    ("LOOSE_SOURCE_ROUTE", 131), ("STREAM_IDENTIFIER", 136), ("STRICT_SOURCE_ROUTE", 137), ("ROUTER_ALERT", 148),
]:  # fmt: skip
    setattr(IPv4OptionKind, _name, IPv4OptionKind(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class IPv4Option:
    """One option: its kind and its data."""

    kind: IPv4OptionKind
    data: bytes


class IPv4Options:
    """The options of a header: the bytes after its fixed 20 bytes, at most 40."""

    MAXIMUM_LENGTH = 40

    def __init__(self) -> None:
        self.structure = Library.default().type("umilib_protocol_ip_v4_IPv4Options")()

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> IPv4Options:
        """The options of ``data``; raises ``Option``."""
        options = cls()
        Library.default().call("umilib_protocol_ip_v4_ipv4_options_decode", *Bytes.readable(data), ctypes.byref(options.structure))
        return options

    @classmethod
    def from_structure(cls, structure: Any) -> IPv4Options:
        options = cls()
        ctypes.pointer(options.structure)[0] = structure
        return options

    def as_bytes(self) -> bytes:
        return bytes(self.structure.bytes[: self.structure.length])

    def padded_length(self) -> int:
        return Library.default().function("umilib_protocol_ip_v4_ipv4_options_padded_length")(self.structure)

    def is_empty(self) -> bool:
        return self.structure.length == 0

    def push(self, kind: int, data: bytes = b"") -> None:
        """Appends an option of ``kind`` with ``data``; raises ``Option``."""
        Library.default().call("umilib_protocol_ip_v4_ipv4_options_push", ctypes.byref(self.structure), int(kind), *Bytes.readable(data))

    def copied(self) -> IPv4Options:
        """The options copied into every fragment but the first."""
        return IPv4Options.from_structure(Library.default().function("umilib_protocol_ip_v4_ipv4_options_copied")(self.structure))

    def __iter__(self) -> Iterator[IPv4Option]:
        """The options up to the End of Option List, without No Operation; raises ``Option``."""
        library = Library.default()
        index = 0
        while True:
            found, kind, data = ctypes.c_bool(), ctypes.c_uint8(), Buffer()
            library.call("umilib_protocol_ip_v4_ipv4_options_get", ctypes.byref(self.structure), index, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(data))
            value = library.take(data)
            if not found.value:
                return
            yield IPv4Option(IPv4OptionKind(kind.value), value)
            index += 1

    def iter(self) -> Iterator[IPv4Option]:
        return iter(self)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IPv4Options) and other.as_bytes() == self.as_bytes()

    def __repr__(self) -> str:
        return f"IPv4Options({self.as_bytes()!r})"


@dataclasses.dataclass
class IPv4Header:
    """The header of an IPv4 packet (RFC 791 §3.1); the checksum is checked on reading and computed on writing."""

    VERSION: ClassVar[int] = 4
    MINIMUM_LENGTH: ClassVar[int] = 20
    MAXIMUM_LENGTH: ClassVar[int] = 60
    MAXIMUM_TOTAL_LENGTH: ClassVar[int] = 65535
    MINIMUM_MTU: ClassVar[int] = 68
    DEFAULT_TIME_TO_LIVE: ClassVar[int] = 64
    FRAGMENT_UNIT: ClassVar[int] = 8

    source: IPv4Address
    destination: IPv4Address
    protocol: IPProtocol
    total_length: int = 20
    dscp: int = 0
    ecn: int = 0
    identification: int = 0
    dont_fragment: bool = False
    more_fragments: bool = False
    fragment_offset: int = 0
    time_to_live: int = 64
    options: IPv4Options = dataclasses.field(default_factory=IPv4Options)

    @classmethod
    def new(cls, source: IPv4Address, destination: IPv4Address, protocol: int, payload_length: int) -> IPv4Header:
        """The header of a datagram of ``payload_length`` bytes of ``protocol`` without options; raises ``Length``."""
        structure = Library.default().type("umilib_protocol_ip_v4_IPv4Header")()
        Library.default().call("umilib_protocol_ip_v4_ipv4_header_new", source.to_structure(), destination.to_structure(), int(protocol), payload_length, ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> IPv4Header:
        return cls(
            source=IPv4Address.from_structure(structure.source),
            destination=IPv4Address.from_structure(structure.destination),
            protocol=IPProtocol(structure.protocol),
            total_length=structure.total_length,
            dscp=structure.dscp,
            ecn=structure.ecn,
            identification=structure.identification,
            dont_fragment=bool(structure.dont_fragment),
            more_fragments=bool(structure.more_fragments),
            fragment_offset=structure.fragment_offset,
            time_to_live=structure.time_to_live,
            options=IPv4Options.from_structure(structure.options),
        )

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_ip_v4_IPv4Header")()
        for name in ("total_length", "dscp", "ecn", "identification", "dont_fragment", "more_fragments", "fragment_offset", "time_to_live"):
            Fields.assign(structure, name, getattr(self, name))
        Fields.assign(structure, "protocol", int(self.protocol))
        structure.source = self.source.to_structure()
        structure.destination = self.destination.to_structure()
        structure.options = self.options.structure
        return structure

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> tuple[IPv4Header, bytes]:
        """The header at the start of ``data`` and the data it covers; raises ``Version``,
        ``Length``, ``Checksum`` or ``Option``."""
        data = bytes(data)
        structure = Library.default().type("umilib_protocol_ip_v4_IPv4Header")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        Library.default().call("umilib_protocol_ip_v4_ipv4_header_decode", data, len(data), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        return cls.from_structure(structure), data[offset.value : offset.value + length.value]

    def encode(self) -> bytes:
        """The bytes of the header, with its checksum."""
        return Library.default().output("umilib_protocol_ip_v4_ipv4_header_encode", ctypes.byref(self.to_structure()))

    def header_length(self) -> int:
        return Library.default().function("umilib_protocol_ip_v4_ipv4_header_header_length")(self.to_structure())

    def payload_length(self) -> int:
        return Library.default().function("umilib_protocol_ip_v4_ipv4_header_payload_length")(self.to_structure())

    def is_fragment(self) -> bool:
        return bool(Library.default().function("umilib_protocol_ip_v4_ipv4_header_is_fragment")(self.to_structure()))

    def set_payload_length(self, length: int) -> None:
        """Sets the total length for ``length`` bytes of data; raises ``Length``."""
        structure = self.to_structure()
        Library.default().call("umilib_protocol_ip_v4_ipv4_header_set_payload_length", ctypes.byref(structure), length)
        self.total_length = structure.total_length


class IPv4Fragmenter(Handle):
    """The fragments of a datagram that fit an MTU (RFC 791 §3.2): iterating gives each fragment's
    header and data. Raises ``Fragment`` or ``Length`` when made."""

    FREE = "umilib_protocol_ip_v4_ipv4_fragmenter_free"

    def __init__(self, header: IPv4Header, payload: bytes | bytearray | memoryview, mtu: int) -> None:
        self.payload = bytes(payload)
        super().__init__(Handle.create("umilib_protocol_ip_v4_ipv4_fragmenter_new", ctypes.byref(header.to_structure()), self.payload, len(self.payload), mtu))

    def __iter__(self) -> Iterator[tuple[IPv4Header, bytes]]:
        return self

    def __next__(self) -> tuple[IPv4Header, bytes]:
        found = ctypes.c_bool()
        structure = self.library.type("umilib_protocol_ip_v4_IPv4Header")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        self.library.call("umilib_protocol_ip_v4_ipv4_fragmenter_next", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        if not found.value:
            raise StopIteration
        return IPv4Header.from_structure(structure), self.payload[offset.value : offset.value + length.value]


@dataclasses.dataclass(frozen=True)
class IPv4ReassemblyConfig:
    """The limits of an :class:`IPv4Reassembler`: the timeout from the first-arriving fragment
    (RFC 1122 §3.3.2: 60 to 120 seconds), the largest datagram (EMTU_R), the most datagrams and the
    most bytes held at once."""

    timeout: datetime.timedelta = datetime.timedelta(seconds=60)
    maximum_length: int = 65535
    maximum_datagrams: int = 64
    maximum_buffered: int = 4 << 20

    def to_structure(self) -> Any:
        return Library.default().type("umilib_protocol_ip_v4_IPv4ReassemblyConfig")(
            Nanoseconds.from_timedelta(self.timeout), self.maximum_length, self.maximum_datagrams, self.maximum_buffered
        )


@dataclasses.dataclass(frozen=True)
class IPv4ReassemblyKey:
    """What identifies the fragments of one datagram."""

    source: IPv4Address
    destination: IPv4Address
    protocol: IPProtocol
    identification: int

    @classmethod
    def of(cls, header: IPv4Header) -> IPv4ReassemblyKey:
        return cls(header.source, header.destination, header.protocol, header.identification)


class IPv4Reassembly(Handle):
    """A datagram given back by :meth:`IPv4Reassembler.expire` at its deadline."""

    FREE = "umilib_protocol_ip_v4_ipv4_reassembly_free"

    @property
    def abandoned(self) -> bool:
        """Whether its fragments overlapped (RFC 5722): it has no first fragment, and no ICMP message is sent."""
        return self.library.value("umilib_protocol_ip_v4_ipv4_reassembly_abandoned", ctypes.c_bool, self.handle)

    def first(self) -> tuple[IPv4Header | None, bytes]:
        """The header of the first fragment, if it arrived, and the data received (zeros between the
        fragments): what an ICMP Time Exceeded message quotes."""
        found = ctypes.c_bool()
        structure = self.library.type("umilib_protocol_ip_v4_IPv4Header")()
        data = Buffer()
        self.library.call("umilib_protocol_ip_v4_ipv4_reassembly_first", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(data))
        received = self.library.take(data)
        return (IPv4Header.from_structure(structure) if found.value else None), received


class IPv4Reassembler(Handle):
    """The reassembly of IPv4 datagrams from their fragments, without I/O: fragments that overlap
    discard their datagram (RFC 1858); a datagram not complete by its deadline is given back by
    :meth:`expire`."""

    FREE = "umilib_protocol_ip_v4_ipv4_reassembler_free"

    def __init__(self, config: IPv4ReassemblyConfig = IPv4ReassemblyConfig()) -> None:
        super().__init__(Handle.create("umilib_protocol_ip_v4_ipv4_reassembler_new", config.to_structure()))
        self.config = config

    def receive(self, header: IPv4Header, payload: bytes | bytearray | memoryview, now: int) -> tuple[IPv4Header, bytes] | None:
        """Adds a fragment received at ``now``; returns the datagram it completes. A packet that is
        not a fragment is a complete datagram."""
        complete = ctypes.c_bool()
        structure = self.library.type("umilib_protocol_ip_v4_IPv4Header")()
        data = Buffer()
        self.library.call(
            "umilib_protocol_ip_v4_ipv4_reassembler_receive", self.handle, ctypes.byref(header.to_structure()), *Bytes.readable(payload), now,
            ctypes.byref(complete), ctypes.byref(structure), ctypes.byref(data),
        )  # fmt: skip
        reassembled = self.library.take(data)
        return (IPv4Header.from_structure(structure), reassembled) if complete.value else None

    def poll_timeout(self) -> int | None:
        """The earliest deadline of the datagrams being reassembled."""
        return self.library.optional("umilib_protocol_ip_v4_ipv4_reassembler_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> tuple[IPv4ReassemblyKey, IPv4Reassembly] | None:
        """Removes a datagram whose deadline is at or before ``now`` and returns it."""
        found = ctypes.c_bool()
        key = self.library.type("umilib_protocol_ip_v4_IPv4ReassemblyKey")()
        pointer = ctypes.c_void_p()
        self.library.call("umilib_protocol_ip_v4_ipv4_reassembler_expire", self.handle, now, ctypes.byref(found), ctypes.byref(key), ctypes.byref(pointer))
        if not found.value:
            return None
        key = IPv4ReassemblyKey(
            IPv4Address.from_structure(key.source), IPv4Address.from_structure(key.destination), IPProtocol(key.protocol), key.identification
        )
        return key, IPv4Reassembly(pointer.value)


__all__ = [
    "IPv4Error",
    "IPv4Fragmenter",
    "IPv4Header",
    "IPv4Option",
    "IPv4OptionKind",
    "IPv4Options",
    "IPv4Reassembler",
    "IPv4Reassembly",
    "IPv4ReassemblyConfig",
    "IPv4ReassemblyKey",
]
