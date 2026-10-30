"""IPv6 (RFC 8200): the header, the extension headers with their options, the fragmentation of
packets by their source and their reassembly (RFC 8200 §4.5, RFC 5722, RFC 6946, RFC 7112), without
I/O. Mirrors ``umilib::protocol::ip::v6``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`.
Errors are :class:`IPv6Error`, and :class:`~umilib.protocol.ip.IPError` for fragments the reassembly
buffer refuses.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
from collections.abc import Iterator
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds
from umilib.protocol.ip import IPProtocol, IPv6Address

P = "umilib_protocol_ip_v6"


class IPv6Error(FFIError):
    """An error of an IPv6 packet: ``Version``, ``Length``, ``ExtensionHeader``, ``Option``,
    ``HeaderChain``, ``Fragment``, ``Limit`` or ``Expired``."""


Library.register_error("protocol.ip.v6", IPv6Error)


@dataclasses.dataclass
class IPv6Header:
    """The fixed header of an IPv6 packet (RFC 8200 §3)."""

    VERSION: ClassVar[int] = 6
    LENGTH: ClassVar[int] = 40
    MAXIMUM_PAYLOAD_LENGTH: ClassVar[int] = 65535
    MINIMUM_MTU: ClassVar[int] = 1280
    DEFAULT_HOP_LIMIT: ClassVar[int] = 64
    MAXIMUM_FLOW_LABEL: ClassVar[int] = 0xFFFFF

    source: IPv6Address
    destination: IPv6Address
    next_header: IPProtocol
    payload_length: int = 0
    dscp: int = 0
    ecn: int = 0
    flow_label: int = 0
    hop_limit: int = 64

    @classmethod
    def new(cls, source: IPv6Address, destination: IPv6Address, next_header: int, payload_length: int) -> IPv6Header:
        """The header of a packet of ``payload_length`` bytes starting with ``next_header``; raises ``Length``."""
        structure = Library.default().type(f"{P}_IPv6Header")()
        Library.default().call(f"{P}_ipv6_header_new", source.to_structure(), destination.to_structure(), int(next_header), payload_length, ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> IPv6Header:
        return cls(
            source=IPv6Address.from_structure(structure.source),
            destination=IPv6Address.from_structure(structure.destination),
            next_header=IPProtocol(structure.next_header),
            payload_length=structure.payload_length,
            dscp=structure.dscp,
            ecn=structure.ecn,
            flow_label=structure.flow_label,
            hop_limit=structure.hop_limit,
        )

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_IPv6Header")()
        for name in ("payload_length", "dscp", "ecn", "flow_label", "hop_limit"):
            Fields.assign(structure, name, getattr(self, name))
        Fields.assign(structure, "next_header", int(self.next_header))
        structure.source = self.source.to_structure()
        structure.destination = self.destination.to_structure()
        return structure

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> tuple[IPv6Header, bytes]:
        """The header at the start of ``data`` and the payload it covers; raises ``Version`` or ``Length``."""
        data = bytes(data)
        structure = Library.default().type(f"{P}_IPv6Header")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        Library.default().call(f"{P}_ipv6_header_decode", data, len(data), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        return cls.from_structure(structure), data[offset.value : offset.value + length.value]

    def encode(self) -> bytes:
        """The 40 bytes of the header."""
        return Library.default().output(f"{P}_ipv6_header_encode", ctypes.byref(self.to_structure()))


@dataclasses.dataclass(frozen=True)
class IPv6ExtensionHeader:
    """One extension header of a chain: its kind, the Next Header value it holds and its bytes."""

    kind: IPProtocol
    next_header: IPProtocol
    bytes: bytes

    @staticmethod
    def is_extension(kind: int) -> bool:
        """Whether ``kind`` names an extension header that a chain continues after (RFC 7045, ESP excepted)."""
        return bool(Library.default().function(f"{P}_ipv6_extension_header_is_extension")(int(kind)))

    @staticmethod
    def length(kind: int, data: bytes | bytearray | memoryview) -> int:
        """The length of the extension header of ``kind`` that ``data`` starts with; raises ``Length``."""
        return Library.default().value(f"{P}_ipv6_extension_header_length", ctypes.c_size_t, int(kind), *Bytes.readable(data))


class IPv6ExtensionHeaders:
    """The extension headers of a payload, in order (RFC 8200 §4.1). When it ends, ``next_header``
    is the upper layer and ``offset`` the start of its data. Raises ``Length`` or ``ExtensionHeader``."""

    def __init__(self, next_header: int, payload: bytes | bytearray | memoryview) -> None:
        self.next_header = IPProtocol(next_header)
        self.payload = bytes(payload)
        self.offset = 0

    def __iter__(self) -> Iterator[IPv6ExtensionHeader]:
        return self

    def __next__(self) -> IPv6ExtensionHeader:
        kind, offset = ctypes.c_uint8(int(self.next_header)), ctypes.c_size_t(self.offset)
        found, length = ctypes.c_bool(), ctypes.c_size_t()
        Library.default().call(
            f"{P}_ipv6_extension_headers_next", ctypes.byref(kind), self.payload, len(self.payload), ctypes.byref(offset),
            ctypes.byref(found), ctypes.byref(length),
        )  # fmt: skip
        if not found.value:
            raise StopIteration
        start = self.offset
        header = IPv6ExtensionHeader(self.next_header, IPProtocol(kind.value), self.payload[start : start + length.value])
        self.next_header, self.offset = IPProtocol(kind.value), offset.value
        return header

    @staticmethod
    def upper_layer(next_header: int, payload: bytes | bytearray | memoryview) -> tuple[IPProtocol, int]:
        """The upper layer of ``payload`` and the offset of its data."""
        protocol, offset = ctypes.c_uint8(), ctypes.c_size_t()
        Library.default().call(
            f"{P}_ipv6_extension_headers_upper_layer", int(next_header), *Bytes.readable(payload), ctypes.byref(protocol), ctypes.byref(offset)
        )
        return IPProtocol(protocol.value), offset.value


class IPv6OptionKind(int):
    """The Option Type of an option (RFC 8200 §4.2)."""

    PAD1: ClassVar[IPv6OptionKind]
    PADN: ClassVar[IPv6OptionKind]
    TUNNEL_ENCAPSULATION_LIMIT: ClassVar[IPv6OptionKind]
    ROUTER_ALERT: ClassVar[IPv6OptionKind]
    JUMBO_PAYLOAD: ClassVar[IPv6OptionKind]
    HOME_ADDRESS: ClassVar[IPv6OptionKind]

    def __new__(cls, value: int) -> IPv6OptionKind:
        if not 0 <= value <= 255:
            raise ValueError("an option type is 0 to 255")
        return super().__new__(cls, value)

    def action(self) -> int:
        """What a node that does not recognize the option does: 0 skips it, 1 discards the packet,
        2 also sends an ICMP Parameter Problem, 3 does so if the destination is not multicast."""
        return Library.default().function(f"{P}_ipv6_option_kind_action")(int(self))

    def may_change(self) -> bool:
        return bool(Library.default().function(f"{P}_ipv6_option_kind_may_change")(int(self)))

    def __repr__(self) -> str:
        return f"IPv6OptionKind({int(self)})"


for _name, _value in [
    ("PAD1", 0x00), ("PADN", 0x01), ("TUNNEL_ENCAPSULATION_LIMIT", 0x04), ("ROUTER_ALERT", 0x05),
    ("JUMBO_PAYLOAD", 0xC2), ("HOME_ADDRESS", 0xC9),
]:  # fmt: skip
    setattr(IPv6OptionKind, _name, IPv6OptionKind(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class IPv6Option:
    """One option: its type, its data and the offset of its type in its header."""

    kind: IPv6OptionKind
    data: bytes
    offset: int = 0

    @staticmethod
    def encode(kind: int, data: bytes = b"") -> bytes:
        """The bytes of an option of ``kind`` with ``data``; raises ``Option``."""
        return Library.default().output(f"{P}_ipv6_option_encode", int(kind), *Bytes.readable(data))

    @staticmethod
    def encode_padding(length: int) -> bytes:
        """``length`` bytes of padding: Pad1 for one, PadN otherwise."""
        return Library.default().output(f"{P}_ipv6_option_encode_padding", length)


@dataclasses.dataclass(frozen=True)
class IPv6OptionsHeader:
    """A Hop-by-Hop or Destination Options header: the Next Header value and the options area."""

    next_header: IPProtocol
    options: bytes

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> IPv6OptionsHeader:
        """The header that ``data`` is; raises ``Length`` or ``Option``."""
        data = bytes(data)
        next_header = Library.default().value(f"{P}_ipv6_options_header_decode", ctypes.c_uint8, data, len(data))
        return cls(IPProtocol(next_header), data[2:])

    def __iter__(self) -> Iterator[IPv6Option]:
        """The options in order, without padding."""
        library = Library.default()
        data = bytes([int(self.next_header), (len(self.options) + 2) // 8 - 1]) + self.options
        index = 0
        while True:
            found, kind, offset, buffer = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_size_t(), Buffer()
            library.call(
                f"{P}_ipv6_options_header_get", data, len(data), index, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(offset), ctypes.byref(buffer)
            )
            value = library.take(buffer)
            if not found.value:
                return
            yield IPv6Option(IPv6OptionKind(kind.value), value, offset.value)
            index += 1

    def iter(self) -> Iterator[IPv6Option]:
        return iter(self)

    @staticmethod
    def encoded_length(length: int) -> int:
        """The length of a header whose options take ``length`` bytes."""
        return (length + 2 + 7) // 8 * 8

    def encode(self) -> bytes:
        """The bytes of the header: its encoded options, padded to a multiple of 8 bytes; raises ``Length``."""
        return Library.default().output(f"{P}_ipv6_options_header_encode", int(self.next_header), *Bytes.readable(self.options))


@dataclasses.dataclass(frozen=True)
class IPv6RoutingHeader:
    """A Routing header (RFC 8200 §4.4): its type, the segments left and the type-specific data."""

    next_header: IPProtocol
    routing_type: int
    segments_left: int
    data: bytes

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> IPv6RoutingHeader:
        """The header that ``data`` is; raises ``Length``."""
        next_header, routing_type, segments_left, buffer = ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_uint8(), Buffer()
        library = Library.default()
        library.call(
            f"{P}_ipv6_routing_header_decode", *Bytes.readable(data), ctypes.byref(next_header), ctypes.byref(routing_type),
            ctypes.byref(segments_left), ctypes.byref(buffer),
        )  # fmt: skip
        return cls(IPProtocol(next_header.value), routing_type.value, segments_left.value, library.take(buffer))

    def encode(self) -> bytes:
        """The bytes of the header; the data must make it a multiple of 8 bytes."""
        return Library.default().output(
            f"{P}_ipv6_routing_header_encode", int(self.next_header), self.routing_type, self.segments_left, *Bytes.readable(self.data)
        )


@dataclasses.dataclass(frozen=True)
class IPv6FragmentHeader:
    """A Fragment header (RFC 8200 §4.5); the offset is in units of 8 bytes."""

    LENGTH: ClassVar[int] = 8
    FRAGMENT_UNIT: ClassVar[int] = 8

    next_header: IPProtocol
    fragment_offset: int
    more_fragments: bool
    identification: int

    @classmethod
    def from_structure(cls, structure: Any) -> IPv6FragmentHeader:
        return cls(IPProtocol(structure.next_header), structure.fragment_offset, bool(structure.more_fragments), structure.identification)

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_IPv6FragmentHeader")()
        for name, value in (("next_header", int(self.next_header)), ("fragment_offset", self.fragment_offset), ("identification", self.identification)):
            Fields.assign(structure, name, value)
        structure.more_fragments = self.more_fragments
        return structure

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> IPv6FragmentHeader:
        structure = Library.default().type(f"{P}_IPv6FragmentHeader")()
        Library.default().call(f"{P}_ipv6_fragment_header_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls.from_structure(structure)

    def encode(self) -> bytes:
        return Library.default().output(f"{P}_ipv6_fragment_header_encode", self.to_structure())

    def is_atomic(self) -> bool:
        """Whether the fragment is a whole packet (RFC 6946)."""
        return bool(Library.default().function(f"{P}_ipv6_fragment_header_is_atomic")(self.to_structure()))


class IPv6Fragmenter(Handle):
    """The fragments of a packet that fit an MTU, made by its source (RFC 8200 §4.5): iterating gives
    the bytes of each packet. Raises ``Fragment``, ``HeaderChain`` or ``Length`` when made."""

    FREE = f"{P}_ipv6_fragmenter_free"

    def __init__(self, header: IPv6Header, payload: bytes | bytearray | memoryview, identification: int, mtu: int) -> None:
        super().__init__(Handle.create(f"{P}_ipv6_fragmenter_new", ctypes.byref(header.to_structure()), *Bytes.readable(payload), identification, mtu))

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        found, buffer = ctypes.c_bool(), Buffer()
        self.library.call(f"{P}_ipv6_fragmenter_next", self.handle, ctypes.byref(found), ctypes.byref(buffer))
        packet = self.library.take(buffer)
        if not found.value:
            raise StopIteration
        return packet


@dataclasses.dataclass(frozen=True)
class IPv6ReassemblyConfig:
    """The limits of an :class:`IPv6Reassembler`: the timeout from the first-arriving fragment
    (RFC 8200 §4.5: 60 seconds), the largest payload, the most packets and the most bytes held at once."""

    timeout: datetime.timedelta = datetime.timedelta(seconds=60)
    maximum_length: int = 65535
    maximum_datagrams: int = 64
    maximum_buffered: int = 4 << 20

    def to_structure(self) -> Any:
        return Library.default().type(f"{P}_IPv6ReassemblyConfig")(
            Nanoseconds.from_timedelta(self.timeout), self.maximum_length, self.maximum_datagrams, self.maximum_buffered
        )


@dataclasses.dataclass(frozen=True)
class IPv6ReassemblyKey:
    """What identifies the fragments of one packet."""

    source: IPv6Address
    destination: IPv6Address
    identification: int

    @classmethod
    def of(cls, header: IPv6Header, fragment: IPv6FragmentHeader) -> IPv6ReassemblyKey:
        return cls(header.source, header.destination, fragment.identification)


class IPv6Reassembly(Handle):
    """A packet given back by :meth:`IPv6Reassembler.expire` at its deadline."""

    FREE = f"{P}_ipv6_reassembly_free"

    @property
    def abandoned(self) -> bool:
        """Whether its fragments overlapped (RFC 5722): it has no first fragment, and no ICMP message is sent."""
        return self.library.value(f"{P}_ipv6_reassembly_abandoned", ctypes.c_bool, self.handle)

    def first(self) -> tuple[bytes | None, bytes]:
        """The headers of the first fragment's packet up to its data (IPv6 header, per-fragment
        headers, Fragment header), if it arrived, and the data received: what an ICMPv6 Time
        Exceeded message quotes."""
        found, headers, data = ctypes.c_bool(), Buffer(), Buffer()
        self.library.call(f"{P}_ipv6_reassembly_first", self.handle, ctypes.byref(found), ctypes.byref(headers), ctypes.byref(data))
        first, received = self.library.take(headers), self.library.take(data)
        return (first if found.value else None), received


class IPv6Reassembler(Handle):
    """The reassembly of IPv6 packets from their fragments, without I/O: an atomic fragment is a
    whole packet; overlapping fragments discard their packet (RFC 5722); a packet not complete by
    its deadline is given back by :meth:`expire`."""

    FREE = f"{P}_ipv6_reassembler_free"

    def __init__(self, config: IPv6ReassemblyConfig = IPv6ReassemblyConfig()) -> None:
        super().__init__(Handle.create(f"{P}_ipv6_reassembler_new", config.to_structure()))
        self.config = config

    def receive(self, header: IPv6Header, payload: bytes | bytearray | memoryview, now: int) -> tuple[IPv6Header, bytes] | None:
        """Adds a packet received at ``now``; returns the packet it completes, without a Fragment header."""
        complete = ctypes.c_bool()
        structure = self.library.type(f"{P}_IPv6Header")()
        data = Buffer()
        self.library.call(
            f"{P}_ipv6_reassembler_receive", self.handle, ctypes.byref(header.to_structure()), *Bytes.readable(payload), now,
            ctypes.byref(complete), ctypes.byref(structure), ctypes.byref(data),
        )  # fmt: skip
        reassembled = self.library.take(data)
        return (IPv6Header.from_structure(structure), reassembled) if complete.value else None

    def poll_timeout(self) -> int | None:
        """The earliest deadline of the packets being reassembled."""
        return self.library.optional(f"{P}_ipv6_reassembler_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> tuple[IPv6ReassemblyKey, IPv6Reassembly] | None:
        """Removes a packet whose deadline is at or before ``now`` and returns it."""
        found = ctypes.c_bool()
        key = self.library.type(f"{P}_IPv6ReassemblyKey")()
        pointer = ctypes.c_void_p()
        self.library.call(f"{P}_ipv6_reassembler_expire", self.handle, now, ctypes.byref(found), ctypes.byref(key), ctypes.byref(pointer))
        if not found.value:
            return None
        key = IPv6ReassemblyKey(IPv6Address.from_structure(key.source), IPv6Address.from_structure(key.destination), key.identification)
        return key, IPv6Reassembly(pointer.value)


__all__ = [
    "IPv6Error",
    "IPv6ExtensionHeader",
    "IPv6ExtensionHeaders",
    "IPv6FragmentHeader",
    "IPv6Fragmenter",
    "IPv6Header",
    "IPv6Option",
    "IPv6OptionKind",
    "IPv6OptionsHeader",
    "IPv6Reassembler",
    "IPv6Reassembly",
    "IPv6ReassemblyConfig",
    "IPv6ReassemblyKey",
    "IPv6RoutingHeader",
]
