"""ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861, with RFC 4191 and RFC 8106): the messages, the
rules of error messages, the Neighbor Discovery messages with their options and validity checks, and
the Neighbor Cache with its reachability state machine, for 6-byte link-layer addresses. Mirrors
``umilib::protocol::icmp::v6``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`.
Errors are :class:`~umilib.protocol.icmp.ICMPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from collections.abc import Iterator
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds
from umilib.protocol.icmp import ICMPExtensions, ICMPHeader
from umilib.protocol.ip import IPv6Address
from umilib.protocol.ip.v6 import IPv6Header

P = "umilib_protocol_icmp_v6"


class ICMPv6Type(int):
    """The type of an ICMPv6 message (the IANA registry "ICMPv6 'type' Numbers")."""

    DESTINATION_UNREACHABLE: ClassVar[ICMPv6Type]
    PACKET_TOO_BIG: ClassVar[ICMPv6Type]
    TIME_EXCEEDED: ClassVar[ICMPv6Type]
    PARAMETER_PROBLEM: ClassVar[ICMPv6Type]
    ECHO_REQUEST: ClassVar[ICMPv6Type]
    ECHO_REPLY: ClassVar[ICMPv6Type]
    MULTICAST_LISTENER_QUERY: ClassVar[ICMPv6Type]
    MULTICAST_LISTENER_REPORT: ClassVar[ICMPv6Type]
    MULTICAST_LISTENER_DONE: ClassVar[ICMPv6Type]
    ROUTER_SOLICITATION: ClassVar[ICMPv6Type]
    ROUTER_ADVERTISEMENT: ClassVar[ICMPv6Type]
    NEIGHBOR_SOLICITATION: ClassVar[ICMPv6Type]
    NEIGHBOR_ADVERTISEMENT: ClassVar[ICMPv6Type]
    REDIRECT: ClassVar[ICMPv6Type]
    MULTICAST_LISTENER_REPORT_V2: ClassVar[ICMPv6Type]
    EXTENDED_ECHO_REQUEST: ClassVar[ICMPv6Type]
    EXTENDED_ECHO_REPLY: ClassVar[ICMPv6Type]

    def __new__(cls, value: int) -> ICMPv6Type:
        if not 0 <= value <= 255:
            raise ValueError("a type is 0 to 255")
        return super().__new__(cls, value)

    def is_error(self) -> bool:
        """Whether the type is that of an error message: below 128."""
        return bool(Library.default().function(f"{P}_icmpv6_type_is_error")(int(self)))

    def is_extensible(self) -> bool:
        """Whether an error of this type carries the length attribute of RFC 4884."""
        return bool(Library.default().function(f"{P}_icmpv6_type_is_extensible")(int(self)))

    def __repr__(self) -> str:
        return f"ICMPv6Type({int(self)})"


for _name, _value in [
    ("DESTINATION_UNREACHABLE", 1), ("PACKET_TOO_BIG", 2), ("TIME_EXCEEDED", 3), ("PARAMETER_PROBLEM", 4),
    ("ECHO_REQUEST", 128), ("ECHO_REPLY", 129), ("MULTICAST_LISTENER_QUERY", 130), ("MULTICAST_LISTENER_REPORT", 131),
    ("MULTICAST_LISTENER_DONE", 132), ("ROUTER_SOLICITATION", 133), ("ROUTER_ADVERTISEMENT", 134),
    ("NEIGHBOR_SOLICITATION", 135), ("NEIGHBOR_ADVERTISEMENT", 136), ("REDIRECT", 137),
    ("MULTICAST_LISTENER_REPORT_V2", 143), ("EXTENDED_ECHO_REQUEST", 160), ("EXTENDED_ECHO_REPLY", 161),
]:  # fmt: skip
    setattr(ICMPv6Type, _name, ICMPv6Type(_value))
del _name, _value


class ICMPv6Code:
    """The codes of ICMPv6 error messages, by type (RFC 4443 §3, RFC 7112, RFC 8883)."""

    NO_ROUTE = 0
    ADMINISTRATIVELY_PROHIBITED = 1
    BEYOND_SCOPE = 2
    ADDRESS_UNREACHABLE = 3
    PORT_UNREACHABLE = 4
    SOURCE_POLICY_FAILED = 5
    REJECT_ROUTE = 6
    SOURCE_ROUTING_HEADER_ERROR = 7
    HEADERS_TOO_LONG = 8
    HOP_LIMIT_EXCEEDED = 0
    REASSEMBLY_TIME_EXCEEDED = 1
    ERRONEOUS_HEADER_FIELD = 0
    UNRECOGNIZED_NEXT_HEADER = 1
    UNRECOGNIZED_OPTION = 2
    INCOMPLETE_HEADER_CHAIN = 3


@dataclasses.dataclass(frozen=True)
class ICMPv6Message:
    """An ICMPv6 message (RFC 4443): its type, its code, the four bytes after the checksum and the
    body. The checksum, which covers the addresses of the packet, is checked on reading and computed
    on writing."""

    HEADER_LENGTH: ClassVar[int] = 8
    MAXIMUM_ERROR_LENGTH: ClassVar[int] = 1280
    WORD: ClassVar[int] = 8

    kind: ICMPv6Type
    code: int
    rest: bytes
    body: bytes = b""

    def header_structure(self) -> Any:
        return ICMPHeader.to_structure(self.kind, self.code, self.rest)

    @classmethod
    def from_structure(cls, structure: Any, body: bytes = b"") -> ICMPv6Message:
        kind, code, rest = ICMPHeader.from_structure(structure)
        return cls(ICMPv6Type(kind), code, rest, body)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview, source: IPv6Address, destination: IPv6Address) -> ICMPv6Message:
        """The message that ``data`` is, carried from ``source`` to ``destination``; raises ``Length`` or ``Checksum``."""
        data = bytes(data)
        structure = Library.default().type("umilib_protocol_icmp_ICMPHeader")()
        Library.default().call(f"{P}_icmpv6_message_decode", data, len(data), source.to_structure(), destination.to_structure(), ctypes.byref(structure))
        return cls.from_structure(structure, data[ICMPv6Message.HEADER_LENGTH :])

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        return Library.default().output(
            f"{P}_icmpv6_message_encode", self.header_structure(), *Bytes.readable(self.body), source.to_structure(), destination.to_structure()
        )

    def length(self) -> int:
        return ICMPv6Message.HEADER_LENGTH + len(self.body)

    @classmethod
    def echo_request(cls, identifier: int, sequence: int, data: bytes = b"") -> ICMPv6Message:
        return cls.from_structure(Library.default().function(f"{P}_icmpv6_message_echo_request")(identifier, sequence), bytes(data))

    def echo_reply(self) -> ICMPv6Message | None:
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_icmp_ICMPHeader")()
        Library.default().call(f"{P}_icmpv6_message_echo_reply", self.header_structure(), ctypes.byref(found), ctypes.byref(structure))
        return ICMPv6Message.from_structure(structure, self.body) if found.value else None

    def echo(self) -> tuple[int, int] | None:
        found, identifier, sequence = ctypes.c_bool(), ctypes.c_uint16(), ctypes.c_uint16()
        Library.default().call(f"{P}_icmpv6_message_echo", self.header_structure(), ctypes.byref(found), ctypes.byref(identifier), ctypes.byref(sequence))
        return (identifier.value, sequence.value) if found.value else None

    def is_echo(self) -> bool:
        return self.echo() is not None

    def identifier(self) -> int | None:
        echo = self.echo()
        return echo[0] if echo else None

    def sequence(self) -> int | None:
        echo = self.echo()
        return echo[1] if echo else None

    def mtu(self) -> int | None:
        """The MTU of a Packet Too Big message."""
        return Library.default().optional(f"{P}_icmpv6_message_mtu", ctypes.c_uint32, self.header_structure())

    def pointer(self) -> int | None:
        """The offset in the invoking packet a Parameter Problem points to."""
        return Library.default().optional(f"{P}_icmpv6_message_pointer", ctypes.c_uint32, self.header_structure())

    def original(self) -> tuple[bytes, ICMPExtensions | None]:
        """The invoking packet an error quotes and its extension structure (RFC 4884), if any."""
        length, found = ctypes.c_size_t(), ctypes.c_bool()
        Library.default().call(f"{P}_icmpv6_message_original", self.header_structure(), *Bytes.readable(self.body), ctypes.byref(length), ctypes.byref(found))
        return self.body[: length.value], (ICMPExtensions.decode(self.body[length.value :]) if found.value else None)

    def invoking(self) -> tuple[IPv6Header, bytes] | None:
        """The header of the packet an error quotes and the part of its data quoted; read from the
        whole body when the extensions are malformed."""
        try:
            original, _ = self.original()
        except FFIError:
            original = self.body
        structure = Library.default().type("umilib_protocol_ip_v6_IPv6Header")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        try:
            Library.default().call("umilib_protocol_ip_v6_ipv6_header_decode_truncated", original, len(original), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        except FFIError:
            return None
        return IPv6Header.from_structure(structure), original[offset.value : offset.value + length.value]

    @staticmethod
    def quote_length(length: int, headers: int) -> int:
        return Library.default().function(f"{P}_icmpv6_message_quote_length")(length, headers)

    @staticmethod
    def quote(packet: bytes, headers: int) -> bytes:
        """The start of ``packet`` an error quotes, within 1,280 bytes (RFC 4443 §2.4 (c))."""
        return bytes(packet[: ICMPv6Message.quote_length(len(packet), headers)])

    @staticmethod
    def may_report(header: IPv6Header, payload: bytes, multicast: bool, error: ICMPv6Message) -> bool:
        """Whether the error ``error`` (its body is not read) may be sent about a packet (RFC 4443 §2.4 (e))."""
        return Library.default().value(
            f"{P}_icmpv6_message_may_report", ctypes.c_bool, ctypes.byref(header.to_structure()), *Bytes.readable(payload), multicast, error.header_structure()
        )


class NDPOptionKind(int):
    """The type of a Neighbor Discovery option."""

    SOURCE_LINK_ADDRESS: ClassVar[NDPOptionKind]
    TARGET_LINK_ADDRESS: ClassVar[NDPOptionKind]
    PREFIX_INFORMATION: ClassVar[NDPOptionKind]
    REDIRECTED_HEADER: ClassVar[NDPOptionKind]
    MTU: ClassVar[NDPOptionKind]
    NONCE: ClassVar[NDPOptionKind]
    ROUTE_INFORMATION: ClassVar[NDPOptionKind]
    RECURSIVE_DNS_SERVERS: ClassVar[NDPOptionKind]
    DNS_SEARCH_LIST: ClassVar[NDPOptionKind]

    def __new__(cls, value: int) -> NDPOptionKind:
        if not 0 <= value <= 255:
            raise ValueError("an option type is 0 to 255")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"NDPOptionKind({int(self)})"


for _name, _value in [
    ("SOURCE_LINK_ADDRESS", 1), ("TARGET_LINK_ADDRESS", 2), ("PREFIX_INFORMATION", 3), ("REDIRECTED_HEADER", 4),
    ("MTU", 5), ("NONCE", 14), ("ROUTE_INFORMATION", 24), ("RECURSIVE_DNS_SERVERS", 25), ("DNS_SEARCH_LIST", 31),
]:  # fmt: skip
    setattr(NDPOptionKind, _name, NDPOptionKind(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class NDPOption:
    """One option: its type and the bytes after its type and length octets."""

    UNIT: ClassVar[int] = 8

    kind: NDPOptionKind
    data: bytes

    @staticmethod
    def encode(kind: int, data: bytes) -> bytes:
        """The bytes of an option of ``kind`` with ``data``, padded to a multiple of 8 bytes."""
        return Library.default().output(f"{P}_ndp_option_encode", int(kind), *Bytes.readable(data))

    def mtu(self) -> int | None:
        """The MTU of an MTU option."""
        return Library.default().optional(f"{P}_ndp_option_mtu", ctypes.c_uint32, int(self.kind), *Bytes.readable(self.data))

    def redirected_packet(self) -> bytes | None:
        return self.data[6:] if self.kind == NDPOptionKind.REDIRECTED_HEADER and len(self.data) >= 6 else None


class NDPOptions:
    """The options of a Neighbor Discovery message, in order; an option of length zero raises ``Invalid``."""

    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)

    def __iter__(self) -> Iterator[NDPOption]:
        library = Library.default()
        index = 0
        while True:
            found, kind, data = ctypes.c_bool(), ctypes.c_uint8(), Buffer()
            library.call(f"{P}_ndp_options_get", self.data, len(self.data), index, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(data))
            value = library.take(data)
            if not found.value:
                return
            yield NDPOption(NDPOptionKind(kind.value), value)
            index += 1

    @staticmethod
    def check(data: bytes) -> None:
        for _ in NDPOptions(data):
            pass

    @staticmethod
    def find(data: bytes, kind: int) -> bytes | None:
        """The data of the first option of ``kind``."""
        try:
            return next((option.data for option in NDPOptions(data) if option.kind == kind), None)
        except FFIError:
            return None


@dataclasses.dataclass(frozen=True)
class NDPPrefixInformation:
    """A Prefix Information option (RFC 4861 §4.6.2); lifetimes in seconds, all ones being infinity."""

    LENGTH: ClassVar[int] = 30
    INFINITY: ClassVar[int] = 0xFFFFFFFF
    FLAGS: ClassVar[int] = 0x3F

    prefix_length: int
    on_link: bool
    autonomous: bool
    flags: int
    valid_lifetime: int
    preferred_lifetime: int
    prefix: IPv6Address

    @classmethod
    def decode(cls, data: bytes) -> NDPPrefixInformation:
        structure = Library.default().type(f"{P}_NDPPrefixInformation")()
        Library.default().call(f"{P}_ndp_prefix_information_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls(
            structure.prefix_length, bool(structure.on_link), bool(structure.autonomous), structure.flags,
            structure.valid_lifetime, structure.preferred_lifetime, IPv6Address.from_structure(structure.prefix),
        )  # fmt: skip

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_NDPPrefixInformation")()
        for name in ("prefix_length", "flags", "valid_lifetime", "preferred_lifetime"):
            Fields.assign(structure, name, getattr(self, name))
        structure.on_link, structure.autonomous = self.on_link, self.autonomous
        structure.prefix = self.prefix.to_structure()
        return structure

    def check(self) -> None:
        """Raises ``Invalid`` for a prefix length above 128, a preferred lifetime above the valid one,
        or other bits in ``flags`` than :attr:`FLAGS`."""
        Library.default().call(f"{P}_ndp_prefix_information_check", self.to_structure())

    def encode(self) -> bytes:
        return Library.default().output(f"{P}_ndp_prefix_information_encode", self.to_structure())


class NDPPreference:
    """The two-bit preferences of default routers and routes (RFC 4191 §2.1); ``RESERVED`` is never sent."""

    HIGH = 0b01
    MEDIUM = 0b00
    LOW = 0b11
    RESERVED = 0b10

    @staticmethod
    def is_valid(preference: int) -> bool:
        return 0 <= preference <= 0b11 and preference != NDPPreference.RESERVED


@dataclasses.dataclass(frozen=True)
class NDPRouteInformation:
    """A Route Information option (RFC 4191 §2.3), with a preference of :class:`NDPPreference`."""

    prefix_length: int
    preference: int
    lifetime: int
    prefix: IPv6Address

    @classmethod
    def decode(cls, data: bytes) -> NDPRouteInformation:
        structure = Library.default().type(f"{P}_NDPRouteInformation")()
        Library.default().call(f"{P}_ndp_route_information_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls(structure.prefix_length, structure.preference, structure.lifetime, IPv6Address.from_structure(structure.prefix))

    def encode(self) -> bytes:
        structure = Library.default().type(f"{P}_NDPRouteInformation")()
        for name in ("prefix_length", "preference", "lifetime"):
            Fields.assign(structure, name, getattr(self, name))
        structure.prefix = self.prefix.to_structure()
        return Library.default().output(f"{P}_ndp_route_information_encode", structure)


@dataclasses.dataclass(frozen=True)
class NDPRecursiveDNSServers:
    """A Recursive DNS Server option (RFC 8106 §5.1): the lifetime and the addresses of the servers."""

    lifetime: int
    addresses: bytes

    @classmethod
    def decode(cls, data: bytes) -> NDPRecursiveDNSServers:
        lifetime, addresses = ctypes.c_uint32(), Buffer()
        library = Library.default()
        library.call(f"{P}_ndp_recursive_dns_servers_decode", *Bytes.readable(data), ctypes.byref(lifetime), ctypes.byref(addresses))
        return cls(lifetime.value, library.take(addresses))

    def __iter__(self) -> Iterator[IPv6Address]:
        for start in range(0, len(self.addresses), 16):
            yield IPv6Address(self.addresses[start : start + 16])

    def iter(self) -> Iterator[IPv6Address]:
        return iter(self)

    def encode(self) -> bytes:
        return Library.default().output(f"{P}_ndp_recursive_dns_servers_encode", self.lifetime, *Bytes.readable(self.addresses))


class NDPMessage:
    """What every Neighbor Discovery message shares."""

    HOP_LIMIT = 255

    @staticmethod
    def is_solicited_node(address: IPv6Address) -> bool:
        return bool(Library.default().function(f"{P}_ndp_message_is_solicited_node")(address.to_structure()))


@dataclasses.dataclass(frozen=True)
class NDPRouterSolicitation:
    """A Router Solicitation (RFC 4861 §4.1)."""

    options: bytes = b""

    @classmethod
    def decode(cls, message: ICMPv6Message, header: IPv6Header) -> NDPRouterSolicitation:
        """The valid solicitation (RFC 4861 §6.1.1) of ``message``; raises ``Invalid``."""
        Library.default().call(f"{P}_ndp_router_solicitation_decode", message.header_structure(), *Bytes.readable(message.body), ctypes.byref(header.to_structure()))
        return cls(message.body)

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        return Library.default().output(f"{P}_ndp_router_solicitation_encode", *Bytes.readable(self.options), source.to_structure(), destination.to_structure())

    def source_link_address(self) -> bytes | None:
        return NDPOptions.find(self.options, NDPOptionKind.SOURCE_LINK_ADDRESS)


@dataclasses.dataclass(frozen=True)
class NDPRouterAdvertisement:
    """A Router Advertisement (RFC 4861 §4.2, with the preference of RFC 4191)."""

    current_hop_limit: int
    managed_flag: bool
    other_flag: bool
    preference: int
    flags: int
    router_lifetime: int
    reachable_time: int
    retransmission_timer: int
    options: bytes = b""

    FLAGS: ClassVar[int] = 0x27
    FIELDS: ClassVar[tuple[str, ...]] = (
        "current_hop_limit", "managed_flag", "other_flag", "preference", "flags", "router_lifetime", "reachable_time",
        "retransmission_timer",
    )  # fmt: skip

    @classmethod
    def decode(cls, message: ICMPv6Message, header: IPv6Header) -> NDPRouterAdvertisement:
        """The valid advertisement (RFC 4861 §6.1.2) of ``message``; raises ``Invalid``."""
        structure = Library.default().type(f"{P}_NDPRouterAdvertisement")()
        offset = ctypes.c_size_t()
        Library.default().call(
            f"{P}_ndp_router_advertisement_decode", message.header_structure(), *Bytes.readable(message.body), ctypes.byref(header.to_structure()),
            ctypes.byref(structure), ctypes.byref(offset),
        )  # fmt: skip
        values = {name: getattr(structure, name) for name in NDPRouterAdvertisement.FIELDS}
        return cls(**values, options=message.body[offset.value :])

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        structure = Library.default().type(f"{P}_NDPRouterAdvertisement")()
        for name in NDPRouterAdvertisement.FIELDS:
            Fields.assign(structure, name, getattr(self, name))
        return Library.default().output(
            f"{P}_ndp_router_advertisement_encode", ctypes.byref(structure), *Bytes.readable(self.options), source.to_structure(), destination.to_structure()
        )

    def source_link_address(self) -> bytes | None:
        return NDPOptions.find(self.options, NDPOptionKind.SOURCE_LINK_ADDRESS)


@dataclasses.dataclass(frozen=True)
class NDPNeighborSolicitation:
    """A Neighbor Solicitation (RFC 4861 §4.3)."""

    target: IPv6Address
    options: bytes = b""

    @classmethod
    def decode(cls, message: ICMPv6Message, header: IPv6Header) -> NDPNeighborSolicitation:
        """The valid solicitation (RFC 4861 §7.1.1) of ``message``; raises ``Invalid``."""
        target = Library.default().type("umilib_protocol_ip_IPv6Address")()
        offset = ctypes.c_size_t()
        Library.default().call(
            f"{P}_ndp_neighbor_solicitation_decode", message.header_structure(), *Bytes.readable(message.body), ctypes.byref(header.to_structure()),
            ctypes.byref(target), ctypes.byref(offset),
        )  # fmt: skip
        return cls(IPv6Address.from_structure(target), message.body[offset.value :])

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        return Library.default().output(
            f"{P}_ndp_neighbor_solicitation_encode", self.target.to_structure(), *Bytes.readable(self.options), source.to_structure(), destination.to_structure()
        )

    def source_link_address(self) -> bytes | None:
        return NDPOptions.find(self.options, NDPOptionKind.SOURCE_LINK_ADDRESS)

    @staticmethod
    def is_duplicate_address_detection(header: IPv6Header) -> bool:
        return header.source.is_unspecified()


@dataclasses.dataclass(frozen=True)
class NDPNeighborAdvertisement:
    """A Neighbor Advertisement (RFC 4861 §4.4)."""

    router_flag: bool
    solicited_flag: bool
    override_flag: bool
    target: IPv6Address
    options: bytes = b""

    def to_structure(self) -> Any:
        return Library.default().type(f"{P}_NDPNeighborAdvertisement")(self.router_flag, self.solicited_flag, self.override_flag, self.target.to_structure())

    @classmethod
    def decode(cls, message: ICMPv6Message, header: IPv6Header) -> NDPNeighborAdvertisement:
        """The valid advertisement (RFC 4861 §7.1.2) of ``message``; raises ``Invalid``."""
        structure = Library.default().type(f"{P}_NDPNeighborAdvertisement")()
        offset = ctypes.c_size_t()
        Library.default().call(
            f"{P}_ndp_neighbor_advertisement_decode", message.header_structure(), *Bytes.readable(message.body), ctypes.byref(header.to_structure()),
            ctypes.byref(structure), ctypes.byref(offset),
        )  # fmt: skip
        return cls(
            bool(structure.router_flag), bool(structure.solicited_flag), bool(structure.override_flag),
            IPv6Address.from_structure(structure.target), message.body[offset.value :],
        )  # fmt: skip

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        return Library.default().output(
            f"{P}_ndp_neighbor_advertisement_encode", ctypes.byref(self.to_structure()), *Bytes.readable(self.options), source.to_structure(), destination.to_structure()
        )

    def target_link_address(self) -> bytes | None:
        return NDPOptions.find(self.options, NDPOptionKind.TARGET_LINK_ADDRESS)


@dataclasses.dataclass(frozen=True)
class NDPRedirect:
    """A Redirect (RFC 4861 §4.5): a better first hop (``target``) for ``destination``."""

    target: IPv6Address
    destination: IPv6Address
    options: bytes = b""

    @classmethod
    def decode(cls, message: ICMPv6Message, header: IPv6Header) -> NDPRedirect:
        """The redirect of ``message``, valid but for its first hop (RFC 4861 §8.1); raises ``Invalid``."""
        target = Library.default().type("umilib_protocol_ip_IPv6Address")()
        destination = Library.default().type("umilib_protocol_ip_IPv6Address")()
        offset = ctypes.c_size_t()
        Library.default().call(
            f"{P}_ndp_redirect_decode", message.header_structure(), *Bytes.readable(message.body), ctypes.byref(header.to_structure()),
            ctypes.byref(target), ctypes.byref(destination), ctypes.byref(offset),
        )  # fmt: skip
        return cls(IPv6Address.from_structure(target), IPv6Address.from_structure(destination), message.body[offset.value :])

    def encode(self, source: IPv6Address, destination: IPv6Address) -> bytes:
        return Library.default().output(
            f"{P}_ndp_redirect_encode", self.target.to_structure(), self.destination.to_structure(), *Bytes.readable(self.options),
            source.to_structure(), destination.to_structure(),
        )  # fmt: skip

    def target_link_address(self) -> bytes | None:
        return NDPOptions.find(self.options, NDPOptionKind.TARGET_LINK_ADDRESS)


@dataclasses.dataclass(frozen=True)
class NeighborConfig:
    """The parameters of a :class:`NeighborCache` (RFC 4861 §10)."""

    reachable_time: datetime.timedelta = datetime.timedelta(seconds=30)
    retransmission_timer: datetime.timedelta = datetime.timedelta(seconds=1)
    delay_first_probe_time: datetime.timedelta = datetime.timedelta(seconds=5)
    maximum_multicast_solicitations: int = 3
    maximum_unicast_solicitations: int = 3
    maximum_entries: int = 512
    maximum_queued: int = 1

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_NeighborConfig")()
        for name in ("reachable_time", "retransmission_timer", "delay_first_probe_time"):
            Fields.assign(structure, name, Nanoseconds.from_timedelta(getattr(self, name)))
        for name in ("maximum_multicast_solicitations", "maximum_unicast_solicitations", "maximum_entries", "maximum_queued"):
            Fields.assign(structure, name, getattr(self, name))
        return structure


class NeighborState(enum.IntEnum):
    """The reachability state of a neighbor (RFC 4861 §7.3.2)."""

    INCOMPLETE = 0
    REACHABLE = 1
    STALE = 2
    DELAY = 3
    PROBE = 4


class NeighborResolution(enum.IntEnum):
    """The kind of answer of :meth:`NeighborCache.resolve`."""

    RESOLVED = 0
    SOLICIT = 1
    PENDING = 2


@dataclasses.dataclass(frozen=True)
class NeighborReception:
    """What a received message did to one neighbor: the packets kept for it, now resolved, and
    whether it was a router and no longer is (remove it from the Default Router List, RFC 4861 §7.2.5)."""

    packets: list[bytes]
    no_longer_router: bool


class NeighborPackets(Handle):
    """Packets the neighbor cache gives back."""

    FREE = f"{P}_neighbor_packets_free"

    def __iter__(self) -> Iterator[bytes]:
        count = self.library.value(f"{P}_neighbor_packets_count", ctypes.c_size_t, self.handle)
        for index in range(count):
            yield self.library.output(f"{P}_neighbor_packets_get", self.handle, index)

    def list(self) -> list[bytes]:
        return list(self)

    @staticmethod
    def collect(pointer: int | None) -> list[bytes]:
        """The packets of the handle ``pointer``, which is released."""
        with NeighborPackets(pointer) as packets:
            return packets.list()


class NeighborEvent(Handle):
    """What :meth:`NeighborCache.poll` reports: a solicitation to send (``kind`` :attr:`SOLICIT`,
    multicast if ``link`` is ``None``) or a neighbor that did not answer (:attr:`UNREACHABLE`)."""

    FREE = f"{P}_neighbor_event_free"
    SOLICIT: ClassVar[int] = 1
    UNREACHABLE: ClassVar[int] = 2

    def fields(self) -> tuple[int, IPv6Address, bytes | None]:
        kind, unicast, link = ctypes.c_uint8(), ctypes.c_bool(), (ctypes.c_uint8 * 6)()
        target = self.library.type("umilib_protocol_ip_IPv6Address")()
        self.library.call(f"{P}_neighbor_event_target", self.handle, ctypes.byref(kind), ctypes.byref(target), ctypes.byref(unicast), link)
        return kind.value, IPv6Address.from_structure(target), (bytes(link) if unicast.value else None)

    @property
    def kind(self) -> int:
        return self.fields()[0]

    @property
    def target(self) -> IPv6Address:
        return self.fields()[1]

    @property
    def link(self) -> bytes | None:
        return self.fields()[2]

    @property
    def packets(self) -> list[bytes]:
        pointer = ctypes.c_void_p()
        self.library.call(f"{P}_neighbor_event_packets", self.handle, ctypes.byref(pointer))
        return NeighborPackets.collect(pointer.value)


class NeighborCache(Handle):
    """The Neighbor Cache of RFC 4861 §5.1 and its reachability state machine (§7.3, Appendix C) for
    6-byte link-layer addresses, without I/O."""

    FREE = f"{P}_neighbor_cache_free"

    def __init__(self, config: NeighborConfig = NeighborConfig()) -> None:
        super().__init__(Handle.create(f"{P}_neighbor_cache_new", config.to_structure()))
        self.config = config

    def resolve(self, address: IPv6Address, packet: bytes | None, now: int) -> tuple[NeighborResolution, bytes | None]:
        """The link-layer address to send to ``address`` at ``now``, or the start or wait of its
        resolution; ``packet`` is kept until it ends. Raises ``Limit``."""
        kind, link = ctypes.c_uint8(), (ctypes.c_uint8 * 6)()
        data, length = (None, 0) if packet is None else (bytes(packet), len(packet))
        self.library.call(f"{P}_neighbor_cache_resolve", self.handle, address.to_structure(), data, length, now, ctypes.byref(kind), link)
        resolution = NeighborResolution(kind.value)
        return resolution, (bytes(link) if resolution == NeighborResolution.RESOLVED else None)

    def lookup(self, address: IPv6Address) -> tuple[bytes, NeighborState] | None:
        found, state, link = ctypes.c_bool(), ctypes.c_uint8(), (ctypes.c_uint8 * 6)()
        self.library.call(f"{P}_neighbor_cache_lookup", self.handle, address.to_structure(), ctypes.byref(found), ctypes.byref(state), link)
        return (bytes(link), NeighborState(state.value)) if found.value else None

    def confirm(self, address: IPv6Address, now: int) -> None:
        """A confirmation from an upper layer that ``address`` is reachable (RFC 4861 §7.3.1)."""
        self.library.call(f"{P}_neighbor_cache_confirm", self.handle, address.to_structure(), now)

    def receive_advertisement(self, advertisement: NDPNeighborAdvertisement, now: int) -> NeighborReception:
        """Processes a valid Neighbor Advertisement (RFC 4861 §7.2.5)."""
        pointer, no_longer_router = ctypes.c_void_p(), ctypes.c_bool()
        self.library.call(
            f"{P}_neighbor_cache_receive_advertisement", self.handle, ctypes.byref(advertisement.to_structure()),
            *Bytes.readable(advertisement.options), now, ctypes.byref(pointer), ctypes.byref(no_longer_router),
        )  # fmt: skip
        return NeighborReception(NeighborPackets.collect(pointer.value), no_longer_router.value)

    def learn(self, address: IPv6Address, link: bytes | None, router: bool | None, now: int) -> NeighborReception:
        """Learns what a Neighbor or Router Solicitation, Router Advertisement or Redirect says of
        ``address``: its link-layer address, if given, and whether it is a router (``True`` for a
        Router Advertisement, ``False`` for a Router Solicitation, ``None`` for no indication)."""
        if link is not None and len(link) != 6:
            raise ValueError("a link-layer address has 6 bytes here")
        pointer, no_longer_router = ctypes.c_void_p(), ctypes.c_bool()
        code = 0 if router is None else (2 if router else 1)
        data = None if link is None else bytes(link)
        self.library.call(
            f"{P}_neighbor_cache_learn", self.handle, address.to_structure(), data, code, now, ctypes.byref(pointer), ctypes.byref(no_longer_router)
        )
        return NeighborReception(NeighborPackets.collect(pointer.value), no_longer_router.value)

    def remove(self, address: IPv6Address) -> bool:
        return self.library.value(f"{P}_neighbor_cache_remove", ctypes.c_bool, self.handle, address.to_structure())

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_neighbor_cache_poll_timeout", ctypes.c_uint64, self.handle)

    def poll(self, now: int) -> NeighborEvent | None:
        """Advances the cache to ``now``; returns the next solicitation to send or neighbor that did not answer."""
        found, pointer = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call(f"{P}_neighbor_cache_poll", self.handle, now, ctypes.byref(found), ctypes.byref(pointer))
        return NeighborEvent(pointer.value) if found.value else None


__all__ = [
    "ICMPv6Code",
    "ICMPv6Message",
    "ICMPv6Type",
    "NDPMessage",
    "NDPNeighborAdvertisement",
    "NDPNeighborSolicitation",
    "NDPOption",
    "NDPOptionKind",
    "NDPOptions",
    "NDPPreference",
    "NDPPrefixInformation",
    "NDPRecursiveDNSServers",
    "NDPRedirect",
    "NDPRouteInformation",
    "NDPRouterAdvertisement",
    "NDPRouterSolicitation",
    "NeighborCache",
    "NeighborConfig",
    "NeighborEvent",
    "NeighborPackets",
    "NeighborReception",
    "NeighborResolution",
    "NeighborState",
]
