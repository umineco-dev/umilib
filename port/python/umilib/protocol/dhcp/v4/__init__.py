"""DHCP for IPv4 (RFC 2131, RFC 2132): the message of BOOTP's header and its options, long options (RFC
3396) and overload, classless static routes (RFC 3442), the client identifier of RFC 4361 echoed by
servers (RFC 6842), a client of every state of RFC 2131 §4.4 and a server of an address pool. Mirrors
``umilib::protocol::dhcp::v4``.

A :class:`DHCPv4Client` and a :class:`DHCPv4Server` do no I/O: give them each message that arrives with
``receive``, send what they return, and call ``expire`` at ``poll_timeout``. ``now`` is nanoseconds of a
monotonic clock. The methods that draw randomness (transaction IDs, the jitter of retransmissions) take a
generator of :mod:`umilib.crypto.random`, as ``random``. Errors are :class:`umilib.protocol.dhcp.DHCPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, Fields, Handle, Library
from umilib.protocol.dhcp import DHCPTime
from umilib.protocol.ethernet import MACAddress
from umilib.protocol.ip import IPv4Address


__all__ = [
    "DHCPv4Binding",
    "DHCPv4BindingState",
    "DHCPv4Client",
    "DHCPv4ClientConfig",
    "DHCPv4ClientEvent",
    "DHCPv4ClientEventKind",
    "DHCPv4ClientState",
    "DHCPv4Lease",
    "DHCPv4Message",
    "DHCPv4MessageType",
    "DHCPv4OptionCode",
    "DHCPv4Options",
    "DHCPv4Reply",
    "DHCPv4Route",
    "DHCPv4Server",
    "DHCPv4ServerConfig",
    "DHCPv4Transmission",
]


class DHCPv4OptionCode(int):
    """The code of a DHCPv4 option (RFC 2132, IANA's BOOTP and DHCP parameters)."""

    PAD: ClassVar[DHCPv4OptionCode]
    SUBNET_MASK: ClassVar[DHCPv4OptionCode]
    ROUTER: ClassVar[DHCPv4OptionCode]
    DOMAIN_NAME_SERVER: ClassVar[DHCPv4OptionCode]
    HOST_NAME: ClassVar[DHCPv4OptionCode]
    DOMAIN_NAME: ClassVar[DHCPv4OptionCode]
    INTERFACE_MTU: ClassVar[DHCPv4OptionCode]
    BROADCAST_ADDRESS: ClassVar[DHCPv4OptionCode]
    NTP_SERVERS: ClassVar[DHCPv4OptionCode]
    VENDOR_SPECIFIC: ClassVar[DHCPv4OptionCode]
    REQUESTED_ADDRESS: ClassVar[DHCPv4OptionCode]
    LEASE_TIME: ClassVar[DHCPv4OptionCode]
    OVERLOAD: ClassVar[DHCPv4OptionCode]
    MESSAGE_TYPE: ClassVar[DHCPv4OptionCode]
    SERVER_IDENTIFIER: ClassVar[DHCPv4OptionCode]
    PARAMETER_REQUEST_LIST: ClassVar[DHCPv4OptionCode]
    MESSAGE: ClassVar[DHCPv4OptionCode]
    MAXIMUM_MESSAGE_SIZE: ClassVar[DHCPv4OptionCode]
    RENEWAL_TIME: ClassVar[DHCPv4OptionCode]
    REBINDING_TIME: ClassVar[DHCPv4OptionCode]
    VENDOR_CLASS_IDENTIFIER: ClassVar[DHCPv4OptionCode]
    CLIENT_IDENTIFIER: ClassVar[DHCPv4OptionCode]
    RAPID_COMMIT: ClassVar[DHCPv4OptionCode]
    RELAY_AGENT_INFORMATION: ClassVar[DHCPv4OptionCode]
    IPV6_ONLY_PREFERRED: ClassVar[DHCPv4OptionCode]
    CAPTIVE_PORTAL: ClassVar[DHCPv4OptionCode]
    DOMAIN_SEARCH: ClassVar[DHCPv4OptionCode]
    CLASSLESS_STATIC_ROUTE: ClassVar[DHCPv4OptionCode]
    END: ClassVar[DHCPv4OptionCode]

    def __new__(cls, code: int) -> DHCPv4OptionCode:
        if not 0 <= code <= 255:
            raise ValueError("a DHCPv4 option code is 0 to 255")
        return super().__new__(cls, code)


for _name, _code in (
    ("PAD", 0), ("SUBNET_MASK", 1), ("ROUTER", 3), ("DOMAIN_NAME_SERVER", 6), ("HOST_NAME", 12), ("DOMAIN_NAME", 15),
    ("INTERFACE_MTU", 26), ("BROADCAST_ADDRESS", 28), ("NTP_SERVERS", 42), ("VENDOR_SPECIFIC", 43),
    ("REQUESTED_ADDRESS", 50), ("LEASE_TIME", 51), ("OVERLOAD", 52), ("MESSAGE_TYPE", 53), ("SERVER_IDENTIFIER", 54),
    ("PARAMETER_REQUEST_LIST", 55), ("MESSAGE", 56), ("MAXIMUM_MESSAGE_SIZE", 57), ("RENEWAL_TIME", 58),
    ("REBINDING_TIME", 59), ("VENDOR_CLASS_IDENTIFIER", 60), ("CLIENT_IDENTIFIER", 61), ("RAPID_COMMIT", 80),
    ("RELAY_AGENT_INFORMATION", 82), ("IPV6_ONLY_PREFERRED", 108), ("CAPTIVE_PORTAL", 114), ("DOMAIN_SEARCH", 119),
    ("CLASSLESS_STATIC_ROUTE", 121), ("END", 255),
):  # fmt: skip
    setattr(DHCPv4OptionCode, _name, DHCPv4OptionCode(_code))


class DHCPv4MessageType(int):
    """The type of a DHCPv4 message (RFC 2132 §9.6)."""

    DISCOVER: ClassVar[DHCPv4MessageType]
    OFFER: ClassVar[DHCPv4MessageType]
    REQUEST: ClassVar[DHCPv4MessageType]
    DECLINE: ClassVar[DHCPv4MessageType]
    ACK: ClassVar[DHCPv4MessageType]
    NAK: ClassVar[DHCPv4MessageType]
    RELEASE: ClassVar[DHCPv4MessageType]
    INFORM: ClassVar[DHCPv4MessageType]

    def __new__(cls, kind: int) -> DHCPv4MessageType:
        if not 0 <= kind <= 255:
            raise ValueError("a DHCPv4 message type is 0 to 255")
        return super().__new__(cls, kind)


for _name, _code in (("DISCOVER", 1), ("OFFER", 2), ("REQUEST", 3), ("DECLINE", 4), ("ACK", 5), ("NAK", 6), ("RELEASE", 7), ("INFORM", 8)):
    setattr(DHCPv4MessageType, _name, DHCPv4MessageType(_code))


@dataclasses.dataclass(frozen=True)
class DHCPv4Route:
    """A route of the classless static route option (RFC 3442 §2): the destination and its prefix length,
    and the router."""

    destination: IPv4Address
    prefix: int
    router: IPv4Address

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Route")()
        structure.destination = self.destination.to_structure()
        Fields.assign(structure, "prefix", self.prefix)
        structure.router = self.router.to_structure()
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> DHCPv4Route:
        return cls(IPv4Address.from_structure(structure.destination), structure.prefix, IPv4Address.from_structure(structure.router))


@dataclasses.dataclass
class DHCPv4Options:
    """The options of a DHCPv4 message, each code once, in the order first seen; an option given in
    several parts is their concatenation (RFC 3396 §7)."""

    #: The time of infinity (0xFFFFFFFF seconds) that :meth:`time` returns.
    INFINITY: ClassVar[datetime.timedelta] = datetime.timedelta.max

    entries: list[tuple[DHCPv4OptionCode, bytes]] = dataclasses.field(default_factory=list)

    @classmethod
    def new(cls) -> DHCPv4Options:
        return cls()

    @classmethod
    def decode(cls, area: bytes | bytearray | memoryview) -> DHCPv4Options:
        """The options of the options area ``area``; raises ``Malformed`` for an option cut short."""
        options = cls()
        options.decode_area(area)
        return options

    def decode_area(self, area: bytes | bytearray | memoryview) -> None:
        """Adds the options of ``area`` (RFC 2132 §2): PAD alone, END ends it, any other a code, a length
        and the data. Raises ``Malformed`` for an option cut short."""
        normalized = Library.default().output("umilib_protocol_dhcp_v4_dhcpv4_options_decode", *Bytes.readable(area))
        index = 0
        while normalized[index] != DHCPv4OptionCode.END:
            length = normalized[index + 1]
            self.append(DHCPv4OptionCode(normalized[index]), normalized[index + 2 : index + 2 + length])
            index += 2 + length

    def append(self, code: int, data: bytes) -> None:
        """Appends ``data`` to the option ``code`` (RFC 3396 §7)."""
        for index, (found, existing) in enumerate(self.entries):
            if found == code:
                self.entries[index] = (found, existing + bytes(data))
                return
        self.entries.append((DHCPv4OptionCode(code), bytes(data)))

    def encode(self) -> bytes:
        """The options area: each option of more than 255 bytes in parts of at most 255 (RFC 3396 §6), and END."""
        area = bytearray()
        for code, data in self.entries:
            if code in (DHCPv4OptionCode.PAD, DHCPv4OptionCode.END):
                raise ValueError("PAD and END are not options of data")
            if not data:
                area += bytes([code, 0])
            for start in range(0, len(data), 255):
                part = data[start : start + 255]
                area += bytes([code, len(part)]) + part
        area.append(DHCPv4OptionCode.END)
        return Library.default().output("umilib_protocol_dhcp_v4_dhcpv4_options_decode", *Bytes.readable(bytes(area)))

    def get(self, code: int) -> bytes | None:
        return next((data for found, data in self.entries if found == code), None)

    def set(self, code: int, data: bytes) -> None:
        """Sets the option ``code``, replacing it if there is one."""
        for index, (found, _) in enumerate(self.entries):
            if found == code:
                self.entries[index] = (found, bytes(data))
                return
        self.entries.append((DHCPv4OptionCode(code), bytes(data)))

    def remove(self, code: int) -> None:
        self.entries = [(found, data) for found, data in self.entries if found != code]

    def message_type(self) -> DHCPv4MessageType | None:
        data = self.get(DHCPv4OptionCode.MESSAGE_TYPE)
        return DHCPv4MessageType(data[0]) if data is not None and len(data) == 1 else None

    def address(self, code: int) -> IPv4Address | None:
        """The address of a 4-byte option."""
        data = self.get(code)
        return IPv4Address(data) if data is not None and len(data) == 4 else None

    def addresses(self, code: int) -> list[IPv4Address]:
        """The addresses of an option of a list of them (RFC 2132 §3.5, §3.8)."""
        data = self.get(code) or b""
        if len(data) % 4:
            return []
        return [IPv4Address(data[index : index + 4]) for index in range(0, len(data), 4)]

    def set_address(self, code: int, address: IPv4Address) -> None:
        self.set(code, address.octets)

    def set_addresses(self, code: int, addresses: list[IPv4Address]) -> None:
        self.set(code, b"".join(address.octets for address in addresses))

    def time(self, code: int) -> datetime.timedelta | None:
        """A time of seconds (RFC 2132 §9.2, §9.11, §9.12; RFC 8925 §3.1): :attr:`INFINITY` for 0xFFFFFFFF,
        ``None`` if there is none of 4 bytes."""
        data = self.get(code)
        if data is None or len(data) != 4:
            return None
        seconds = int.from_bytes(data, "big")
        return DHCPv4Options.INFINITY if seconds == 0xFFFF_FFFF else datetime.timedelta(seconds=seconds)

    def set_time(self, code: int, time: datetime.timedelta | None) -> None:
        """Sets a time of seconds; ``None`` or :attr:`INFINITY` for infinity."""
        if time is None or time == DHCPv4Options.INFINITY:
            seconds = 0xFFFF_FFFF
        else:
            seconds = min(int(time.total_seconds()), 0xFFFF_FFFE)
        self.set(code, seconds.to_bytes(4, "big"))

    def maximum_message_size(self) -> int | None:
        """The largest message the sender takes (RFC 2132 §9.10): at least 576."""
        data = self.get(DHCPv4OptionCode.MAXIMUM_MESSAGE_SIZE)
        size = int.from_bytes(data, "big") if data is not None and len(data) == 2 else None
        return size if size is not None and size >= 576 else None

    def routes(self) -> list[DHCPv4Route]:
        """The routes of the classless static route option (RFC 3442 §2); raises ``Malformed`` for one cut
        short or of a prefix longer than 32. A client given this option ignores the Router option."""
        area = self.encode()
        capacity = len(area) // 5 + 1
        routes = (Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Route") * capacity)()
        count = ctypes.c_size_t()
        Library.default().call("umilib_protocol_dhcp_v4_dhcpv4_options_routes", *Bytes.readable(area), routes, capacity, ctypes.byref(count))
        return [DHCPv4Route.from_structure(routes[index]) for index in range(count.value)]

    def set_routes(self, routes: list[DHCPv4Route]) -> None:
        """Sets the classless static route option; the bits of a destination beyond its prefix are not sent."""
        array = (Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Route") * max(len(routes), 1))(*[route.to_structure() for route in routes])
        area = Library.default().output("umilib_protocol_dhcp_v4_dhcpv4_options_set_routes", *Bytes.readable(self.encode()), array, len(routes))
        self.set(DHCPv4OptionCode.CLASSLESS_STATIC_ROUTE, DHCPv4Options.decode(area).get(DHCPv4OptionCode.CLASSLESS_STATIC_ROUTE) or b"")


@dataclasses.dataclass
class DHCPv4Message:
    """A DHCPv4 message (RFC 2131 §2): the BOOTP header and the options after the magic cookie. Options that
    overload ``sname`` and ``file`` (RFC 2132 §9.3) are read into the options, and those fields left zero."""

    BOOTREQUEST: ClassVar[int] = 1
    BOOTREPLY: ClassVar[int] = 2
    #: The flag asking for broadcast replies (RFC 2131 §2, figure 2).
    BROADCAST: ClassVar[int] = 0x8000
    #: The magic cookie before the options (RFC 2131 §3).
    MAGIC: ClassVar[bytes] = bytes([99, 130, 83, 99])
    HEADER_LENGTH: ClassVar[int] = 236
    #: The least length of a message, as BOOTP relays expect (RFC 1542 §2.1).
    MINIMUM_LENGTH: ClassVar[int] = 300
    #: The largest message every host takes (RFC 2131 §2).
    MINIMUM_MAXIMUM: ClassVar[int] = 576
    SERVER_PORT: ClassVar[int] = 67
    CLIENT_PORT: ClassVar[int] = 68
    FIELDS: ClassVar[tuple[str, ...]] = ("op", "hardware_type", "hardware_length", "hops", "xid", "secs", "flags")
    ADDRESSES: ClassVar[tuple[str, ...]] = ("ciaddr", "yiaddr", "siaddr", "giaddr")
    ARRAYS: ClassVar[tuple[tuple[str, int], ...]] = (("chaddr", 16), ("sname", 64), ("file", 128))

    op: int = 1
    hardware_type: int = 1
    hardware_length: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: IPv4Address = IPv4Address.UNSPECIFIED
    yiaddr: IPv4Address = IPv4Address.UNSPECIFIED
    siaddr: IPv4Address = IPv4Address.UNSPECIFIED
    giaddr: IPv4Address = IPv4Address.UNSPECIFIED
    chaddr: bytes = bytes(16)
    sname: bytes = bytes(64)
    file: bytes = bytes(128)
    options: DHCPv4Options = dataclasses.field(default_factory=DHCPv4Options)

    @classmethod
    def request(cls, kind: int, hardware: MACAddress, xid: int) -> DHCPv4Message:
        """A client's message of ``kind`` from ``hardware``, of the transaction ``xid``."""
        message = cls(xid=xid, chaddr=hardware.octets + bytes(10))
        message.options.set(DHCPv4OptionCode.MESSAGE_TYPE, bytes([kind]))
        return message

    @classmethod
    def reply(cls, request: DHCPv4Message, kind: int) -> DHCPv4Message:
        """The server's reply of ``kind`` to ``request``: its xid, flags, giaddr and chaddr, and its client
        identifier (RFC 6842 §3)."""
        reply = cls(
            op=DHCPv4Message.BOOTREPLY, hardware_type=request.hardware_type, hardware_length=request.hardware_length,
            xid=request.xid, flags=request.flags, giaddr=request.giaddr, chaddr=request.chaddr,
        )  # fmt: skip
        reply.options.set(DHCPv4OptionCode.MESSAGE_TYPE, bytes([kind]))
        identifier = request.options.get(DHCPv4OptionCode.CLIENT_IDENTIFIER)
        if identifier is not None:
            reply.options.set(DHCPv4OptionCode.CLIENT_IDENTIFIER, identifier)
        return reply

    def to_structure(self) -> Any:
        """The C structure of the header; raises ``OverflowError`` or ``ValueError`` for a field that does not fit."""
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Message")()
        for name in DHCPv4Message.FIELDS:
            Fields.assign(structure, name, getattr(self, name))
        for name in DHCPv4Message.ADDRESSES:
            setattr(structure, name, getattr(self, name).to_structure())
        for name, length in DHCPv4Message.ARRAYS:
            data = bytes(getattr(self, name))
            if len(data) != length:
                raise ValueError(f"{name} is {length} bytes, not {len(data)}")
            ctypes.memmove(getattr(structure, name), data, length)
        return structure

    @classmethod
    def from_structure(cls, structure: Any, options: DHCPv4Options) -> DHCPv4Message:
        values: dict[str, Any] = {name: getattr(structure, name) for name in DHCPv4Message.FIELDS}
        values.update({name: IPv4Address.from_structure(getattr(structure, name)) for name in DHCPv4Message.ADDRESSES})
        values.update({name: bytes(getattr(structure, name)) for name, _ in DHCPv4Message.ARRAYS})
        return cls(**values, options=options)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv4Message:
        """The message of ``data``: options of the options field, then, as the overload option says, of
        ``file``, then of ``sname`` (RFC 2131 §4.1). Raises ``Malformed`` without the magic cookie (BOOTP,
        not DHCP), for one cut short, of another op, or with an option cut short."""
        structure, buffer = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Message")(), Buffer()
        Library.default().call("umilib_protocol_dhcp_v4_dhcpv4_message_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        return cls.from_structure(structure, DHCPv4Options.decode(Library.default().take(buffer)))

    def encode(self) -> bytes:
        """The message, its options after the magic cookie and END, padded to at least 300 bytes (RFC 1542 §2.1)."""
        return Library.default().output("umilib_protocol_dhcp_v4_dhcpv4_message_encode", ctypes.byref(self.to_structure()), *Bytes.readable(self.options.encode()))

    def message_type(self) -> DHCPv4MessageType | None:
        return self.options.message_type()

    def hardware_address(self) -> bytes:
        """The client's hardware address, of ``hardware_length`` bytes."""
        return self.chaddr[: min(self.hardware_length, 16)]

    def is_broadcast(self) -> bool:
        return bool(self.flags & DHCPv4Message.BROADCAST)

    def client_key(self) -> bytes:
        """The key a server knows the client by: its client identifier, or its hardware type and address
        (RFC 2131 §4.2, RFC 4361 §6.1)."""
        return Library.default().output("umilib_protocol_dhcp_v4_dhcpv4_message_client_key", ctypes.byref(self.to_structure()), *Bytes.readable(self.options.encode()))


@dataclasses.dataclass(frozen=True)
class DHCPv4ClientConfig:
    """How a client asks: its hardware address, its client identifier (option 61, RFC 4361 §6.1; ``None``
    to be known by the hardware address), its host name, the options asked for (RFC 2132 §9.8), whether
    replies are to be broadcast (RFC 2131 §4.1), the largest message it takes, the retransmissions before
    an exchange is given up, and whether it can do without IPv4 (RFC 8925 §3.2)."""

    hardware: MACAddress
    client_identifier: bytes | None = None
    host_name: bytes | None = None
    parameters: tuple[int, ...] = (1, 3, 6, 15, 26, 28, 119, 121)
    broadcast: bool = False
    maximum_message_size: int = 1500
    retransmissions: int = 4
    ipv6_only: bool = False

    @classmethod
    def new(cls, hardware: MACAddress) -> DHCPv4ClientConfig:
        return cls(hardware)

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4ClientConfig")()
        structure.hardware = self.hardware.to_structure()
        structure.broadcast = self.broadcast
        structure.ipv6_only = self.ipv6_only
        Fields.assign(structure, "maximum_message_size", self.maximum_message_size)
        Fields.assign(structure, "retransmissions", self.retransmissions)
        return structure


class DHCPv4ClientState(enum.IntEnum):
    """The states of a client (RFC 2131 §4.4, figure 5)."""

    INIT = 0
    SELECTING = 1
    REQUESTING = 2
    REBOOTING = 3
    BOUND = 4
    RENEWING = 5
    REBINDING = 6


@dataclasses.dataclass(frozen=True)
class DHCPv4Lease:
    """An address leased, from a server, with its times (``None`` for infinity): the lease, T1 and T2 (RFC
    2131 §4.4.5), from ``acquired``, when the REQUEST that the ACK answers was sent; and the ACK's options."""

    address: IPv4Address
    server: IPv4Address
    lease: datetime.timedelta | None
    renewal: datetime.timedelta | None
    rebinding: datetime.timedelta | None
    acquired: int
    options: DHCPv4Options

    @classmethod
    def from_structure(cls, structure: Any, options: bytes) -> DHCPv4Lease:
        return cls(
            IPv4Address.from_structure(structure.address), IPv4Address.from_structure(structure.server),
            DHCPTime.from_milliseconds(structure.lease), DHCPTime.from_milliseconds(structure.renewal),
            DHCPTime.from_milliseconds(structure.rebinding), structure.acquired, DHCPv4Options.decode(options),
        )  # fmt: skip

    def at(self, time: datetime.timedelta | None) -> int | None:
        """When the time ``time`` after acquisition comes, in nanoseconds; ``None`` for infinity."""
        if time is None:
            return None
        return self.acquired + (time.days * 86_400 + time.seconds) * 1_000_000_000 + time.microseconds * 1_000


class DHCPv4ClientEventKind(enum.IntEnum):
    BOUND = 0
    REFUSED = 1
    EXPIRED = 2
    UNANSWERED = 3
    IPV6_ONLY = 4


@dataclasses.dataclass(frozen=True)
class DHCPv4ClientEvent:
    """What a client tells: ``BOUND`` with its lease (the client should check that no other host has the
    address, RFC 2131 §4.4.1), ``REFUSED`` (DHCPNAK), ``EXPIRED``, ``UNANSWERED``, or ``IPV6_ONLY`` for the
    time ``wait`` (RFC 8925 §3.2)."""

    kind: DHCPv4ClientEventKind
    lease: DHCPv4Lease | None = None
    wait: datetime.timedelta | None = None


@dataclasses.dataclass(frozen=True)
class DHCPv4Transmission:
    """A message for a client to send, to ``destination`` (255.255.255.255 to broadcast), port 67: its bytes."""

    destination: IPv4Address
    data: bytes

    @property
    def message(self) -> DHCPv4Message:
        return DHCPv4Message.decode(self.data)


class DHCPv4Client:
    """A DHCPv4 client (RFC 2131 §4.4) without I/O."""

    class Object(Handle):
        """The object of umilib behind a client. The client holds it rather than being it: the
        ``release`` of a :class:`Handle` is its lock's, and the client's is the protocol's."""

        FREE = "umilib_protocol_dhcp_v4_dhcpv4_client_free"

    def __init__(self, config: DHCPv4ClientConfig, now: int) -> None:
        parameters = bytes(config.parameters)
        self.object = DHCPv4Client.Object(
            Handle.create(
                "umilib_protocol_dhcp_v4_dhcpv4_client_new", ctypes.byref(config.to_structure()), *DHCPv4Client.optional(config.client_identifier),
                *DHCPv4Client.optional(config.host_name), *Bytes.readable(parameters), now,
            )  # fmt: skip
        )

    @property
    def handle(self) -> Handle:
        """The handle passed to C functions."""
        return self.object

    @property
    def library(self) -> Library:
        return self.object.library

    def close(self) -> None:
        """Releases the object of umilib; using the client afterwards raises ``FFIError``."""
        self.object.close()

    def __enter__(self) -> DHCPv4Client:
        return self

    def __exit__(self, *exception: object) -> None:
        self.object.close()

    @staticmethod
    def optional(data: bytes | None) -> tuple[bytes | None, int]:
        """The pointer and length of ``data``, null for ``None``."""
        return (None, 0) if data is None else (bytes(data), len(data))

    def start(self, previous: IPv4Address | None, now: int, random: Any) -> None:
        """Starts: with ``previous``, an address the client had, by asking for it again (INIT-REBOOT, RFC 2131
        §3.2); else by discovering servers. Raises ``Random`` if ``random`` fails."""
        address = None if previous is None else ctypes.byref(previous.to_structure())
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_start", self.handle, address, now, *random.source())

    def receive(self, data: bytes, now: int, random: Any) -> None:
        """Takes a server's reply; ignored unless it is a reply to the client's exchange, of its hardware
        address and client identifier (RFC 6842 §3), of a type the state expects."""
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_receive", self.handle, *Bytes.readable(data), now, *random.source())

    def transmit(self) -> DHCPv4Transmission | None:
        found, destination, buffer = ctypes.c_bool(), Library.default().type("umilib_protocol_ip_IPv4Address")(), Buffer()
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_transmit", self.handle, ctypes.byref(found), ctypes.byref(destination), ctypes.byref(buffer))
        data = self.library.take(buffer)
        return DHCPv4Transmission(IPv4Address.from_structure(destination), data) if found.value else None

    def poll_timeout(self) -> int | None:
        """When :meth:`expire` is next due, in nanoseconds."""
        return self.library.optional("umilib_protocol_dhcp_v4_dhcpv4_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int, random: Any) -> None:
        """Does what is due at ``now``: a retransmission, giving up an exchange, or the next step of the
        lease — RENEWING at T1, REBINDING at T2, and its end (RFC 2131 §4.4.5)."""
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_expire", self.handle, now, *random.source())

    def poll_event(self) -> DHCPv4ClientEvent | None:
        found, structure, buffer = ctypes.c_bool(), Library.default().type("umilib_protocol_dhcp_v4_DHCPv4ClientEvent")(), Buffer()
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_poll_event", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        options = self.library.take(buffer)
        if not found.value:
            return None
        kind = DHCPv4ClientEventKind(structure.kind)
        lease = DHCPv4Lease.from_structure(structure.lease, options) if kind == DHCPv4ClientEventKind.BOUND else None
        wait = DHCPTime.from_milliseconds(structure.wait) if kind == DHCPv4ClientEventKind.IPV6_ONLY else None
        return DHCPv4ClientEvent(kind, lease, wait)

    @property
    def state(self) -> DHCPv4ClientState:
        return DHCPv4ClientState(self.library.value("umilib_protocol_dhcp_v4_dhcpv4_client_state", ctypes.c_uint8, self.handle))

    @property
    def lease(self) -> DHCPv4Lease | None:
        found, structure, buffer = ctypes.c_bool(), Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Lease")(), Buffer()
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_lease", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        options = self.library.take(buffer)
        return DHCPv4Lease.from_structure(structure, options) if found.value else None

    def decline(self, now: int, random: Any) -> None:
        """Declines the address of the lease, which another host has (RFC 2131 §4.4.1): a DECLINE, then
        discovery again after ten seconds (§3.1.5). Raises ``State`` without a lease."""
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_decline", self.handle, now, *random.source())

    def release(self, now: int) -> None:
        """Gives the address back (RFC 2131 §4.4.6): a RELEASE to the server; the client stops. Raises
        ``State`` without a lease."""
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_client_release", self.handle, now)

    def inform(self, address: IPv4Address, now: int, random: Any) -> DHCPv4Transmission:
        """The DHCPINFORM of a client whose address ``address`` is configured otherwise (RFC 2131 §3.4), of
        an xid of its own: the client's exchange goes on, and the ACK, of that xid, is the caller's to read."""
        destination, buffer = Library.default().type("umilib_protocol_ip_IPv4Address")(), Buffer()
        self.library.call(
            "umilib_protocol_dhcp_v4_dhcpv4_client_inform", self.handle, address.to_structure(), now, *random.source(), ctypes.byref(destination),
            ctypes.byref(buffer),
        )  # fmt: skip
        return DHCPv4Transmission(IPv4Address.from_structure(destination), self.library.take(buffer))


@dataclasses.dataclass(frozen=True)
class DHCPv4ServerConfig:
    """What a server leases and gives: its address (its server identifier, RFC 2132 §9.7), the first and
    last addresses it leases, addresses reserved by client key (:meth:`DHCPv4Message.client_key`), the
    lease time (``None`` for infinity; T1 and T2 are half and seven eighths of it), how long an offered
    address is kept (RFC 2131 §4.3.1) and a declined one not leased (§4.3.3), the options given to every
    client, and whether it refuses a REQUEST for an address it does not know (§4.3.2)."""

    address: IPv4Address
    first: IPv4Address
    last: IPv4Address
    reservations: tuple[tuple[bytes, IPv4Address], ...]
    lease: datetime.timedelta | None
    offer_time: datetime.timedelta
    decline_time: datetime.timedelta
    options: DHCPv4Options
    authoritative: bool

    @classmethod
    def new(cls, address: IPv4Address, first: IPv4Address, last: IPv4Address) -> DHCPv4ServerConfig:
        """A server at ``address`` leasing ``first`` to ``last``, of the defaults of umilib, without
        reservations or options."""
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4ServerConfig")()
        Library.default().call(
            "umilib_protocol_dhcp_v4_dhcpv4_server_config_new", address.to_structure(), first.to_structure(), last.to_structure(), ctypes.byref(structure)
        )
        return cls(
            address, first, last, (), DHCPTime.from_milliseconds(structure.lease), DHCPTime.from_milliseconds(structure.offer_time),
            DHCPTime.from_milliseconds(structure.decline_time), DHCPv4Options(), bool(structure.authoritative),
        )  # fmt: skip

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4ServerConfig")()
        structure.address = self.address.to_structure()
        structure.first = self.first.to_structure()
        structure.last = self.last.to_structure()
        structure.authoritative = self.authoritative
        structure.lease = DHCPTime.to_milliseconds(self.lease)
        structure.offer_time = DHCPTime.to_milliseconds(self.offer_time)
        structure.decline_time = DHCPTime.to_milliseconds(self.decline_time)
        return structure


class DHCPv4BindingState(enum.IntEnum):
    OFFERED = 0
    BOUND = 1
    #: Declined by a client: in use by a host the server does not know.
    DECLINED = 2


@dataclasses.dataclass(frozen=True)
class DHCPv4Binding:
    """An address given: to which client, how, and until when (nanoseconds; ``None`` for ever)."""

    client: bytes
    state: DHCPv4BindingState
    expires: int | None


@dataclasses.dataclass(frozen=True)
class DHCPv4Reply:
    """A reply for a server to send: to ``destination`` and ``port``, and, for a client without an address
    that did not ask for broadcast, to its hardware address ``link`` without ARP (RFC 2131 §4.1); its bytes."""

    destination: IPv4Address
    port: int
    link: MACAddress | None
    data: bytes

    @property
    def message(self) -> DHCPv4Message:
        return DHCPv4Message.decode(self.data)


class DHCPv4Server(Handle):
    """A DHCPv4 server (RFC 2131 §4.3) without I/O: it answers each client message with the reply of its
    rules, from the addresses of its pool. Raises ``Config`` for a pool whose first address is after its last."""

    FREE = "umilib_protocol_dhcp_v4_dhcpv4_server_free"

    def __init__(self, config: DHCPv4ServerConfig) -> None:
        keys, lengths, count, _kept = Bytes.array([key for key, _ in config.reservations])
        address = Library.default().type("umilib_protocol_ip_IPv4Address")
        addresses = (address * max(count, 1))(*[reserved.to_structure() for _, reserved in config.reservations])
        super().__init__(
            Handle.create(
                "umilib_protocol_dhcp_v4_dhcpv4_server_new", ctypes.byref(config.to_structure()), keys, lengths, addresses, count,
                *Bytes.readable(config.options.encode()),
            )  # fmt: skip
        )

    def receive(self, data: bytes, now: int) -> DHCPv4Reply | None:
        """The reply to the message ``data`` from a client at ``now``, if one is due."""
        found, reply, buffer = ctypes.c_bool(), Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Reply")(), Buffer()
        self.library.call(
            "umilib_protocol_dhcp_v4_dhcpv4_server_receive", self.handle, *Bytes.readable(data), now, ctypes.byref(found), ctypes.byref(reply),
            ctypes.byref(buffer),
        )  # fmt: skip
        message = self.library.take(buffer)
        if not found.value:
            return None
        link = MACAddress.from_structure(reply.link) if reply.has_link else None
        return DHCPv4Reply(IPv4Address.from_structure(reply.destination), reply.port, link, message)

    def expire(self, now: int) -> None:
        """Forgets the bindings expired at ``now``, but the leases bound."""
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_server_expire", self.handle, now)

    def binding(self, address: IPv4Address) -> DHCPv4Binding | None:
        """What the server knows of ``address``."""
        found, structure, buffer = ctypes.c_bool(), Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Binding")(), Buffer()
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_server_binding", self.handle, address.to_structure(), ctypes.byref(found), ctypes.byref(structure), ctypes.byref(buffer))
        client = self.library.take(buffer)
        if not found.value:
            return None
        expires = None if structure.expires == DHCPTime.INFINITY else structure.expires
        return DHCPv4Binding(client, DHCPv4BindingState(structure.state), expires)

    @property
    def bindings(self) -> dict[IPv4Address, DHCPv4Binding]:
        """Every binding, by address: the server's state, for its caller to keep."""
        count = self.library.value("umilib_protocol_dhcp_v4_dhcpv4_server_bindings_count", ctypes.c_size_t, self.handle)
        bindings = {}
        for index in range(count):
            address = Library.default().type("umilib_protocol_ip_IPv4Address")()
            structure, buffer = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Binding")(), Buffer()
            self.library.call("umilib_protocol_dhcp_v4_dhcpv4_server_binding_entry", self.handle, index, ctypes.byref(address), ctypes.byref(structure), ctypes.byref(buffer))
            expires = None if structure.expires == DHCPTime.INFINITY else structure.expires
            bindings[IPv4Address.from_structure(address)] = DHCPv4Binding(self.library.take(buffer), DHCPv4BindingState(structure.state), expires)
        return bindings

    def set_binding(self, address: IPv4Address, binding: DHCPv4Binding) -> None:
        """Sets the binding of ``address``: one kept elsewhere, given back."""
        structure = Library.default().type("umilib_protocol_dhcp_v4_DHCPv4Binding")()
        Fields.assign(structure, "state", int(binding.state))
        Fields.assign(structure, "expires", DHCPTime.INFINITY if binding.expires is None else binding.expires)
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_server_set_binding", self.handle, address.to_structure(), structure, *Bytes.readable(binding.client))

    def remove_binding(self, address: IPv4Address) -> None:
        self.library.call("umilib_protocol_dhcp_v4_dhcpv4_server_remove_binding", self.handle, address.to_structure())

