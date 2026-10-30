"""DHCP for IPv6 (RFC 9915): its messages and those of relay agents, the options of addresses (IA_NA) and
prefixes (IA_PD), a client of every exchange of §18.2 and a server of address and prefix pools that
answers relayed messages too. Mirrors ``umilib::protocol::dhcp::v6``.

A :class:`DHCPv6Client` and a :class:`DHCPv6Server` do no I/O: give them each message that arrives with
``receive``, send what they return, and call ``expire`` at ``poll_timeout``. A client's messages go to
:attr:`DHCPv6Message.ALL_RELAY_AGENTS_AND_SERVERS`, port 547. ``now`` is nanoseconds of a monotonic clock.
The methods that draw randomness (transaction IDs, the delays of retransmissions) take a generator of
:mod:`umilib.crypto.random`, as ``random``. Errors are :class:`umilib.protocol.dhcp.DHCPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar, Iterator

from umilib.ffi import Buffer, Bytes, Fields, Handle, Library, Text, Words
from umilib.protocol.dhcp import DHCPDUID, DHCPError, DHCPTime
from umilib.protocol.ip import IPv6Address

P = "umilib_protocol_dhcp_v6"

__all__ = [
    "DHCPv6Client",
    "DHCPv6ClientConfig",
    "DHCPv6ClientEvent",
    "DHCPv6ClientEventKind",
    "DHCPv6ClientState",
    "DHCPv6IA",
    "DHCPv6IAAddress",
    "DHCPv6IAPrefix",
    "DHCPv6Lease",
    "DHCPv6Message",
    "DHCPv6MessageType",
    "DHCPv6Option",
    "DHCPv6OptionCode",
    "DHCPv6Options",
    "DHCPv6RelayMessage",
    "DHCPv6Server",
    "DHCPv6ServerConfig",
    "DHCPv6StatusCode",
]


class DHCPv6MessageType(int):
    """The type of a DHCPv6 message (RFC 9915 §7.3)."""

    SOLICIT: ClassVar[DHCPv6MessageType]
    ADVERTISE: ClassVar[DHCPv6MessageType]
    REQUEST: ClassVar[DHCPv6MessageType]
    CONFIRM: ClassVar[DHCPv6MessageType]
    RENEW: ClassVar[DHCPv6MessageType]
    REBIND: ClassVar[DHCPv6MessageType]
    REPLY: ClassVar[DHCPv6MessageType]
    RELEASE: ClassVar[DHCPv6MessageType]
    DECLINE: ClassVar[DHCPv6MessageType]
    RECONFIGURE: ClassVar[DHCPv6MessageType]
    INFORMATION_REQUEST: ClassVar[DHCPv6MessageType]
    RELAY_FORW: ClassVar[DHCPv6MessageType]
    RELAY_REPL: ClassVar[DHCPv6MessageType]

    def __new__(cls, kind: int) -> DHCPv6MessageType:
        if not 0 <= kind <= 255:
            raise ValueError("a DHCPv6 message type is 0 to 255")
        return super().__new__(cls, kind)

    def is_relay(self) -> bool:
        return self in (DHCPv6MessageType.RELAY_FORW, DHCPv6MessageType.RELAY_REPL)


for _name, _code in (
    ("SOLICIT", 1), ("ADVERTISE", 2), ("REQUEST", 3), ("CONFIRM", 4), ("RENEW", 5), ("REBIND", 6), ("REPLY", 7),
    ("RELEASE", 8), ("DECLINE", 9), ("RECONFIGURE", 10), ("INFORMATION_REQUEST", 11), ("RELAY_FORW", 12), ("RELAY_REPL", 13),
):  # fmt: skip
    setattr(DHCPv6MessageType, _name, DHCPv6MessageType(_code))


class DHCPv6OptionCode(int):
    """The code of a DHCPv6 option (RFC 9915 §24, IANA's DHCPv6 parameters)."""

    CLIENT_ID: ClassVar[DHCPv6OptionCode]
    SERVER_ID: ClassVar[DHCPv6OptionCode]
    IA_NA: ClassVar[DHCPv6OptionCode]
    IA_TA: ClassVar[DHCPv6OptionCode]
    IAADDR: ClassVar[DHCPv6OptionCode]
    ORO: ClassVar[DHCPv6OptionCode]
    PREFERENCE: ClassVar[DHCPv6OptionCode]
    ELAPSED_TIME: ClassVar[DHCPv6OptionCode]
    RELAY_MSG: ClassVar[DHCPv6OptionCode]
    AUTH: ClassVar[DHCPv6OptionCode]
    UNICAST: ClassVar[DHCPv6OptionCode]
    STATUS_CODE: ClassVar[DHCPv6OptionCode]
    RAPID_COMMIT: ClassVar[DHCPv6OptionCode]
    USER_CLASS: ClassVar[DHCPv6OptionCode]
    VENDOR_CLASS: ClassVar[DHCPv6OptionCode]
    VENDOR_OPTS: ClassVar[DHCPv6OptionCode]
    INTERFACE_ID: ClassVar[DHCPv6OptionCode]
    RECONF_MSG: ClassVar[DHCPv6OptionCode]
    RECONF_ACCEPT: ClassVar[DHCPv6OptionCode]
    DNS_SERVERS: ClassVar[DHCPv6OptionCode]
    DOMAIN_LIST: ClassVar[DHCPv6OptionCode]
    IA_PD: ClassVar[DHCPv6OptionCode]
    IAPREFIX: ClassVar[DHCPv6OptionCode]
    INFORMATION_REFRESH_TIME: ClassVar[DHCPv6OptionCode]
    SOL_MAX_RT: ClassVar[DHCPv6OptionCode]
    INF_MAX_RT: ClassVar[DHCPv6OptionCode]

    def __new__(cls, code: int) -> DHCPv6OptionCode:
        if not 0 <= code <= 0xFFFF:
            raise ValueError("a DHCPv6 option code is 0 to 65535")
        return super().__new__(cls, code)


for _name, _code in (
    ("CLIENT_ID", 1), ("SERVER_ID", 2), ("IA_NA", 3), ("IA_TA", 4), ("IAADDR", 5), ("ORO", 6), ("PREFERENCE", 7),
    ("ELAPSED_TIME", 8), ("RELAY_MSG", 9), ("AUTH", 11), ("UNICAST", 12), ("STATUS_CODE", 13), ("RAPID_COMMIT", 14),
    ("USER_CLASS", 15), ("VENDOR_CLASS", 16), ("VENDOR_OPTS", 17), ("INTERFACE_ID", 18), ("RECONF_MSG", 19),
    ("RECONF_ACCEPT", 20), ("DNS_SERVERS", 23), ("DOMAIN_LIST", 24), ("IA_PD", 25), ("IAPREFIX", 26),
    ("INFORMATION_REFRESH_TIME", 32), ("SOL_MAX_RT", 82), ("INF_MAX_RT", 83),
):  # fmt: skip
    setattr(DHCPv6OptionCode, _name, DHCPv6OptionCode(_code))


@dataclasses.dataclass(frozen=True)
class DHCPv6Option:
    """An option: its code and data (RFC 9915 §21.1)."""

    code: DHCPv6OptionCode
    data: bytes


@dataclasses.dataclass
class DHCPv6Options:
    """The options of a message or of an option, in order; a code may repeat (several IA_NA, several IAADDR in one)."""

    entries: list[DHCPv6Option] = dataclasses.field(default_factory=list)

    @classmethod
    def new(cls) -> DHCPv6Options:
        return cls()

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6Options:
        """The options of ``data``: each a code, a length and the data (§21.1); raises ``Malformed`` for one cut short."""
        data, entries, index = bytes(data), [], 0
        while index < len(data):
            if index + 4 > len(data):
                raise DHCPError("protocol.dhcp", "Malformed", "an option cut short")
            length = int.from_bytes(data[index + 2 : index + 4], "big")
            if index + 4 + length > len(data):
                raise DHCPError("protocol.dhcp", "Malformed", "an option cut short")
            entries.append(DHCPv6Option(DHCPv6OptionCode(int.from_bytes(data[index : index + 2], "big")), data[index + 4 : index + 4 + length]))
            index += 4 + length
        return cls(entries)

    def encode(self) -> bytes:
        """Their bytes; raises ``TooLarge`` for an option of more than 65535 bytes."""
        out = bytearray()
        for option in self.entries:
            if len(option.data) > 0xFFFF:
                raise DHCPError("protocol.dhcp", "TooLarge", "a DHCP option too large")
            out += option.code.to_bytes(2, "big") + len(option.data).to_bytes(2, "big") + option.data
        return bytes(out)

    def get(self, code: int) -> bytes | None:
        return next((option.data for option in self.entries if option.code == code), None)

    def all(self, code: int) -> Iterator[bytes]:
        return (option.data for option in self.entries if option.code == code)

    def contains(self, code: int) -> bool:
        return self.get(code) is not None

    def push(self, code: int, data: bytes) -> None:
        """Adds the option ``code``."""
        self.entries.append(DHCPv6Option(DHCPv6OptionCode(code), bytes(data)))

    def set(self, code: int, data: bytes) -> None:
        """Sets the one option ``code``, replacing those there are."""
        self.remove(code)
        self.push(code, data)

    def remove(self, code: int) -> None:
        self.entries = [option for option in self.entries if option.code != code]

    def duid(self, code: int) -> DHCPDUID | None:
        """The DUID of the client or server identifier option ``code``."""
        data = self.get(code)
        if data is None:
            return None
        try:
            return DHCPDUID.decode(data)
        except DHCPError:
            return None

    def status(self) -> DHCPv6StatusCode:
        """The status of the message or option (§21.13); success without one. Raises ``Malformed``."""
        data = self.get(DHCPv6OptionCode.STATUS_CODE)
        return DHCPv6StatusCode(DHCPv6StatusCode.SUCCESS, "") if data is None else DHCPv6StatusCode.decode(data)

    def ias(self, code: int) -> list[DHCPv6IA]:
        """The IAs of type ``code`` (IA_NA or IA_PD) that can be read."""
        found = []
        for data in self.all(code):
            try:
                found.append(DHCPv6IA.decode(code, data))
            except DHCPError:
                pass
        return found

    def addresses(self, code: int) -> list[IPv6Address]:
        """The addresses of an option of a list of them (RFC 3646 §3)."""
        data = self.get(code) or b""
        if len(data) % 16:
            return []
        return [IPv6Address(data[index : index + 16]) for index in range(0, len(data), 16)]

    def requested(self) -> list[DHCPv6OptionCode]:
        """The option codes of the Option Request option (§21.7)."""
        data = self.get(DHCPv6OptionCode.ORO) or b""
        return [DHCPv6OptionCode(int.from_bytes(data[index : index + 2], "big")) for index in range(0, len(data) - 1, 2)]


@dataclasses.dataclass(frozen=True)
class DHCPv6StatusCode:
    """The Status Code option (RFC 9915 §21.13)."""

    SUCCESS: ClassVar[int] = 0
    UNSPEC_FAIL: ClassVar[int] = 1
    NO_ADDRS_AVAIL: ClassVar[int] = 2
    NO_BINDING: ClassVar[int] = 3
    NOT_ON_LINK: ClassVar[int] = 4
    #: Obsolete (RFC 9915 §21.13).
    USE_MULTICAST: ClassVar[int] = 5
    NO_PREFIX_AVAIL: ClassVar[int] = 6

    code: int
    message: str = ""

    @classmethod
    def new(cls, code: int, message: str) -> DHCPv6StatusCode:
        return cls(code, message)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6StatusCode:
        """Two bytes of code, then UTF-8 text; text that is not UTF-8 is replaced. Raises ``Malformed``."""
        code, buffer = ctypes.c_uint16(), Buffer()
        Library.default().call(f"{P}_dhcpv6_status_code_decode", *Bytes.readable(data), ctypes.byref(code), ctypes.byref(buffer))
        return cls(code.value, Library.default().take(buffer).decode("utf-8"))

    def encode(self) -> bytes:
        return Library.default().output(f"{P}_dhcpv6_status_code_encode", self.code, *Text.encode(self.message))


@dataclasses.dataclass
class DHCPv6IAAddress:
    """An IA Address option (RFC 9915 §21.6), its lifetimes in seconds."""

    address: IPv6Address
    preferred: int
    valid: int
    options: DHCPv6Options = dataclasses.field(default_factory=DHCPv6Options)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6IAAddress:
        """Raises ``Malformed`` for data shorter than 24 bytes or an option cut short."""
        structure, buffer = Library.default().type(f"{P}_DHCPv6IAAddress")(), Buffer()
        Library.default().call(f"{P}_dhcpv6_ia_address_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        options = DHCPv6Options.decode(Library.default().take(buffer))
        return cls(IPv6Address.from_structure(structure.address), structure.preferred, structure.valid, options)

    def encode(self) -> bytes:
        structure = Library.default().type(f"{P}_DHCPv6IAAddress")()
        structure.address = self.address.to_structure()
        Fields.assign(structure, "preferred", self.preferred)
        Fields.assign(structure, "valid", self.valid)
        return Library.default().output(f"{P}_dhcpv6_ia_address_encode", structure, *Bytes.readable(self.options.encode()))


@dataclasses.dataclass
class DHCPv6IAPrefix:
    """An IA Prefix option (RFC 9915 §21.22), its lifetimes in seconds."""

    preferred: int
    valid: int
    length: int
    prefix: IPv6Address
    options: DHCPv6Options = dataclasses.field(default_factory=DHCPv6Options)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6IAPrefix:
        """Raises ``Malformed`` for data shorter than 25 bytes, a prefix longer than 128 bits or an option cut short."""
        structure, buffer = Library.default().type(f"{P}_DHCPv6IAPrefix")(), Buffer()
        Library.default().call(f"{P}_dhcpv6_ia_prefix_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        options = DHCPv6Options.decode(Library.default().take(buffer))
        return cls(structure.preferred, structure.valid, structure.length, IPv6Address.from_structure(structure.prefix), options)

    def encode(self) -> bytes:
        """Raises ``Malformed`` for a prefix longer than 128 bits."""
        structure = Library.default().type(f"{P}_DHCPv6IAPrefix")()
        Fields.assign(structure, "preferred", self.preferred)
        Fields.assign(structure, "valid", self.valid)
        Fields.assign(structure, "length", self.length)
        structure.prefix = self.prefix.to_structure()
        return Library.default().output(f"{P}_dhcpv6_ia_prefix_encode", structure, *Bytes.readable(self.options.encode()))


@dataclasses.dataclass
class DHCPv6IA:
    """An Identity Association of addresses (IA_NA, §21.4) or prefixes (IA_PD, §21.21): T1 and T2 in
    seconds, 0 to let the client choose, :attr:`INFINITY` for infinity (§7.7)."""

    INFINITY: ClassVar[int] = 0xFFFF_FFFF

    kind: DHCPv6OptionCode
    iaid: int
    t1: int = 0
    t2: int = 0
    options: DHCPv6Options = dataclasses.field(default_factory=DHCPv6Options)

    @classmethod
    def new(cls, kind: int, iaid: int) -> DHCPv6IA:
        return cls(DHCPv6OptionCode(kind), iaid)

    @classmethod
    def decode(cls, kind: int, data: bytes | bytearray | memoryview) -> DHCPv6IA:
        """The IA of the option ``kind`` of ``data``; raises ``Malformed`` for data shorter than 12 bytes or an option cut short."""
        structure, buffer = Library.default().type(f"{P}_DHCPv6IA")(), Buffer()
        Library.default().call(f"{P}_dhcpv6_ia_decode", kind, *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        options = DHCPv6Options.decode(Library.default().take(buffer))
        return cls(DHCPv6OptionCode(structure.kind), structure.iaid, structure.t1, structure.t2, options)

    def encode(self) -> DHCPv6Option:
        structure = Library.default().type(f"{P}_DHCPv6IA")()
        for name in ("kind", "iaid", "t1", "t2"):
            Fields.assign(structure, name, getattr(self, name))
        data = Library.default().output(f"{P}_dhcpv6_ia_encode", structure, *Bytes.readable(self.options.encode()))
        return DHCPv6Option(DHCPv6OptionCode(self.kind), data)

    def addresses(self) -> list[DHCPv6IAAddress]:
        return [DHCPv6IAAddress.decode(data) for data in self.options.all(DHCPv6OptionCode.IAADDR)]

    def prefixes(self) -> list[DHCPv6IAPrefix]:
        return [DHCPv6IAPrefix.decode(data) for data in self.options.all(DHCPv6OptionCode.IAPREFIX)]

    def lifetimes(self) -> list[tuple[int, int]]:
        """The lifetimes of what the IA holds, preferred and valid: of its addresses or prefixes."""
        held: list[DHCPv6IAAddress | DHCPv6IAPrefix] = [*self.addresses(), *self.prefixes()]
        return [(item.preferred, item.valid) for item in held]


@dataclasses.dataclass
class DHCPv6Message:
    """A message between a client and a server (RFC 9915 §8): its type, its transaction ID of 24 bits, and its options."""

    CLIENT_PORT: ClassVar[int] = 546
    SERVER_PORT: ClassVar[int] = 547
    #: All_DHCP_Relay_Agents_and_Servers, ff02::1:2 (§7.1).
    ALL_RELAY_AGENTS_AND_SERVERS: ClassVar[IPv6Address] = IPv6Address(bytes([0xFF, 2] + [0] * 11 + [1, 0, 2]))

    kind: DHCPv6MessageType
    transaction: int
    options: DHCPv6Options = dataclasses.field(default_factory=DHCPv6Options)

    @classmethod
    def new(cls, kind: int, transaction: int) -> DHCPv6Message:
        return cls(DHCPv6MessageType(kind), transaction & 0xFF_FFFF)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6Message:
        """Raises ``Malformed`` for one shorter than 4 bytes, of a relay agent's type, or with an option cut short."""
        structure, buffer = Library.default().type(f"{P}_DHCPv6Message")(), Buffer()
        Library.default().call(f"{P}_dhcpv6_message_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        return cls(DHCPv6MessageType(structure.kind), structure.transaction, DHCPv6Options.decode(Library.default().take(buffer)))

    def encode(self) -> bytes:
        """Raises ``Malformed`` for a relay agent's type or a transaction ID of more than 24 bits."""
        structure = Library.default().type(f"{P}_DHCPv6Message")()
        Fields.assign(structure, "kind", self.kind)
        Fields.assign(structure, "transaction", self.transaction)
        return Library.default().output(f"{P}_dhcpv6_message_encode", structure, *Bytes.readable(self.options.encode()))


@dataclasses.dataclass
class DHCPv6RelayMessage:
    """A message of relay agents (RFC 9915 §9): its type, hop count, link and peer addresses, and options,
    one of which carries the relayed message."""

    #: The most hops a Relay-forward may have made (§7.6: HOP_COUNT_LIMIT).
    HOP_COUNT_LIMIT: ClassVar[int] = 8

    kind: DHCPv6MessageType
    hops: int
    link: IPv6Address
    peer: IPv6Address
    options: DHCPv6Options = dataclasses.field(default_factory=DHCPv6Options)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPv6RelayMessage:
        """Raises ``Malformed`` for one shorter than 34 bytes, of a type of no relay agent, or with an option cut short."""
        structure, buffer = Library.default().type(f"{P}_DHCPv6RelayMessage")(), Buffer()
        Library.default().call(f"{P}_dhcpv6_relay_message_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        options = DHCPv6Options.decode(Library.default().take(buffer))
        return cls(
            DHCPv6MessageType(structure.kind), structure.hops, IPv6Address.from_structure(structure.link),
            IPv6Address.from_structure(structure.peer), options,
        )  # fmt: skip

    def encode(self) -> bytes:
        """Raises ``Malformed`` for a type of no relay agent."""
        structure = Library.default().type(f"{P}_DHCPv6RelayMessage")()
        Fields.assign(structure, "kind", self.kind)
        Fields.assign(structure, "hops", self.hops)
        structure.link = self.link.to_structure()
        structure.peer = self.peer.to_structure()
        return Library.default().output(f"{P}_dhcpv6_relay_message_encode", ctypes.byref(structure), *Bytes.readable(self.options.encode()))

    def relayed(self) -> bytes | None:
        """The message relayed (the Relay Message option, §21.10)."""
        return self.options.get(DHCPv6OptionCode.RELAY_MSG)


@dataclasses.dataclass(frozen=True)
class DHCPv6ClientConfig:
    """How a client asks: its DUID, the IAID of its IA_NA and IA_PD (RFC 9915 §12), whether it asks for
    addresses (IA_NA) and for a prefix (IA_PD) — of ``prefix_length`` bits as a hint unless ``None`` —, the
    options asked for (§21.7), and whether it takes a Reply to its Solicit (§18.2.1, Rapid Commit). The
    ``prefix`` of Rust, ``Option<Option<u8>>``, is here ``prefix`` and ``prefix_length``."""

    duid: DHCPDUID
    iaid: int
    addresses: bool = True
    prefix: bool = False
    prefix_length: int | None = None
    requested: tuple[int, ...] = (23, 24, 82)
    rapid_commit: bool = False

    @classmethod
    def new(cls, duid: DHCPDUID, iaid: int) -> DHCPv6ClientConfig:
        return cls(duid, iaid)

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_DHCPv6ClientConfig")()
        Fields.assign(structure, "iaid", self.iaid)
        structure.addresses = self.addresses
        structure.prefix = self.prefix
        structure.prefix_hint = self.prefix_length is not None
        Fields.assign(structure, "prefix_length", self.prefix_length or 0)
        structure.rapid_commit = self.rapid_commit
        return structure


class DHCPv6ClientState(enum.IntEnum):
    """The exchanges of a client (RFC 9915 §18.2)."""

    INIT = 0
    SOLICITING = 1
    REQUESTING = 2
    BOUND = 3
    RENEWING = 4
    REBINDING = 5
    CONFIRMING = 6
    RELEASING = 7
    DECLINING = 8
    INFORMING = 9
    #: Stateless, configured, until it refreshes (§18.2.12).
    INFORMED = 10


@dataclasses.dataclass(frozen=True)
class DHCPv6Lease:
    """The bindings of a client from a server: its IAs, the options of the Reply, when the exchange began
    (``acquired``, nanoseconds), from which the times run, and when to Renew and Rebind (§18.2.4, §18.2.5)
    and when the last of its addresses and prefixes is no longer valid; ``None`` for infinity."""

    server: DHCPDUID
    ias: list[DHCPv6IA]
    options: DHCPv6Options
    acquired: int
    renewal: datetime.timedelta | None
    rebinding: datetime.timedelta | None
    valid: datetime.timedelta | None

    @classmethod
    def from_structure(cls, structure: Any, ias: bytes, options: bytes, server: bytes) -> DHCPv6Lease:
        read = DHCPv6Options.decode(ias)
        return cls(
            DHCPDUID.decode(server), [DHCPv6IA.decode(option.code, option.data) for option in read.entries],
            DHCPv6Options.decode(options), structure.acquired, DHCPTime.from_milliseconds(structure.renewal),
            DHCPTime.from_milliseconds(structure.rebinding), DHCPTime.from_milliseconds(structure.valid),
        )  # fmt: skip

    def at(self, time: datetime.timedelta | None) -> int | None:
        """When the time ``time`` after acquisition comes, in nanoseconds; ``None`` for infinity."""
        if time is None:
            return None
        return self.acquired + (time.days * 86_400 + time.seconds) * 1_000_000_000 + time.microseconds * 1_000

    def addresses(self) -> list[DHCPv6IAAddress]:
        return [address for ia in self.ias for address in ia.addresses()]

    def prefixes(self) -> list[DHCPv6IAPrefix]:
        return [prefix for ia in self.ias for prefix in ia.prefixes()]


class DHCPv6ClientEventKind(enum.IntEnum):
    BOUND = 0
    EXPIRED = 1
    INFORMED = 2
    RELEASED = 3
    UNANSWERED = 4


@dataclasses.dataclass(frozen=True)
class DHCPv6ClientEvent:
    """What a client tells: ``BOUND`` with its lease (the client should check its addresses with DAD and
    decline those in use, §18.2.10.1), ``EXPIRED``, ``INFORMED`` with the options of an Information-request's
    Reply (§18.2.6), ``RELEASED`` (a Release or Decline taken or unanswered), or ``UNANSWERED``."""

    kind: DHCPv6ClientEventKind
    lease: DHCPv6Lease | None = None
    options: DHCPv6Options | None = None


class DHCPv6Client:
    """A DHCPv6 client (RFC 9915 §18.2) without I/O. Raises ``Malformed`` for a DUID that cannot be read."""

    class Object(Handle):
        """The object of umilib behind a client. The client holds it rather than being it: the
        ``release`` of a :class:`Handle` is its lock's, and the client's is the protocol's."""

        FREE = f"{P}_dhcpv6_client_free"

    def __init__(self, config: DHCPv6ClientConfig, now: int) -> None:
        requested = Words.array(ctypes.c_uint16, list(config.requested), len(config.requested)) if config.requested else None
        self.object = DHCPv6Client.Object(
            Handle.create(
                f"{P}_dhcpv6_client_new", ctypes.byref(config.to_structure()), *Bytes.readable(config.duid.encode()), requested,
                len(config.requested), now,
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

    def __enter__(self) -> DHCPv6Client:
        return self

    def __exit__(self, *exception: object) -> None:
        self.object.close()

    def start(self, now: int, random: Any) -> None:
        """Starts: Solicit for addresses or prefixes, or, asking for neither, Information-request (§18.2.6);
        the first after a random delay of up to a second."""
        self.library.call(f"{P}_dhcpv6_client_start", self.handle, now, *random.source())

    def receive(self, data: bytes, now: int, random: Any) -> None:
        """Takes a server's Advertise or Reply; ignored unless of the exchange's transaction, with the
        client's DUID and a server's (§16)."""
        self.library.call(f"{P}_dhcpv6_client_receive", self.handle, *Bytes.readable(data), now, *random.source())

    def transmit(self) -> bytes | None:
        """The next message to send, to :attr:`DHCPv6Message.ALL_RELAY_AGENTS_AND_SERVERS`, port 547."""
        return self.library.optional(f"{P}_dhcpv6_client_transmit", Buffer, self.handle)

    def poll_timeout(self) -> int | None:
        """When :meth:`expire` is next due, in nanoseconds."""
        return self.library.optional(f"{P}_dhcpv6_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int, random: Any) -> None:
        """Does what is due at ``now``: a delayed first message, a retransmission or the end of an exchange
        (§15), Renew at T1, Rebind at T2, the end of the lease, or a refresh of stateless configuration (§18.2.12)."""
        self.library.call(f"{P}_dhcpv6_client_expire", self.handle, now, *random.source())

    def outputs(self, name: str, ctype: Any) -> tuple[bool, Any, bytes, bytes, bytes]:
        """Calls ``name``, whose outputs are a flag, a structure of ``ctype`` and three buffers."""
        found, structure = ctypes.c_bool(), ctype()
        buffers = (Buffer(), Buffer(), Buffer())
        try:
            self.library.call(name, self.handle, ctypes.byref(found), ctypes.byref(structure), *[ctypes.byref(buffer) for buffer in buffers])
        finally:
            ias, options, server = (self.library.take(buffer) for buffer in buffers)
        return found.value, structure, ias, options, server

    def poll_event(self) -> DHCPv6ClientEvent | None:
        found, structure, ias, options, server = self.outputs(f"{P}_dhcpv6_client_poll_event", Library.default().type(f"{P}_DHCPv6ClientEvent"))
        if not found:
            return None
        kind = DHCPv6ClientEventKind(structure.kind)
        if kind == DHCPv6ClientEventKind.BOUND:
            return DHCPv6ClientEvent(kind, DHCPv6Lease.from_structure(structure.lease, ias, options, server))
        if kind == DHCPv6ClientEventKind.INFORMED:
            return DHCPv6ClientEvent(kind, options=DHCPv6Options.decode(options))
        return DHCPv6ClientEvent(kind)

    @property
    def state(self) -> DHCPv6ClientState:
        return DHCPv6ClientState(self.library.value(f"{P}_dhcpv6_client_state", ctypes.c_uint8, self.handle))

    @property
    def lease(self) -> DHCPv6Lease | None:
        found, structure, ias, options, server = self.outputs(f"{P}_dhcpv6_client_lease", Library.default().type(f"{P}_DHCPv6Lease"))
        return DHCPv6Lease.from_structure(structure, ias, options, server) if found else None

    def release(self, now: int, random: Any) -> None:
        """Releases the lease (§18.2.7); the client stops. Raises ``State`` without a lease."""
        self.library.call(f"{P}_dhcpv6_client_release", self.handle, now, *random.source())

    def decline(self, addresses: list[IPv6Address], now: int, random: Any) -> None:
        """Declines ``addresses`` of the lease, which DAD found in use (§18.2.8). Raises ``State`` without a
        lease or without addresses."""
        array = (Library.default().type("umilib_protocol_ip_IPv6Address") * max(len(addresses), 1))(*[address.to_structure() for address in addresses])
        self.library.call(f"{P}_dhcpv6_client_decline", self.handle, array, len(addresses), now, *random.source())

    def confirm(self, now: int, random: Any) -> None:
        """Confirms the lease after the link may have changed (§18.2.3). Raises ``State`` without a lease."""
        self.library.call(f"{P}_dhcpv6_client_confirm", self.handle, now, *random.source())


@dataclasses.dataclass(frozen=True)
class DHCPv6ServerConfig:
    """What a server leases and gives: its DUID, the first and last addresses it leases in IA_NA, the prefix
    it delegates from with its length and the length of each delegated prefix (IA_PD), the lifetimes it
    gives in seconds (0xFFFFFFFF for infinity), T1 and T2 (0: half and four fifths of the preferred
    lifetime, RFC 9915 §21.4), the preference of its Advertise messages (§21.8), whether it answers a
    Solicit with Rapid Commit with a Reply (§18.3.1), and the options it gives, each to a client that asks."""

    duid: DHCPDUID
    addresses: tuple[IPv6Address, IPv6Address] | None
    prefixes: tuple[IPv6Address, int, int] | None
    preferred: int
    valid: int
    t1: int
    t2: int
    preference: int
    rapid_commit: bool
    options: DHCPv6Options

    @classmethod
    def new(cls, duid: DHCPDUID) -> DHCPv6ServerConfig:
        """A server of ``duid`` leasing nothing yet, of the defaults of umilib, giving no options."""
        structure = Library.default().type(f"{P}_DHCPv6ServerConfig")()
        Library.default().call(f"{P}_dhcpv6_server_config_new", ctypes.byref(structure))
        return cls(
            duid, None, None, structure.preferred, structure.valid, structure.t1, structure.t2, structure.preference,
            bool(structure.rapid_commit), DHCPv6Options(),
        )  # fmt: skip

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_DHCPv6ServerConfig")()
        if self.addresses is not None:
            structure.addresses = True
            structure.first, structure.last = (address.to_structure() for address in self.addresses)
        if self.prefixes is not None:
            structure.prefixes = True
            structure.prefix = self.prefixes[0].to_structure()
            Fields.assign(structure, "prefix_length", self.prefixes[1])
            Fields.assign(structure, "delegated_length", self.prefixes[2])
        for name in ("preferred", "valid", "t1", "t2", "preference"):
            Fields.assign(structure, name, getattr(self, name))
        structure.rapid_commit = self.rapid_commit
        return structure


@dataclasses.dataclass(frozen=True)
class DHCPv6Binding:
    """An address (``length`` ``None``) or a prefix a server gave to the IA ``kind``/``iaid`` of ``client``
    (its DUID's bytes), until ``expires`` (nanoseconds; ``None`` for ever); a declined one is leased no more."""

    client: bytes
    kind: DHCPv6OptionCode
    iaid: int
    address: IPv6Address
    length: int | None
    expires: int | None
    declined: bool

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_DHCPv6Binding")()
        structure.address = self.address.to_structure()
        for name, value in (
            ("iaid", self.iaid), ("kind", int(self.kind)), ("length", self.length or 0), ("has_length", self.length is not None),
            ("declined", self.declined), ("expires", DHCPTime.INFINITY if self.expires is None else self.expires),
        ):  # fmt: skip
            Fields.assign(structure, name, value)
        return structure

    @classmethod
    def from_structure(cls, structure: Any, client: bytes) -> DHCPv6Binding:
        return cls(
            client, DHCPv6OptionCode(structure.kind), structure.iaid, IPv6Address.from_structure(structure.address),
            structure.length if structure.has_length else None,
            None if structure.expires == DHCPTime.INFINITY else structure.expires, bool(structure.declined),
        )  # fmt: skip


class DHCPv6Server(Handle):
    """A DHCPv6 server (RFC 9915 §18.3) without I/O: it answers each client message, relayed or not, with
    the reply of its rules. Raises ``Config`` for a pool whose first address is after its last, or prefixes
    longer than their delegated length."""

    FREE = f"{P}_dhcpv6_server_free"

    def __init__(self, config: DHCPv6ServerConfig) -> None:
        super().__init__(
            Handle.create(
                f"{P}_dhcpv6_server_new", ctypes.byref(config.to_structure()), *Bytes.readable(config.duid.encode()),
                *Bytes.readable(config.options.encode()),
            )  # fmt: skip
        )

    def receive(self, data: bytes, now: int) -> bytes | None:
        """The reply to ``data`` at ``now``: of a client's message, or of a Relay-forward, whose relayed
        message is answered inside a Relay-reply of the same addresses and Interface-Id (§19.3)."""
        return self.library.optional(f"{P}_dhcpv6_server_receive", Buffer, self.handle, *Bytes.readable(data), now)

    def expire(self, now: int) -> None:
        """Forgets the bindings expired at ``now``."""
        self.library.call(f"{P}_dhcpv6_server_expire", self.handle, now)

    @property
    def bindings(self) -> list[DHCPv6Binding]:
        """Every binding, in the order of addresses: the server's state, for its caller to keep."""
        count = self.library.value(f"{P}_dhcpv6_server_bindings_count", ctypes.c_size_t, self.handle)
        bindings = []
        for index in range(count):
            structure, buffer = Library.default().type(f"{P}_DHCPv6Binding")(), Buffer()
            self.library.call(f"{P}_dhcpv6_server_binding_entry", self.handle, index, ctypes.byref(structure), ctypes.byref(buffer))
            bindings.append(DHCPv6Binding.from_structure(structure, self.library.take(buffer)))
        return bindings

    def set_binding(self, binding: DHCPv6Binding) -> None:
        """Sets the binding of its address (and prefix length): one kept elsewhere, given back."""
        self.library.call(f"{P}_dhcpv6_server_set_binding", self.handle, binding.to_structure(), *Bytes.readable(binding.client))

    def remove_binding(self, address: IPv6Address, length: int | None = None) -> None:
        self.library.call(f"{P}_dhcpv6_server_remove_binding", self.handle, address.to_structure(), length or 0, length is not None)
