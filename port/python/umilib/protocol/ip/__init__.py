"""The Internet Protocol: what both versions share — addresses (RFC 791, RFC 4291, with the text
form of RFC 5952), protocol numbers, the Internet checksum (RFC 1071, RFC 1624), the pseudo-header of
upper-layer checksums and the reassembly buffer of fragments. Mirrors ``umilib::protocol::ip``.

:class:`IPv4Address` and :class:`IPv6Address` are immutable values derived from :class:`IPAddress`
(the Rust enum ``IPAddress``); :meth:`IPAddress.parse` reads either. Errors are :class:`IPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Text

P = "umilib_protocol_ip"


class IPError(FFIError):
    """An error of an address or a pseudo-header: ``Syntax``, ``Family``, ``Length`` or ``Overlap``."""


Library.register_error("protocol.ip", IPError)


class IPAddress:
    """An address of either IP version: the base of :class:`IPv4Address` and :class:`IPv6Address`."""

    LENGTH: ClassVar[int] = 0
    BITS: ClassVar[int] = 0
    VERSION: ClassVar[int] = 0
    C_TYPE: ClassVar[str] = ""
    C_NAME: ClassVar[str] = ""

    __slots__ = ("octets",)

    def __init__(self, octets: bytes | bytearray | memoryview) -> None:
        octets = bytes(octets)
        if len(octets) != self.LENGTH:
            raise ValueError(f"an {type(self).__name__} has {self.LENGTH} octets, not {len(octets)}")
        object.__setattr__(self, "octets", octets)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"an {type(self).__name__} is immutable")

    @staticmethod
    def parse(text: str) -> IPAddress:
        """An IPv6 address if ``text`` has a colon, and an IPv4 address otherwise."""
        return IPv6Address.parse(text) if ":" in text else IPv4Address.parse(text)

    @staticmethod
    def from_octets(octets: bytes | bytearray | memoryview) -> IPAddress:
        """The address of ``octets``: 4 for IPv4, 16 for IPv6; raises ``Length`` otherwise."""
        octets = bytes(octets)
        if len(octets) == IPv4Address.LENGTH:
            return IPv4Address(octets)
        if len(octets) == IPv6Address.LENGTH:
            return IPv6Address(octets)
        raise IPError("protocol.ip", "Length", "the length does not fit its field or the datagram")

    def version(self) -> int:
        return self.VERSION

    def to_structure(self) -> Any:
        """The C structure of the address."""
        structure = Library.default().type(self.C_TYPE)()
        ctypes.memmove(structure.octets, self.octets, self.LENGTH)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> Any:
        """The address of a C structure."""
        return cls(bytes(structure.octets))

    def to_bits(self) -> int:
        return int.from_bytes(self.octets, "big")

    @classmethod
    def from_bits(cls, bits: int) -> Any:
        return cls(bits.to_bytes(cls.LENGTH, "big"))

    def call(self, method: str, *arguments: Any) -> Any:
        """The result of the C function of ``method`` on this address."""
        return Library.default().function(f"{P}_{self.C_NAME}_{method}")(self.to_structure(), *arguments)

    def prefix(self, length: int) -> Any:
        """The address with every bit after the first ``length`` cleared."""
        return type(self).from_structure(self.call("prefix", length))

    def has_prefix(self, prefix: IPAddress, length: int) -> bool:
        """Whether the first ``length`` bits are those of ``prefix``; never for a prefix of the other version."""
        if type(prefix) is not type(self):
            return False
        return bool(self.call("has_prefix", prefix.to_structure(), length))

    def to_canonical_prefix(self, length: int) -> tuple[IPAddress, int]:
        """The prefix of ``length`` bits as :meth:`to_canonical` makes it: an IPv4 prefix for at least 96
        bits of an IPv4-mapped address (RFC 4291 §2.5.5.2); the bits after the length cleared."""
        out, used, bits = (ctypes.c_uint8 * 16)(), ctypes.c_uint8(), ctypes.c_uint8()
        Library.default().call(f"{P}_ip_address_to_canonical_prefix", self.octets, self.LENGTH, length, out, ctypes.byref(used), ctypes.byref(bits))
        return IPAddress.from_octets(bytes(out)[: used.value]), bits.value

    def is_unspecified(self) -> bool:
        return bool(self.call("is_unspecified"))

    def is_loopback(self) -> bool:
        return bool(self.call("is_loopback"))

    def is_multicast(self) -> bool:
        return bool(self.call("is_multicast"))

    def is_link_local(self) -> bool:
        return bool(self.call("is_link_local"))

    def is_documentation(self) -> bool:
        return bool(self.call("is_documentation"))

    def to_canonical(self) -> IPAddress:
        """The IPv4 address of an IPv4-mapped IPv6 address, and the address itself otherwise."""
        return self

    def __str__(self) -> str:
        library = Library.default()
        return library.output(f"{P}_{self.C_NAME}_to_string", self.to_structure()).decode("utf-8")

    def __repr__(self) -> str:
        return f"{type(self).__name__}('{self}')"

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and other.octets == self.octets

    def __lt__(self, other: IPAddress) -> bool:
        return (self.VERSION, self.octets) < (other.VERSION, other.octets)

    def __hash__(self) -> int:
        return hash((self.VERSION, self.octets))

    def __bytes__(self) -> bytes:
        return self.octets


class IPv4Address(IPAddress):
    """An IPv4 address (RFC 791); its text is dotted decimal without leading zeros."""

    LENGTH = 4
    BITS = 32
    VERSION = 4
    C_TYPE = f"{P}_IPv4Address"
    C_NAME = "ipv4_address"
    UNSPECIFIED: ClassVar[IPv4Address]
    LOOPBACK: ClassVar[IPv4Address]
    BROADCAST: ClassVar[IPv4Address]

    __slots__ = ()

    @classmethod
    def parse(cls, text: str) -> IPv4Address:
        """Reads a dotted decimal address; raises ``Syntax``."""
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_ipv4_address_parse", *Text.encode(text), ctypes.byref(structure))
        return cls.from_structure(structure)

    @staticmethod
    def mask(length: int) -> int:
        """The netmask of a prefix of ``length`` bits."""
        return IPv4Address.BROADCAST.prefix(length).to_bits()

    def is_private(self) -> bool:
        """10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (RFC 1918)."""
        return bool(self.call("is_private"))

    def is_broadcast(self) -> bool:
        return bool(self.call("is_broadcast"))

    def to_ipv6_mapped(self) -> IPv6Address:
        """The IPv4-mapped IPv6 address ``::ffff:a.b.c.d`` (RFC 4291 §2.5.5.2)."""
        return IPv6Address.from_structure(self.call("to_ipv6_mapped"))


class IPv6Address(IPAddress):
    """An IPv6 address (RFC 4291); its text is that of RFC 5952."""

    LENGTH = 16
    BITS = 128
    VERSION = 6
    C_TYPE = f"{P}_IPv6Address"
    C_NAME = "ipv6_address"
    UNSPECIFIED: ClassVar[IPv6Address]
    LOOPBACK: ClassVar[IPv6Address]
    ALL_NODES: ClassVar[IPv6Address]
    ALL_ROUTERS: ClassVar[IPv6Address]

    __slots__ = ()

    @classmethod
    def parse(cls, text: str) -> IPv6Address:
        """Reads an address in any form of RFC 4291 §2.2; raises ``Syntax``."""
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_ipv6_address_parse", *Text.encode(text), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_words(cls, words: list[int]) -> IPv6Address:
        """The address of eight 16-bit words, first word first."""
        if len(words) != 8:
            raise ValueError("an IPv6 address has eight words")
        return cls(b"".join(word.to_bytes(2, "big") for word in words))

    def to_words(self) -> list[int]:
        return [int.from_bytes(self.octets[index : index + 2], "big") for index in range(0, 16, 2)]

    @staticmethod
    def mask(length: int) -> int:
        """The mask of a prefix of ``length`` bits."""
        return IPv6Address(b"\xff" * 16).prefix(length).to_bits()

    @classmethod
    def from_interface_identifier(cls, prefix: bytes, interface_identifier: bytes) -> IPv6Address:
        """The address of the 64-bit ``prefix`` and ``interface_identifier`` (8 bytes each)."""
        if len(prefix) != 8 or len(interface_identifier) != 8:
            raise ValueError("the prefix and the interface identifier have 8 bytes each")
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_ipv6_address_from_interface_identifier", bytes(prefix), bytes(interface_identifier), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def link_local(cls, interface_identifier: bytes) -> IPv6Address:
        """The link-local address ``fe80::/64`` of ``interface_identifier`` (RFC 4291 §2.5.6)."""
        return cls.from_interface_identifier(bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0]), interface_identifier)

    def interface_identifier(self) -> bytes:
        """The last 64 bits."""
        return self.octets[8:]

    def solicited_node(self) -> IPv6Address:
        """The solicited-node multicast address of the last 24 bits (RFC 4291 §2.7.1)."""
        return IPv6Address.from_structure(self.call("solicited_node"))

    def multicast_scope(self) -> int | None:
        """The scope of a multicast address (RFC 4291 §2.7, RFC 7346), ``None`` for other addresses."""
        found, scope = ctypes.c_bool(), ctypes.c_uint8()
        Library.default().call(f"{P}_ipv6_address_multicast_scope", self.to_structure(), ctypes.byref(found), ctypes.byref(scope))
        return scope.value if found.value else None

    def is_unique_local(self) -> bool:
        """``fc00::/7`` (RFC 4193)."""
        return bool(self.call("is_unique_local"))

    def to_ipv4_mapped(self) -> IPv4Address | None:
        """The IPv4 address of an IPv4-mapped address, or ``None``."""
        found = ctypes.c_bool()
        structure = Library.default().type(IPv4Address.C_TYPE)()
        Library.default().call(f"{P}_ipv6_address_to_ipv4_mapped", self.to_structure(), ctypes.byref(found), ctypes.byref(structure))
        return IPv4Address.from_structure(structure) if found.value else None

    def to_canonical(self) -> IPAddress:
        return self.to_ipv4_mapped() or self


IPv4Address.UNSPECIFIED = IPv4Address(bytes(4))
IPv4Address.LOOPBACK = IPv4Address(bytes([127, 0, 0, 1]))
IPv4Address.BROADCAST = IPv4Address(b"\xff" * 4)
IPv6Address.UNSPECIFIED = IPv6Address(bytes(16))
IPv6Address.LOOPBACK = IPv6Address.from_words([0, 0, 0, 0, 0, 0, 0, 1])
IPv6Address.ALL_NODES = IPv6Address.from_words([0xFF02, 0, 0, 0, 0, 0, 0, 1])
IPv6Address.ALL_ROUTERS = IPv6Address.from_words([0xFF02, 0, 0, 0, 0, 0, 0, 2])


class IPProtocol(int):
    """An IP protocol number of the IANA registry; numbers without a constant are kept as they are."""

    HOP_BY_HOP_OPTIONS: ClassVar[IPProtocol]
    ICMP: ClassVar[IPProtocol]
    IGMP: ClassVar[IPProtocol]
    IPV4: ClassVar[IPProtocol]
    TCP: ClassVar[IPProtocol]
    UDP: ClassVar[IPProtocol]
    IPV6: ClassVar[IPProtocol]
    IPV6_ROUTING: ClassVar[IPProtocol]
    IPV6_FRAGMENT: ClassVar[IPProtocol]
    ESP: ClassVar[IPProtocol]
    AH: ClassVar[IPProtocol]
    ICMPV6: ClassVar[IPProtocol]
    IPV6_NO_NEXT_HEADER: ClassVar[IPProtocol]
    IPV6_DESTINATION_OPTIONS: ClassVar[IPProtocol]
    SCTP: ClassVar[IPProtocol]
    MOBILITY: ClassVar[IPProtocol]
    HIP: ClassVar[IPProtocol]
    SHIM6: ClassVar[IPProtocol]
    EXPERIMENT_1: ClassVar[IPProtocol]
    EXPERIMENT_2: ClassVar[IPProtocol]

    def __new__(cls, number: int) -> IPProtocol:
        if not 0 <= number <= 255:
            raise ValueError("a protocol number is 0 to 255")
        return super().__new__(cls, number)

    def name(self) -> str | None:
        """The keyword of the registry, for the numbers with a constant."""
        data = Library.default().optional(f"{P}_ip_protocol_name", Buffer, int(self))
        return data.decode("utf-8") if data is not None else None

    def __str__(self) -> str:
        return self.name() or str(int(self))

    def __repr__(self) -> str:
        return f"IPProtocol({int(self)})"


for _name, _number in [
    ("HOP_BY_HOP_OPTIONS", 0), ("ICMP", 1), ("IGMP", 2), ("IPV4", 4), ("TCP", 6), ("UDP", 17), ("IPV6", 41),
    ("IPV6_ROUTING", 43), ("IPV6_FRAGMENT", 44), ("ESP", 50), ("AH", 51), ("ICMPV6", 58), ("IPV6_NO_NEXT_HEADER", 59),
    ("IPV6_DESTINATION_OPTIONS", 60), ("SCTP", 132), ("MOBILITY", 135), ("HIP", 139), ("SHIM6", 140),
    ("EXPERIMENT_1", 253), ("EXPERIMENT_2", 254),
]:  # fmt: skip
    setattr(IPProtocol, _name, IPProtocol(_number))
del _name, _number


class InternetChecksum:
    """The Internet checksum (RFC 1071) of the bytes added so far, in any number of updates."""

    def __init__(self) -> None:
        self.structure = Library.default().type(f"{P}_InternetChecksum")()

    @property
    def sum(self) -> int:
        """The sum of the words so far, not yet folded."""
        return self.structure.sum

    @property
    def odd(self) -> bool:
        """Whether an odd number of bytes was added."""
        return bool(self.structure.odd)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data``, which follows the bytes added before."""
        Library.default().call(f"{P}_internet_checksum_update", ctypes.byref(self.structure), *Bytes.readable(data))

    def sum16(self) -> int:
        """The one's complement sum, folded to 16 bits."""
        return Library.default().function(f"{P}_internet_checksum_sum16")(self.structure)

    def finish(self) -> int:
        """The checksum: the one's complement of :meth:`sum16`."""
        return Library.default().function(f"{P}_internet_checksum_finish")(self.structure)

    @staticmethod
    def checksum(data: bytes | bytearray | memoryview) -> int:
        return Library.default().value(f"{P}_internet_checksum_checksum", ctypes.c_uint16, *Bytes.readable(data))

    @staticmethod
    def verify(data: bytes | bytearray | memoryview) -> bool:
        """Whether ``data``, which contains its checksum field, sums to all one bits."""
        return Library.default().value(f"{P}_internet_checksum_verify", ctypes.c_bool, *Bytes.readable(data))

    @staticmethod
    def fold(value: int) -> int:
        """``value`` folded to 16 bits by adding the carries back."""
        return Library.default().function(f"{P}_internet_checksum_fold")(value)

    @staticmethod
    def adjust(checksum: int, old: int, new: int) -> int:
        """The checksum after a 16-bit word changes from ``old`` to ``new`` (RFC 1624 §3)."""
        return Library.default().function(f"{P}_internet_checksum_adjust")(checksum, old, new)

    @staticmethod
    def adjust_bytes(checksum: int, old: bytes, new: bytes) -> int | None:
        """The checksum after the bytes ``old``, at an even offset, change to ``new``; ``None`` if
        the lengths differ."""
        if len(old) != len(new):
            return None
        out = ctypes.c_uint16()
        Library.default().call(f"{P}_internet_checksum_adjust_bytes", checksum, bytes(old), bytes(new), len(old), ctypes.byref(out))
        return out.value


class IPPseudoHeader:
    """The pseudo-header of ``length`` upper-layer bytes of ``protocol`` between ``source`` and
    ``destination`` (RFC 768, RFC 9293 §3.1, RFC 8200 §8.1); raises ``Family`` or ``Length``."""

    def __init__(self, source: IPAddress, destination: IPAddress, protocol: int, length: int) -> None:
        self.source, self.destination, self.protocol, self.length = source, destination, IPProtocol(protocol), length
        self.bytes = Library.default().output(
            f"{P}_ip_pseudo_header_to_bytes", source.octets, source.LENGTH, destination.octets, destination.LENGTH, int(protocol), length
        )

    def to_bytes(self) -> bytes:
        """The bytes of the pseudo-header: 12 for IPv4, 40 for IPv6."""
        return self.bytes

    def checksum(self) -> InternetChecksum:
        """A checksum to which the pseudo-header is added."""
        checksum = InternetChecksum()
        checksum.update(self.bytes)
        return checksum


@dataclasses.dataclass(frozen=True, order=True)
class IPEndpoint:
    """An endpoint of a transport protocol over IP (UDP, TCP): an address and a port (RFC 6335)."""

    address: IPAddress
    port: int

    @classmethod
    def parse(cls, text: str) -> IPEndpoint:
        """The endpoint of ``address:port`` (IPv4) or ``[address]:port`` (IPv6), as RFC 3986 §3.2.2; raises ``Syntax``."""
        structure = Library.default().type(f"{P}_IPEndpoint")()
        Library.default().call(f"{P}_ip_endpoint_parse", *Text.encode(text), ctypes.byref(structure))
        return cls.from_structure(structure)

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a port that does not fit 16 bits."""
        structure = Library.default().type(f"{P}_IPEndpoint")()
        ctypes.memmove(structure.octets, self.address.octets, self.address.LENGTH)
        structure.length = self.address.LENGTH
        Fields.assign(structure, "port", self.port)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> IPEndpoint:
        return cls(IPAddress.from_octets(bytes(structure.octets)[: structure.length]), structure.port)

    def __str__(self) -> str:
        return Library.default().output(f"{P}_ip_endpoint_to_string", ctypes.byref(self.to_structure())).decode()


@dataclasses.dataclass(frozen=True)
class IPEndpointPattern:
    """The endpoints whose address has a prefix (any address if ``prefix`` is ``None``) and whose
    port is from ``first_port`` to ``last_port``; IPv4-mapped IPv6 addresses match as IPv4, and a
    prefix of at least 96 bits of them is the IPv4 prefix it maps."""

    ANY: ClassVar[IPEndpointPattern]

    prefix: tuple[IPAddress, int] | None = None
    first_port: int = 0
    last_port: int = 0xFFFF

    @classmethod
    def port(cls, port: int) -> IPEndpointPattern:
        return cls(None, port, port)

    @classmethod
    def ports(cls, first: int, last: int) -> IPEndpointPattern:
        return cls(None, first, last)

    def with_address(self, address: IPAddress) -> IPEndpointPattern:
        return self.with_prefix(address, address.BITS)

    def with_prefix(self, address: IPAddress, length: int) -> IPEndpointPattern:
        """These endpoints, of the addresses whose first ``length`` bits are those of ``address``, the
        prefix kept as :meth:`IPAddress.to_canonical_prefix` makes it."""
        return dataclasses.replace(self, prefix=address.to_canonical_prefix(length))

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_IPEndpointPattern")()
        if self.prefix is not None:
            address, length = self.prefix
            ctypes.memmove(structure.octets, address.octets, address.LENGTH)
            structure.length = address.LENGTH
            Fields.assign(structure, "prefix_length", length)
        Fields.assign(structure, "first_port", self.first_port)
        Fields.assign(structure, "last_port", self.last_port)
        return structure

    def matches(self, endpoint: IPEndpoint) -> bool:
        return Library.default().value(
            f"{P}_ip_endpoint_pattern_matches", ctypes.c_bool, ctypes.byref(self.to_structure()), ctypes.byref(endpoint.to_structure())
        )


IPEndpointPattern.ANY = IPEndpointPattern()


class IPFragmentBuffer(Handle):
    """The data of one datagram being reassembled: a fragment that overlaps another raises
    ``Overlap``; only an exact duplicate of a fragment received is ignored."""

    FREE = f"{P}_ip_fragment_buffer_free"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{P}_ip_fragment_buffer_new"))

    def insert(self, offset: int, data: bytes | bytearray | memoryview, last: bool, maximum: int) -> bool:
        """Adds ``data`` at ``offset`` (the last bytes if ``last``) of data of at most ``maximum``
        bytes; returns whether every byte is received."""
        return self.library.value(f"{P}_ip_fragment_buffer_insert", ctypes.c_bool, self.handle, offset, *Bytes.readable(data), last, maximum)

    def check(self, offset: int, data: bytes | bytearray | memoryview, last: bool, maximum: int) -> int:
        """Checks ``data`` at ``offset`` against the fragments received without adding it; returns how
        much :meth:`memory` would grow (0 for an exact duplicate); raises ``Overlap`` or ``Length``."""
        return self.library.value(f"{P}_ip_fragment_buffer_check", ctypes.c_size_t, self.handle, offset, *Bytes.readable(data), last, maximum)

    @property
    def data(self) -> bytes:
        """The bytes received at their offsets, zeros between them."""
        return self.library.output(f"{P}_ip_fragment_buffer_data", self.handle)

    @property
    def length(self) -> int | None:
        """The length of the data, known from its last fragment."""
        return self.library.optional(f"{P}_ip_fragment_buffer_length", ctypes.c_size_t, self.handle)

    def progress(self) -> tuple[bool, int]:
        complete, received = ctypes.c_bool(), ctypes.c_size_t()
        self.library.call(f"{P}_ip_fragment_buffer_progress", self.handle, ctypes.byref(complete), ctypes.byref(received))
        return complete.value, received.value

    def is_complete(self) -> bool:
        return self.progress()[0]

    def memory(self) -> int:
        """The bytes the buffer holds, approximately: its data and the record of its fragments."""
        return self.library.value(f"{P}_ip_fragment_buffer_memory", ctypes.c_size_t, self.handle)

    def received_length(self) -> int:
        return self.progress()[1]


__all__ = ["IPAddress", "IPEndpoint", "IPEndpointPattern", "IPError", "IPFragmentBuffer", "IPProtocol", "IPPseudoHeader", "IPv4Address", "IPv6Address", "InternetChecksum"]
