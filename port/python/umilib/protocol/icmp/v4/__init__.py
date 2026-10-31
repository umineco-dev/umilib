"""ICMP for IPv4 (RFC 792, with RFC 1122 §3.2.2): the messages, their types and codes, the rules of
error messages, and the extensions of RFC 4884. Mirrors ``umilib::protocol::icmp::v4``.

Errors are :class:`~umilib.protocol.icmp.ICMPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import ClassVar

from umilib.ffi import Bytes, FFIError, Library
from umilib.protocol.icmp import ICMPExtensions, ICMPHeader
from umilib.protocol.ip import IPv4Address
from umilib.protocol.ip.v4 import IPv4Header


class ICMPv4Type(int):
    """The type of an ICMP message (the IANA registry "ICMP Type Numbers")."""

    ECHO_REPLY: ClassVar[ICMPv4Type]
    DESTINATION_UNREACHABLE: ClassVar[ICMPv4Type]
    SOURCE_QUENCH: ClassVar[ICMPv4Type]
    REDIRECT: ClassVar[ICMPv4Type]
    ECHO_REQUEST: ClassVar[ICMPv4Type]
    ROUTER_ADVERTISEMENT: ClassVar[ICMPv4Type]
    ROUTER_SOLICITATION: ClassVar[ICMPv4Type]
    TIME_EXCEEDED: ClassVar[ICMPv4Type]
    PARAMETER_PROBLEM: ClassVar[ICMPv4Type]
    TIMESTAMP: ClassVar[ICMPv4Type]
    TIMESTAMP_REPLY: ClassVar[ICMPv4Type]
    EXTENDED_ECHO_REQUEST: ClassVar[ICMPv4Type]
    EXTENDED_ECHO_REPLY: ClassVar[ICMPv4Type]

    def __new__(cls, value: int) -> ICMPv4Type:
        if not 0 <= value <= 255:
            raise ValueError("a type is 0 to 255")
        return super().__new__(cls, value)

    def is_error(self) -> bool:
        return bool(Library.default().function("umilib_protocol_icmp_v4_icmpv4_type_is_error")(int(self)))

    def is_deprecated(self) -> bool:
        """Whether the type is deprecated (RFC 6633, RFC 6918)."""
        return bool(Library.default().function("umilib_protocol_icmp_v4_icmpv4_type_is_deprecated")(int(self)))

    def is_extensible(self) -> bool:
        """Whether an error of this type carries the length attribute of RFC 4884."""
        return bool(Library.default().function("umilib_protocol_icmp_v4_icmpv4_type_is_extensible")(int(self)))

    def __repr__(self) -> str:
        return f"ICMPv4Type({int(self)})"


for _name, _value in [
    ("ECHO_REPLY", 0), ("DESTINATION_UNREACHABLE", 3), ("SOURCE_QUENCH", 4), ("REDIRECT", 5), ("ECHO_REQUEST", 8),
    ("ROUTER_ADVERTISEMENT", 9), ("ROUTER_SOLICITATION", 10), ("TIME_EXCEEDED", 11), ("PARAMETER_PROBLEM", 12),
    ("TIMESTAMP", 13), ("TIMESTAMP_REPLY", 14), ("EXTENDED_ECHO_REQUEST", 42), ("EXTENDED_ECHO_REPLY", 43),
]:  # fmt: skip
    setattr(ICMPv4Type, _name, ICMPv4Type(_value))
del _name, _value


class ICMPv4Code:
    """The codes of ICMP messages, by type (RFC 792, RFC 1122 §3.2.2, RFC 1812 §5.2.7.1, RFC 1191)."""

    NETWORK_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    NETWORK_PROHIBITED = 9
    HOST_PROHIBITED = 10
    NETWORK_UNREACHABLE_FOR_TOS = 11
    HOST_UNREACHABLE_FOR_TOS = 12
    COMMUNICATION_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF = 15
    REDIRECT_NETWORK = 0
    REDIRECT_HOST = 1
    REDIRECT_TOS_NETWORK = 2
    REDIRECT_TOS_HOST = 3
    TIME_TO_LIVE_EXCEEDED = 0
    REASSEMBLY_TIME_EXCEEDED = 1
    POINTER = 0
    MISSING_OPTION = 1
    BAD_LENGTH = 2


@dataclasses.dataclass(frozen=True)
class ICMPv4Message:
    """An ICMP message (RFC 792): its type, its code, the four bytes after the checksum and the body.
    The checksum is checked on reading and computed on writing."""

    HEADER_LENGTH: ClassVar[int] = 8
    MAXIMUM_ERROR_LENGTH: ClassVar[int] = 576
    MINIMUM_QUOTE: ClassVar[int] = 8
    WORD: ClassVar[int] = 4

    kind: ICMPv4Type
    code: int
    rest: bytes
    body: bytes = b""

    def header_structure(self):
        return ICMPHeader.to_structure(self.kind, self.code, self.rest)

    @classmethod
    def from_structure(cls, structure, body: bytes = b"") -> ICMPv4Message:
        kind, code, rest = ICMPHeader.from_structure(structure)
        return cls(ICMPv4Type(kind), code, rest, body)

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> ICMPv4Message:
        """The message that ``data`` is; raises ``Length`` or ``Checksum``."""
        data = bytes(data)
        structure = Library.default().type("umilib_protocol_icmp_ICMPHeader")()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_decode", data, len(data), ctypes.byref(structure))
        return cls.from_structure(structure, data[ICMPv4Message.HEADER_LENGTH :])

    def encode(self) -> bytes:
        return Library.default().output("umilib_protocol_icmp_v4_icmpv4_message_encode", self.header_structure(), *Bytes.readable(self.body))

    def length(self) -> int:
        return ICMPv4Message.HEADER_LENGTH + len(self.body)

    @classmethod
    def echo_request(cls, identifier: int, sequence: int, data: bytes = b"") -> ICMPv4Message:
        return cls.from_structure(Library.default().function("umilib_protocol_icmp_v4_icmpv4_message_echo_request")(identifier, sequence), bytes(data))

    def echo_reply(self) -> ICMPv4Message | None:
        """The Echo Reply to this Echo Request."""
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_icmp_ICMPHeader")()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_echo_reply", self.header_structure(), ctypes.byref(found), ctypes.byref(structure))
        return ICMPv4Message.from_structure(structure, self.body) if found.value else None

    def query(self) -> tuple[int, int] | None:
        found, identifier, sequence = ctypes.c_bool(), ctypes.c_uint16(), ctypes.c_uint16()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_query", self.header_structure(), ctypes.byref(found), ctypes.byref(identifier), ctypes.byref(sequence))
        return (identifier.value, sequence.value) if found.value else None

    def is_query(self) -> bool:
        """Whether the message is an Echo, a Timestamp or their replies."""
        return self.query() is not None

    def identifier(self) -> int | None:
        query = self.query()
        return query[0] if query else None

    def sequence(self) -> int | None:
        query = self.query()
        return query[1] if query else None

    def timestamps(self) -> tuple[int, int, int] | None:
        """The originate, receive and transmit timestamps of a Timestamp or Timestamp Reply."""
        found, out = ctypes.c_bool(), (ctypes.c_uint32 * 3)()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_timestamps", self.header_structure(), *Bytes.readable(self.body), ctypes.byref(found), out)
        return (out[0], out[1], out[2]) if found.value else None

    def next_hop_mtu(self) -> int | None:
        """The MTU of the next hop of a Fragmentation Needed message (RFC 1191 §4)."""
        return Library.default().optional("umilib_protocol_icmp_v4_icmpv4_message_next_hop_mtu", ctypes.c_uint16, self.header_structure())

    def pointer(self) -> int | None:
        return Library.default().optional("umilib_protocol_icmp_v4_icmpv4_message_pointer", ctypes.c_uint8, self.header_structure())

    def gateway(self) -> IPv4Address | None:
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_ip_IPv4Address")()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_gateway", self.header_structure(), ctypes.byref(found), ctypes.byref(structure))
        return IPv4Address.from_structure(structure) if found.value else None

    def original(self) -> tuple[bytes, ICMPExtensions | None]:
        """The original datagram an error quotes and its extension structure (RFC 4884), if any."""
        length, found = ctypes.c_size_t(), ctypes.c_bool()
        Library.default().call("umilib_protocol_icmp_v4_icmpv4_message_original", self.header_structure(), *Bytes.readable(self.body), ctypes.byref(length), ctypes.byref(found))
        original = self.body[: length.value]
        return original, (ICMPExtensions.decode(self.body[length.value :]) if found.value else None)

    def invoking(self) -> tuple[IPv4Header, bytes] | None:
        """The header of the packet an error quotes and the part of its data quoted; read from the
        whole body when the extensions are malformed."""
        try:
            original, _ = self.original()
        except FFIError:
            original = self.body
        structure = Library.default().type("umilib_protocol_ip_v4_IPv4Header")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        try:
            Library.default().call("umilib_protocol_ip_v4_ipv4_header_decode_truncated", original, len(original), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        except FFIError:
            return None
        return IPv4Header.from_structure(structure), original[offset.value : offset.value + length.value]

    @staticmethod
    def quote_length(length: int, header_length: int) -> int:
        return Library.default().function("umilib_protocol_icmp_v4_icmpv4_message_quote_length")(length, header_length)

    @staticmethod
    def quote(datagram: bytes, header_length: int) -> bytes:
        """The start of ``datagram`` an error quotes, within 576 bytes (RFC 1812 §4.3.2.3)."""
        return bytes(datagram[: ICMPv4Message.quote_length(len(datagram), header_length)])

    @staticmethod
    def may_report(header: IPv4Header, payload: bytes, broadcast: bool) -> bool:
        """Whether an error may be sent about a datagram (RFC 1122 §3.2.2)."""
        return Library.default().value("umilib_protocol_icmp_v4_icmpv4_message_may_report", ctypes.c_bool, ctypes.byref(header.to_structure()), *Bytes.readable(payload), broadcast)


__all__ = ["ICMPv4Code", "ICMPv4Message", "ICMPv4Type"]
