"""The User Datagram Protocol (RFC 768) over IPv4 and IPv6: the header, the datagram with its checksum
over the pseudo-header (RFC 768, RFC 8200 §8.1), the zero checksum of IPv6 tunnels (RFC 6935, RFC 6936),
jumbograms (RFC 2675 §4), and the rule that routes datagrams by their endpoints. Mirrors
``umilib::protocol::udp``.

Errors are :class:`UDPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.ffi import Bytes, FFIError, Fields, Library
from umilib.protocol.ip import IPAddress, IPEndpoint, IPEndpointPattern

P = "umilib_protocol_udp"


class UDPError(FFIError):
    """An error of a UDP datagram: ``Length``, ``Checksum``, ``ZeroChecksum``, ``Family`` or ``Source``."""


Library.register_error("protocol.udp", UDPError)


@dataclasses.dataclass(frozen=True)
class UDPHeader:
    """The header of a UDP datagram (RFC 768), its fields as they are: nothing is checked but its
    length. :class:`UDPDatagram` reads and writes a datagram with its rules; this reads the header
    an ICMP error quotes."""

    LENGTH: ClassVar[int] = 8

    source_port: int
    destination_port: int
    length: int
    checksum: int

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> UDPHeader:
        """The header at the start of ``data``; raises ``Length`` if it has fewer than 8 bytes."""
        structure = Library.default().type(f"{P}_UDPHeader")()
        Library.default().call(f"{P}_udp_header_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> UDPHeader:
        return cls(structure.source_port, structure.destination_port, structure.length, structure.checksum)

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a field that does not fit 16 bits."""
        structure = Library.default().type(f"{P}_UDPHeader")()
        for name in ("source_port", "destination_port", "length", "checksum"):
            Fields.assign(structure, name, getattr(self, name))
        return structure

    def to_bytes(self) -> bytes:
        return Library.default().output(f"{P}_udp_header_encode", self.to_structure())

    def encode(self) -> bytes:
        return self.to_bytes()


@dataclasses.dataclass(frozen=True)
class UDPConfig:
    """The ports of the zero checksum of IPv6 (RFC 6935, RFC 6936): none by default, so every IPv6
    datagram is sent with a checksum and one received without is refused (RFC 6936 §4)."""

    zero_checksum_send_ports: tuple[int, ...] = ()
    zero_checksum_receive_ports: tuple[int, ...] = ()

    @staticmethod
    def array(ports: tuple[int, ...]) -> tuple[Any, int]:
        """The C array of ``ports``; raises ``OverflowError`` for a port that does not fit 16 bits."""
        for port in ports:
            if not 0 <= port <= 0xFFFF:
                raise OverflowError(f"the port {port} does not fit in 16 bits")
        return (ctypes.c_uint16 * max(len(ports), 1))(*ports), len(ports)


@dataclasses.dataclass(frozen=True)
class UDPDatagram:
    """A UDP datagram (RFC 768): its ports, whether it carries a checksum, and its data. The length
    and the checksum are checked on reading and computed on writing, over the pseudo-header of the
    addresses that carry the datagram."""

    source_port: int
    destination_port: int
    checksummed: bool = True
    payload: bytes = b""

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a port that does not fit 16 bits."""
        structure = Library.default().type(f"{P}_UDPDatagram")()
        Fields.assign(structure, "source_port", self.source_port)
        Fields.assign(structure, "destination_port", self.destination_port)
        structure.checksummed = self.checksummed
        return structure

    @classmethod
    def decode(
        cls, data: bytes | bytearray | memoryview, source: IPAddress, destination: IPAddress, config: UDPConfig = UDPConfig()
    ) -> UDPDatagram:
        """The datagram of ``data``, carried from ``source`` to ``destination``; raises ``Length``,
        ``Checksum``, ``ZeroChecksum`` or ``Family``."""
        data = bytes(data)
        structure, length = Library.default().type(f"{P}_UDPDatagram")(), ctypes.c_size_t()
        Library.default().call(
            f"{P}_udp_datagram_decode", data, len(data), source.octets, source.LENGTH, destination.octets, destination.LENGTH,
            *UDPConfig.array(config.zero_checksum_receive_ports), ctypes.byref(structure), ctypes.byref(length),
        )  # fmt: skip
        payload = data[UDPHeader.LENGTH : UDPHeader.LENGTH + length.value]
        return cls(structure.source_port, structure.destination_port, bool(structure.checksummed), payload)

    def header(self, source: IPAddress, destination: IPAddress, config: UDPConfig = UDPConfig()) -> UDPHeader:
        """The header of the datagram from ``source`` to ``destination``, with its length and checksum."""
        structure = Library.default().type(f"{P}_UDPHeader")()
        Library.default().call(
            f"{P}_udp_datagram_header", self.to_structure(), *Bytes.readable(self.payload), source.octets, source.LENGTH,
            destination.octets, destination.LENGTH, *UDPConfig.array(config.zero_checksum_send_ports), ctypes.byref(structure),
        )  # fmt: skip
        return UDPHeader.from_structure(structure)

    def encode(self, source: IPAddress, destination: IPAddress, config: UDPConfig = UDPConfig()) -> bytes:
        return Library.default().output(
            f"{P}_udp_datagram_encode", self.to_structure(), *Bytes.readable(self.payload), source.octets, source.LENGTH,
            destination.octets, destination.LENGTH, *UDPConfig.array(config.zero_checksum_send_ports),
        )  # fmt: skip

    def length(self) -> int:
        return UDPHeader.LENGTH + len(self.payload)

    def reply(self, payload: bytes) -> UDPDatagram:
        """The reply to this datagram: from its destination port to its source port, with ``payload``."""
        return UDPDatagram(self.destination_port, self.source_port, True, bytes(payload))

    @staticmethod
    def is_ipv6(source: IPAddress, destination: IPAddress) -> bool:
        """Whether ``source`` and ``destination`` are IPv6 addresses; raises ``Family`` if they are of different versions."""
        if source.VERSION != destination.VERSION:
            raise UDPError("protocol.udp", "Family", "the addresses are of different IP versions")
        return source.VERSION == 6

    @staticmethod
    def check_source(source: IPAddress) -> None:
        """Raises ``Source`` unless ``source`` names a single host: not multicast, nor the IPv4 limited
        broadcast (RFC 1122 §4.1.3.6, RFC 4291 §2.7)."""
        broadcast = source.VERSION == 4 and source.octets == b"\xff\xff\xff\xff"
        if source.is_multicast() or broadcast:
            raise UDPError("protocol.udp", "Source", "the source address names no single host")


@dataclasses.dataclass(frozen=True)
class UDPRequest:
    """A datagram as a UDP service receives it: the local endpoint it came to, the remote endpoint
    it came from, and its data."""

    local: IPEndpoint
    remote: IPEndpoint
    payload: bytes = b""


@dataclasses.dataclass(frozen=True)
class UDPRule:
    """The rule of a router that routes datagrams by their local and remote endpoints."""

    local: IPEndpointPattern = IPEndpointPattern.ANY
    remote: IPEndpointPattern = IPEndpointPattern.ANY

    @classmethod
    def new(cls, local: IPEndpointPattern) -> UDPRule:
        return cls(local)

    def with_remote(self, remote: IPEndpointPattern) -> UDPRule:
        return dataclasses.replace(self, remote=remote)

    def matches(self, request: UDPRequest) -> bool:
        rule = Library.default().type(f"{P}_UDPRule")(self.local.to_structure(), self.remote.to_structure())
        return Library.default().value(
            f"{P}_udp_rule_matches", ctypes.c_bool, ctypes.byref(rule), ctypes.byref(request.local.to_structure()),
            ctypes.byref(request.remote.to_structure()),
        )  # fmt: skip


__all__ = ["UDPConfig", "UDPDatagram", "UDPError", "UDPHeader", "UDPRequest", "UDPRule"]
