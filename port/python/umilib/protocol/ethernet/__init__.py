"""Ethernet (IEEE 802.3): MAC addresses, EtherTypes, the header with its VLAN tags (IEEE 802.1Q,
802.1ad), and the padding and frame check sequence of a frame. Mirrors ``umilib::protocol::ethernet``.

Errors are :class:`EthernetError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.ffi import Bytes, FFIError, Fields, Library, Text


class EthernetError(FFIError):
    """An error of an Ethernet frame: ``Length``, ``Tag``, ``EtherType`` or ``Syntax``."""


Library.register_error("protocol.ethernet", EthernetError)


class MACAddress:
    """A 48-bit MAC address (an EUI-48), in transmission byte order."""

    LENGTH: ClassVar[int] = 6
    ZERO: ClassVar[MACAddress]
    BROADCAST: ClassVar[MACAddress]

    __slots__ = ("octets",)

    def __init__(self, octets: bytes | bytearray | memoryview) -> None:
        octets = bytes(octets)
        if len(octets) != MACAddress.LENGTH:
            raise ValueError(f"a MAC address has 6 octets, not {len(octets)}")
        object.__setattr__(self, "octets", octets)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("a MACAddress is immutable")

    @classmethod
    def parse(cls, text: str) -> MACAddress:
        """Reads six hexadecimal pairs separated by colons or hyphens; raises ``Syntax``."""
        structure = Library.default().type("umilib_protocol_ethernet_MACAddress")()
        Library.default().call("umilib_protocol_ethernet_mac_address_parse", *Text.encode(text), ctypes.byref(structure))
        return cls.from_structure(structure)

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_ethernet_MACAddress")()
        ctypes.memmove(structure.octets, self.octets, MACAddress.LENGTH)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> MACAddress:
        return cls(bytes(structure.octets))

    def call(self, method: str) -> Any:
        return Library.default().function(f"umilib_protocol_ethernet_mac_address_{method}")(self.to_structure())

    def is_multicast(self) -> bool:
        """Whether the Individual/Group bit is set."""
        return bool(self.call("is_multicast"))

    def is_unicast(self) -> bool:
        return not self.is_multicast()

    def is_broadcast(self) -> bool:
        return bool(self.call("is_broadcast"))

    def is_local(self) -> bool:
        """Whether the Universal/Local bit is set."""
        return bool(self.call("is_local"))

    def modified_eui64(self) -> bytes:
        """The modified EUI-64 interface identifier (RFC 4291 appendix A, RFC 2464 §4)."""
        out = (ctypes.c_uint8 * 8)()
        Library.default().call("umilib_protocol_ethernet_mac_address_modified_eui64", self.to_structure(), out)
        return bytes(out)

    @classmethod
    def from_ipv4_multicast(cls, address: bytes) -> MACAddress:
        """The address an IPv4 multicast address maps to (RFC 1112 §6.4)."""
        if len(address) != 4:
            raise ValueError("an IPv4 address has 4 octets")
        structure = Library.default().type("umilib_protocol_ethernet_MACAddress")()
        Library.default().call("umilib_protocol_ethernet_mac_address_from_ipv4_multicast", bytes(address), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_ipv6_multicast(cls, address: bytes) -> MACAddress:
        """The address an IPv6 multicast address maps to (RFC 2464 §7)."""
        if len(address) != 16:
            raise ValueError("an IPv6 address has 16 octets")
        structure = Library.default().type("umilib_protocol_ethernet_MACAddress")()
        Library.default().call("umilib_protocol_ethernet_mac_address_from_ipv6_multicast", bytes(address), ctypes.byref(structure))
        return cls.from_structure(structure)

    def __str__(self) -> str:
        return Library.default().output("umilib_protocol_ethernet_mac_address_to_string", self.to_structure()).decode("utf-8")

    def __repr__(self) -> str:
        return f"MACAddress('{self}')"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MACAddress) and other.octets == self.octets

    def __lt__(self, other: MACAddress) -> bool:
        return self.octets < other.octets

    def __hash__(self) -> int:
        return hash(self.octets)

    def __bytes__(self) -> bytes:
        return self.octets


MACAddress.ZERO = MACAddress(bytes(6))
MACAddress.BROADCAST = MACAddress(b"\xff" * 6)


class EtherType(int):
    """The type field of a frame: an EtherType from 0x0600, or up to 1,500 the length of an IEEE
    802.3 frame's data. Values without a constant are kept as they are."""

    IPV4: ClassVar[EtherType]
    ARP: ClassVar[EtherType]
    WAKE_ON_LAN: ClassVar[EtherType]
    VLAN: ClassVar[EtherType]
    IPV6: ClassVar[EtherType]
    MPLS: ClassVar[EtherType]
    MPLS_MULTICAST: ClassVar[EtherType]
    PPPOE_DISCOVERY: ClassVar[EtherType]
    PPPOE_SESSION: ClassVar[EtherType]
    SERVICE_VLAN: ClassVar[EtherType]
    LLDP: ClassVar[EtherType]
    MACSEC: ClassVar[EtherType]
    EXPERIMENTAL_1: ClassVar[EtherType]
    EXPERIMENTAL_2: ClassVar[EtherType]
    MAXIMUM_LENGTH: ClassVar[int] = 1500
    MINIMUM: ClassVar[int] = 0x0600

    def __new__(cls, value: int) -> EtherType:
        if not 0 <= value <= 0xFFFF:
            raise ValueError("a type field is 0 to 0xFFFF")
        return super().__new__(cls, value)

    def is_length(self) -> bool:
        return bool(Library.default().function("umilib_protocol_ethernet_ether_type_is_length")(int(self)))

    def is_ether_type(self) -> bool:
        return bool(Library.default().function("umilib_protocol_ethernet_ether_type_is_ether_type")(int(self)))

    def is_tag(self) -> bool:
        """Whether the EtherType is that of a VLAN tag."""
        return bool(Library.default().function("umilib_protocol_ethernet_ether_type_is_tag")(int(self)))

    def __str__(self) -> str:
        return f"{int(self):#06x}"

    def __repr__(self) -> str:
        return f"EtherType({int(self):#06x})"


for _name, _value in [
    ("IPV4", 0x0800), ("ARP", 0x0806), ("WAKE_ON_LAN", 0x0842), ("VLAN", 0x8100), ("IPV6", 0x86DD), ("MPLS", 0x8847),
    ("MPLS_MULTICAST", 0x8848), ("PPPOE_DISCOVERY", 0x8863), ("PPPOE_SESSION", 0x8864), ("SERVICE_VLAN", 0x88A8),
    ("LLDP", 0x88CC), ("MACSEC", 0x88E5), ("EXPERIMENTAL_1", 0x88B5), ("EXPERIMENTAL_2", 0x88B6),
]:  # fmt: skip
    setattr(EtherType, _name, EtherType(_value))
del _name, _value


@dataclasses.dataclass(frozen=True)
class VLANTag:
    """A VLAN tag (IEEE 802.1Q): the tag protocol identifier, the priority (0 to 7), the drop
    eligible indicator and the VLAN identifier (0 to 4,095)."""

    LENGTH: ClassVar[int] = 4

    protocol: EtherType
    priority: int = 0
    drop_eligible: bool = False
    identifier: int = 0

    @classmethod
    def from_control(cls, protocol: int, control: int) -> VLANTag:
        """The tag of ``protocol`` with the tag control information ``control``."""
        return cls.from_structure(Library.default().function("umilib_protocol_ethernet_vlan_tag_from_control")(int(protocol), control))

    def control(self) -> int | None:
        """The tag control information; ``None`` if a field does not fit."""
        out = ctypes.c_uint16()
        try:
            Library.default().call("umilib_protocol_ethernet_vlan_tag_control", self.to_structure(), ctypes.byref(out))
        except EthernetError:
            return None
        return out.value

    @classmethod
    def from_structure(cls, structure: Any) -> VLANTag:
        return cls(EtherType(structure.protocol), structure.priority, bool(structure.drop_eligible), structure.identifier)

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_ethernet_VLANTag")()
        for name, value in (("protocol", int(self.protocol)), ("priority", self.priority), ("identifier", self.identifier)):
            Fields.assign(structure, name, value)
        structure.drop_eligible = self.drop_eligible
        return structure


@dataclasses.dataclass
class EthernetHeader:
    """The header of a frame: the addresses, up to two VLAN tags (outermost first) and the type field."""

    MINIMUM_LENGTH: ClassVar[int] = 14
    MAXIMUM_TAGS: ClassVar[int] = 2

    destination: MACAddress
    source: MACAddress
    ether_type: EtherType
    tags: list[VLANTag] = dataclasses.field(default_factory=list)

    def length(self) -> int:
        """The length of the header with its tags."""
        return EthernetHeader.MINIMUM_LENGTH + VLANTag.LENGTH * len(self.tags)

    @classmethod
    def from_structure(cls, structure: Any) -> EthernetHeader:
        tags = [VLANTag.from_structure(structure.tags[index]) for index in range(structure.tag_count)]
        return cls(MACAddress.from_structure(structure.destination), MACAddress.from_structure(structure.source), EtherType(structure.ether_type), tags)

    def to_structure(self) -> Any:
        if len(self.tags) > EthernetHeader.MAXIMUM_TAGS:
            raise EthernetError("protocol.ethernet", "Tag", "the VLAN tags are invalid")
        structure = Library.default().type("umilib_protocol_ethernet_EthernetHeader")()
        structure.destination = self.destination.to_structure()
        structure.source = self.source.to_structure()
        for index, tag in enumerate(self.tags):
            structure.tags[index] = tag.to_structure()
        structure.tag_count = len(self.tags)
        structure.ether_type = int(self.ether_type)
        return structure

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> tuple[EthernetHeader, bytes]:
        """The header at the start of ``data`` and the data after it (that of an IEEE 802.3 frame is
        its length); raises ``Length``, ``Tag`` or ``EtherType``."""
        data = bytes(data)
        structure = Library.default().type("umilib_protocol_ethernet_EthernetHeader")()
        offset, length = ctypes.c_size_t(), ctypes.c_size_t()
        Library.default().call("umilib_protocol_ethernet_ethernet_header_decode", data, len(data), ctypes.byref(structure), ctypes.byref(offset), ctypes.byref(length))
        return cls.from_structure(structure), data[offset.value : offset.value + length.value]

    def encode(self) -> bytes:
        """The bytes of the header; raises ``Tag`` or ``EtherType``."""
        return Library.default().output("umilib_protocol_ethernet_ethernet_header_encode", ctypes.byref(self.to_structure()))


class EthernetFrame:
    """The padding to the smallest frame and the frame check sequence (CRC-32, sent least
    significant byte first) of a frame (IEEE 802.3 §3.2)."""

    FCS_LENGTH = 4
    MINIMUM_LENGTH = 64
    MAXIMUM_DATA_LENGTH = 1500

    @staticmethod
    def fcs(frame: bytes | bytearray | memoryview) -> bytes:
        """The frame check sequence of the header and the data, in the order it is sent."""
        out = (ctypes.c_uint8 * EthernetFrame.FCS_LENGTH)()
        Library.default().call("umilib_protocol_ethernet_ethernet_frame_fcs", *Bytes.readable(frame), out)
        return bytes(out)

    @staticmethod
    def verify(frame: bytes | bytearray | memoryview) -> bool:
        """Whether ``frame`` ends with the right frame check sequence."""
        return Library.default().value("umilib_protocol_ethernet_ethernet_frame_verify", ctypes.c_bool, *Bytes.readable(frame))

    @staticmethod
    def padding(length: int) -> int:
        """The zero bytes to append to a header and data of ``length`` bytes."""
        return Library.default().function("umilib_protocol_ethernet_ethernet_frame_padding")(length)


__all__ = ["EtherType", "EthernetError", "EthernetFrame", "EthernetHeader", "MACAddress", "VLANTag"]
