"""The Address Resolution Protocol (RFC 826) for MAC and IPv4 addresses: its packets and the cache
that resolves addresses with them (RFC 1122 §2.3.2), without I/O; probes and announcements are those
of RFC 5227. Mirrors ``umilib::protocol::arp``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`.
Errors are :class:`ARPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.ffi import Bytes, FFIError, Fields, Handle, Library, Nanoseconds
from umilib.protocol.ethernet import EtherType, MACAddress
from umilib.protocol.ip import IPv4Address

P = "umilib_protocol_arp"


class ARPError(FFIError):
    """An error of ARP: ``Length`` or ``Limit``."""


Library.register_error("protocol.arp", ARPError)


class ARPHardwareType(int):
    """The hardware type of a packet (the IANA registry "Hardware Types")."""

    ETHERNET: ClassVar[ARPHardwareType]
    IEEE_802: ClassVar[ARPHardwareType]
    INFINIBAND: ClassVar[ARPHardwareType]

    def __new__(cls, value: int) -> ARPHardwareType:
        if not 0 <= value <= 0xFFFF:
            raise ValueError("a hardware type is 0 to 0xFFFF")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"ARPHardwareType({int(self)})"


class ARPOperation(int):
    """The operation of a packet (the IANA registry "Operation Codes")."""

    REQUEST: ClassVar[ARPOperation]
    REPLY: ClassVar[ARPOperation]

    def __new__(cls, value: int) -> ARPOperation:
        if not 0 <= value <= 0xFFFF:
            raise ValueError("an operation is 0 to 0xFFFF")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"ARPOperation({int(self)})"


ARPHardwareType.ETHERNET = ARPHardwareType(1)
ARPHardwareType.IEEE_802 = ARPHardwareType(6)
ARPHardwareType.INFINIBAND = ARPHardwareType(32)
ARPOperation.REQUEST = ARPOperation(1)
ARPOperation.REPLY = ARPOperation(2)


@dataclasses.dataclass(frozen=True)
class ARPPacket:
    """An ARP packet (RFC 826) of MAC and IPv4 addresses."""

    hardware_type: ARPHardwareType
    protocol_type: EtherType
    operation: ARPOperation
    sender_hardware: MACAddress
    sender_protocol: IPv4Address
    target_hardware: MACAddress
    target_protocol: IPv4Address

    @classmethod
    def from_structure(cls, structure: Any) -> ARPPacket:
        return cls(
            ARPHardwareType(structure.hardware_type),
            EtherType(structure.protocol_type),
            ARPOperation(structure.operation),
            MACAddress.from_structure(structure.sender_hardware),
            IPv4Address.from_structure(structure.sender_protocol),
            MACAddress.from_structure(structure.target_hardware),
            IPv4Address.from_structure(structure.target_protocol),
        )

    def to_structure(self) -> Any:
        return Library.default().type(f"{P}_ARPPacket")(
            int(self.hardware_type),
            int(self.protocol_type),
            int(self.operation),
            self.sender_hardware.to_structure(),
            self.sender_protocol.to_structure(),
            self.target_hardware.to_structure(),
            self.target_protocol.to_structure(),
        )

    @staticmethod
    def length() -> int:
        return 28

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> ARPPacket:
        """The packet at the start of ``data``; raises ``Length``."""
        structure = Library.default().type(f"{P}_ARPPacket")()
        Library.default().call(f"{P}_arp_packet_decode", *Bytes.readable(data), ctypes.byref(structure))
        return cls.from_structure(structure)

    def encode(self) -> bytes:
        return Library.default().output(f"{P}_arp_packet_encode", self.to_structure())

    @classmethod
    def ethernet_request(cls, sender_hardware: MACAddress, sender_protocol: IPv4Address, target: IPv4Address) -> ARPPacket:
        """A request on Ethernet for the hardware address of ``target`` (0.0.0.0 as the sender for a probe)."""
        function = Library.default().function(f"{P}_arp_packet_ethernet_request")
        return cls.from_structure(function(sender_hardware.to_structure(), sender_protocol.to_structure(), target.to_structure()))

    def reply(self, hardware: MACAddress) -> ARPPacket:
        """The reply to this request from ``hardware``, the hardware address of its target."""
        return ARPPacket.from_structure(Library.default().function(f"{P}_arp_packet_reply")(self.to_structure(), hardware.to_structure()))

    def is_probe(self) -> bool:
        return bool(Library.default().function(f"{P}_arp_packet_is_probe")(self.to_structure()))

    def is_announcement(self) -> bool:
        return bool(Library.default().function(f"{P}_arp_packet_is_announcement")(self.to_structure()))


@dataclasses.dataclass(frozen=True)
class ARPConfig:
    """The parameters of an :class:`ARPCache` (RFC 1122 §2.3.2)."""

    hardware_type: int = 1
    protocol_type: int = 0x0800
    timeout: datetime.timedelta = datetime.timedelta(seconds=60)
    retransmission_interval: datetime.timedelta = datetime.timedelta(seconds=1)
    maximum_requests: int = 3
    maximum_entries: int = 512
    maximum_queued: int = 1

    def to_structure(self) -> Any:
        structure = Library.default().type(f"{P}_ARPConfig")()
        values = {
            "hardware_type": self.hardware_type,
            "protocol_type": self.protocol_type,
            "timeout": Nanoseconds.from_timedelta(self.timeout),
            "retransmission_interval": Nanoseconds.from_timedelta(self.retransmission_interval),
            "maximum_requests": self.maximum_requests,
            "maximum_entries": self.maximum_entries,
            "maximum_queued": self.maximum_queued,
        }
        for name, value in values.items():
            Fields.assign(structure, name, value)
        return structure


class ARPResolution(enum.IntEnum):
    """The kind of answer of :meth:`ARPCache.resolve`."""

    RESOLVED = 0
    REQUEST = 1
    PENDING = 2


class ARPReception(Handle):
    """What :meth:`ARPCache.receive` makes of a packet: the reply to send, the packets kept for the
    sender's address, now resolved, and whether the packet claims a local address from elsewhere."""

    FREE = f"{P}_arp_reception_free"

    @property
    def reply(self) -> ARPPacket | None:
        found = ctypes.c_bool()
        reply = self.library.type(f"{P}_ARPPacket")()
        self.library.call(f"{P}_arp_reception_reply", self.handle, ctypes.byref(found), ctypes.byref(reply))
        return ARPPacket.from_structure(reply) if found.value else None

    @property
    def resolved(self) -> list[bytes]:
        count = self.library.value(f"{P}_arp_reception_resolved_count", ctypes.c_size_t, self.handle)
        return [self.library.output(f"{P}_arp_reception_resolved_get", self.handle, index) for index in range(count)]

    @property
    def conflict(self) -> bool:
        return self.library.value(f"{P}_arp_reception_conflict", ctypes.c_bool, self.handle)


class ARPEvent(Handle):
    """What :meth:`ARPCache.poll` reports: a request to send again (``kind`` :attr:`REQUEST`) or an
    address that did not answer (:attr:`UNREACHABLE`), with the packets dropped for it."""

    FREE = f"{P}_arp_event_free"
    REQUEST: ClassVar[int] = 1
    UNREACHABLE: ClassVar[int] = 2

    def kind_and_address(self) -> tuple[int, IPv4Address]:
        kind = ctypes.c_uint8()
        address = self.library.type("umilib_protocol_ip_IPv4Address")()
        self.library.call(f"{P}_arp_event_address", self.handle, ctypes.byref(kind), ctypes.byref(address))
        return kind.value, IPv4Address.from_structure(address)

    @property
    def kind(self) -> int:
        return self.kind_and_address()[0]

    @property
    def address(self) -> IPv4Address:
        return self.kind_and_address()[1]

    @property
    def packets(self) -> list[bytes]:
        count = self.library.value(f"{P}_arp_event_packet_count", ctypes.c_size_t, self.handle)
        return [self.library.output(f"{P}_arp_event_packet_get", self.handle, index) for index in range(count)]


class ARPCache(Handle):
    """The translation table of ARP from IPv4 to MAC addresses, without I/O."""

    FREE = f"{P}_arp_cache_free"

    def __init__(self, config: ARPConfig = ARPConfig()) -> None:
        super().__init__(Handle.create(f"{P}_arp_cache_new", config.to_structure()))
        self.config = config

    def resolve(self, address: IPv4Address, packet: bytes | None, now: int) -> tuple[ARPResolution, MACAddress | None]:
        """The hardware address of ``address`` at ``now``, or the start (send a request) or wait of
        its resolution; ``packet`` is kept until it ends. Raises ``Limit``."""
        kind = ctypes.c_uint8()
        hardware = self.library.type("umilib_protocol_ethernet_MACAddress")()
        data, length = (None, 0) if packet is None else (bytes(packet), len(packet))
        self.library.call(f"{P}_arp_cache_resolve", self.handle, address.to_structure(), data, length, now, ctypes.byref(kind), ctypes.byref(hardware))
        resolution = ARPResolution(kind.value)
        return resolution, MACAddress.from_structure(hardware) if resolution == ARPResolution.RESOLVED else None

    def lookup(self, address: IPv4Address, now: int) -> MACAddress | None:
        found = ctypes.c_bool()
        hardware = self.library.type("umilib_protocol_ethernet_MACAddress")()
        self.library.call(f"{P}_arp_cache_lookup", self.handle, address.to_structure(), now, ctypes.byref(found), ctypes.byref(hardware))
        return MACAddress.from_structure(hardware) if found.value else None

    def insert_static(self, address: IPv4Address, hardware: MACAddress) -> None:
        self.library.call(f"{P}_arp_cache_insert_static", self.handle, address.to_structure(), hardware.to_structure())

    def remove(self, address: IPv4Address) -> bool:
        return self.library.value(f"{P}_arp_cache_remove", ctypes.c_bool, self.handle, address.to_structure())

    def receive(self, packet: ARPPacket, hardware: MACAddress, local: list[IPv4Address], now: int) -> ARPReception:
        """Processes a packet received at ``now`` on an interface of ``hardware`` and the protocol
        addresses ``local`` (RFC 826 "Packet Reception")."""
        addresses = (self.library.type("umilib_protocol_ip_IPv4Address") * max(len(local), 1))(*[address.to_structure() for address in local])
        pointer = ctypes.c_void_p()
        self.library.call(
            f"{P}_arp_cache_receive", self.handle, packet.to_structure(), hardware.to_structure(), addresses, len(local), now, ctypes.byref(pointer)
        )
        return ARPReception(pointer.value)

    def poll_timeout(self) -> int | None:
        """The earliest time at which :meth:`poll` has something to do."""
        return self.library.optional(f"{P}_arp_cache_poll_timeout", ctypes.c_uint64, self.handle)

    def poll(self, now: int) -> ARPEvent | None:
        """Advances the cache to ``now``: forgets expired addresses and returns the next request to
        send again or the next address that did not answer."""
        found = ctypes.c_bool()
        pointer = ctypes.c_void_p()
        self.library.call(f"{P}_arp_cache_poll", self.handle, now, ctypes.byref(found), ctypes.byref(pointer))
        if not found.value:
            return None
        return ARPEvent(pointer.value)


__all__ = ["ARPCache", "ARPConfig", "ARPError", "ARPEvent", "ARPHardwareType", "ARPOperation", "ARPPacket", "ARPReception", "ARPResolution"]
