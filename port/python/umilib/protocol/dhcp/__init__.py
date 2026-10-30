"""DHCP: what both versions share, the DUID (RFC 9915 §11), which DHCPv4 clients also use in their client
identifier (RFC 4361 §6.1). Mirrors ``umilib::protocol::dhcp``.

Instants are nanoseconds of the caller's monotonic clock; durations are :class:`datetime.timedelta`, or
``None`` for infinity. Errors are :class:`DHCPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Library

P = "umilib_protocol_dhcp"


class DHCPError(FFIError):
    """An error of DHCP: ``Malformed``, ``TooLarge``, ``State`` (not possible in the client's state),
    ``Config`` (a configuration that cannot work) or ``Random``."""


Library.register_error("protocol.dhcp", DHCPError)


class DHCPTime:
    """Conversions between the durations of the C ABI, milliseconds with ``INFINITY`` for infinity, and
    :class:`datetime.timedelta` or ``None``."""

    INFINITY: ClassVar[int] = (1 << 64) - 1

    @staticmethod
    def to_milliseconds(duration: datetime.timedelta | None) -> int:
        if duration is None:
            return DHCPTime.INFINITY
        milliseconds = (duration.days * 86_400 + duration.seconds) * 1000 + duration.microseconds // 1000
        if milliseconds < 0:
            raise ValueError("a duration cannot be negative")
        return min(milliseconds, DHCPTime.INFINITY - 1)

    @staticmethod
    def from_milliseconds(milliseconds: int) -> datetime.timedelta | None:
        return None if milliseconds == DHCPTime.INFINITY else datetime.timedelta(milliseconds=milliseconds)


@dataclasses.dataclass(frozen=True)
class DHCPDUID:
    """A DHCP Unique Identifier (RFC 9915 §11): of the type ``kind`` (``LLT``, ``EN``, ``LL``, ``UUID``,
    or another kept as it is), the ``hardware`` type of DUID-LLT and DUID-LL, the ``time`` of DUID-LLT,
    the ``enterprise`` number of DUID-EN, and its variable ``data``: the link-layer address, the
    identifier, the 16 bytes of the UUID, or the data of another type. Of 2 to 130 bytes."""

    LLT: ClassVar[int] = 1
    EN: ClassVar[int] = 2
    LL: ClassVar[int] = 3
    UUID: ClassVar[int] = 4
    #: The hardware type of Ethernet (IANA's ARP parameters).
    ETHERNET: ClassVar[int] = 1
    MAXIMUM_LENGTH: ClassVar[int] = 130

    kind: int
    data: bytes = b""
    hardware: int = 0
    time: int = 0
    enterprise: int = 0

    @classmethod
    def llt(cls, hardware: int, time: int, address: bytes) -> DHCPDUID:
        """DUID-LLT (§11.2): a hardware type, the seconds of :meth:`time_of`, a link-layer address."""
        return cls(DHCPDUID.LLT, bytes(address), hardware=hardware, time=time)

    @classmethod
    def en(cls, enterprise: int, identifier: bytes) -> DHCPDUID:
        """DUID-EN (§11.3): a vendor's enterprise number and identifier."""
        return cls(DHCPDUID.EN, bytes(identifier), enterprise=enterprise)

    @classmethod
    def ll(cls, hardware: int, address: bytes) -> DHCPDUID:
        """DUID-LL (§11.4): a hardware type and a link-layer address."""
        return cls(DHCPDUID.LL, bytes(address), hardware=hardware)

    @classmethod
    def uuid(cls, uuid: bytes) -> DHCPDUID:
        """DUID-UUID (RFC 6355 §4)."""
        return cls(DHCPDUID.UUID, bytes(uuid))

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a field that does not fit."""
        structure = Library.default().type(f"{P}_DHCPDUID")()
        for name in ("kind", "hardware", "time", "enterprise"):
            Fields.assign(structure, name, getattr(self, name))
        return structure

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> DHCPDUID:
        """The DUID of ``data``; raises ``Malformed`` for one of fewer than 3 or more than 130 bytes, or of a
        known type shorter than its fixed fields."""
        structure, buffer = Library.default().type(f"{P}_DHCPDUID")(), Buffer()
        Library.default().call(f"{P}_dhcp_duid_decode", *Bytes.readable(data), ctypes.byref(structure), ctypes.byref(buffer))
        variable = Library.default().take(buffer)
        return cls(structure.kind, variable, structure.hardware, structure.time, structure.enterprise)

    def encode(self) -> bytes:
        """Its bytes; raises ``Malformed`` for one that :meth:`decode` would refuse."""
        return Library.default().output(f"{P}_dhcp_duid_encode", self.to_structure(), *Bytes.readable(self.data))

    @staticmethod
    def time_of(unix: int) -> int:
        """The time of a DUID-LLT made at ``unix`` seconds since 1970: seconds since 2000-01-01 UTC, modulo
        2^32 (§11.2). It is ``DHCPDUID::time`` of Rust, renamed beside the field ``time``."""
        return Library.default().function(f"{P}_dhcp_duid_time")(unix)


__all__ = ["DHCPDUID", "DHCPError", "DHCPTime"]
