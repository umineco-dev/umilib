"""DNS over UDP (RFC 1035 §4.2.1). Mirrors ``umilib::protocol::dns::udp``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Library
from umilib.protocol.ip import IPEndpoint


class DNSUDP:
    """The rules of DNS over UDP."""

    PORT = 53

    @staticmethod
    def accepts(source: IPEndpoint, destination: IPEndpoint) -> bool:
        """Whether a datagram from ``source`` may answer a query sent to ``destination`` (RFC 5452 §9.1)."""
        return Library.default().value("umilib_protocol_dns_udp_dns_udp_accepts", ctypes.c_bool, source.to_structure(), destination.to_structure())
