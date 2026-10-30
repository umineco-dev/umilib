"""DNS over TLS (RFC 7858): the messages of a TCP stream as the application data of a TLS connection
of :mod:`umilib.protocol.tls`. Mirrors ``umilib::protocol::dns::tls``."""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.ffi import Library


class DNSTLS:
    """The constants of DNS over TLS."""

    ALPN = b"dot"
    PORT = 853

    @staticmethod
    def check_protocol(connection: Any) -> bool:
        """Whether the application protocol ``connection`` negotiated is none or "dot"."""
        return Library.default().value("umilib_protocol_dns_tls_dns_tls_check_protocol", ctypes.c_bool, connection.handle)
