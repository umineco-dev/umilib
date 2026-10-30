"""DNS over TCP (RFC 1035 §4.2.2, RFC 7766): the 2-byte length before each message, and a server's
connection that answers the queries of its stream. Mirrors ``umilib::protocol::dns::tcp``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Buffer, Bytes, Handle, Library
from umilib.protocol.dns import DNSAuthority
from umilib.protocol.ip import IPEndpoint

P = "umilib_protocol_dns_tcp"


class DNSTCPFramer(Handle):
    """The framing of messages on a stream."""

    FREE = f"{P}_dns_tcp_framer_free"

    def __init__(self) -> None:
        super().__init__(Handle.create(f"{P}_dns_tcp_framer_new"))

    @staticmethod
    def frame(message: bytes) -> bytes:
        """``message`` after its length in two bytes; raises ``TooLarge`` above 65535 bytes."""
        return Library.default().output(f"{P}_dns_tcp_framer_frame", *Bytes.readable(message))

    def receive(self, data: bytes) -> None:
        self.library.call(f"{P}_dns_tcp_framer_receive", self.handle, *Bytes.readable(data))

    def next_message(self) -> bytes | None:
        """The next whole message received; raises ``Malformed`` for a length of 0."""
        return self.library.optional(f"{P}_dns_tcp_framer_next_message", Buffer, self.handle)


class DNSTCPServer(Handle):
    """A server's connection over TCP; durations in milliseconds."""

    FREE = f"{P}_dns_tcp_server_free"

    def __init__(self, peer: IPEndpoint, now: int, idle_timeout: int = 10_000, read_timeout: int = 10_000) -> None:
        super().__init__(Handle.create(f"{P}_dns_tcp_server_new", peer.to_structure(), idle_timeout, read_timeout, now))

    def receive(self, data: bytes, authority: DNSAuthority, now: int, time: int = 0) -> None:
        self.library.call(f"{P}_dns_tcp_server_receive", self.handle, *Bytes.readable(data), authority.handle, now, time)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_dns_tcp_server_transmit", self.handle)

    def is_idle(self, now: int) -> bool:
        return self.library.value(f"{P}_dns_tcp_server_is_idle", ctypes.c_bool, self.handle, now)
