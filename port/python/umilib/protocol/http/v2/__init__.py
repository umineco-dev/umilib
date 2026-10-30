"""HTTP/2 (RFC 9113). Mirrors ``umilib::protocol::http::v2``.

An :class:`H2Connection` does no I/O, as :class:`~umilib.protocol.http.v1.H1Connection` does not.
"""

from __future__ import annotations

import ctypes
import dataclasses
from typing import Any, ClassVar

from umilib.codec.hpack import HPACKDecoderConfig, HPACKEncoderConfig
from umilib.ffi import Bytes, Handle, Library, Structures
from umilib.protocol.http import HTTPConfig, HTTPConnection

P = "umilib_protocol_http_v2"

__all__ = ["H2Config", "H2Connection"]


@dataclasses.dataclass
class H2Config:
    """The configuration of HTTP/2 connections; durations in milliseconds, 0 for no timeout. The
    defaults are those of the library (:meth:`default`)."""

    C_TYPE: ClassVar[str] = f"{P}_H2Config"

    http: HTTPConfig
    hpack_encoder: HPACKEncoderConfig
    hpack_decoder: HPACKDecoderConfig
    max_concurrent_streams: int
    initial_window_size: int
    connection_window: int
    max_frame_size: int
    enable_connect_protocol: bool
    settings_timeout: int
    idle_timeout: int
    maximum_resets: int
    reset_window: int
    maximum_pending_control: int
    maximum_field_block: int

    @classmethod
    def default(cls) -> H2Config:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_h2_config_default", ctypes.byref(structure))
        return Structures.from_structure(cls, structure)


class H2Connection(Handle, HTTPConnection):
    """An HTTP/2 connection of a client or a server."""

    FREE = f"{P}_h2_connection_free"

    def call(self, name: str, *arguments: Any) -> None:
        self.library.call(f"{P}_h2_connection_{name}", self.handle, *arguments)

    @classmethod
    def client(cls, now: int, config: H2Config | None = None) -> H2Connection:
        """A client's connection; it transmits the preface first."""
        structure = Structures.to_structure(config or H2Config.default())
        return cls(Handle.create(f"{P}_h2_connection_client", ctypes.byref(structure), now))

    @classmethod
    def server(cls, now: int, config: H2Config | None = None) -> H2Connection:
        structure = Structures.to_structure(config or H2Config.default())
        return cls(Handle.create(f"{P}_h2_connection_server", ctypes.byref(structure), now))

    def receive(self, data: bytes, now: int) -> None:
        self.call("receive", *Bytes.readable(data), now)

    def receive_close(self) -> None:
        self.call("receive_close")

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_h2_connection_transmit", self.handle)

    def wants_close(self) -> bool:
        return self.library.value(f"{P}_h2_connection_wants_close", ctypes.c_bool, self.handle)

    def wants_receive(self) -> bool:
        """Whether to read more from the transport: false while events wait up to their limit."""
        return self.library.value(f"{P}_h2_connection_wants_receive", ctypes.c_bool, self.handle)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_h2_connection_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.call("expire", now)

    def ping(self, data: bytes) -> None:
        """Sends a PING of 8 bytes (RFC 9113 §6.7)."""
        if len(data) != 8:
            raise ValueError("a PING carries 8 bytes")
        self.call("ping", data)
