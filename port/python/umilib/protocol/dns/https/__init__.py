"""DNS queries over HTTPS (RFC 8484): the parts of the HTTP exchange, which is the caller's. Mirrors
``umilib::protocol::dns::https``."""

from __future__ import annotations

import ctypes

from umilib.ffi import Buffer, Bytes, Library, Text

P = "umilib_protocol_dns_https"


class DNSHTTPS:
    """The rules of DNS over HTTPS."""

    MEDIA_TYPE = "application/dns-message"
    PATH = "/dns-query"

    @staticmethod
    def get_path(query: bytes, path: str = PATH) -> str:
        """The path of the GET request of ``query``: the message in the "dns" variable (§4.1)."""
        return Library.default().output(f"{P}_dns_https_get_path", *Bytes.readable(query), *Text.encode(path)).decode()

    @staticmethod
    def query(method: str, path: str, content_type: str | None = None, content: bytes = b"") -> bytes | int:
        """The query of a request, or the HTTP status to answer it with (405, 415, 413, 414 or 400)."""
        status, out = ctypes.c_uint16(), Buffer()
        Library.default().call(
            f"{P}_dns_https_query", *Text.encode(method), *Text.encode(path), *Text.encode(content_type or ""), *Bytes.readable(content),
            ctypes.byref(status), ctypes.byref(out),
        )  # fmt: skip
        data = Library.default().take(out)
        return data if status.value == 0 else status.value

    @staticmethod
    def cache_control(message: bytes) -> str:
        """The Cache-Control of the response of ``message``: fresh for its least TTL (§5.1)."""
        return Library.default().output(f"{P}_dns_https_cache_control", *Bytes.readable(message)).decode()

    @staticmethod
    def check_response(status: int, content_type: str, content: bytes) -> None:
        """Raises ``Malformed`` unless a 2xx of "application/dns-message" (§4.2.1)."""
        Library.default().call(f"{P}_dns_https_check_response", status, *Text.encode(content_type), *Bytes.readable(content))
