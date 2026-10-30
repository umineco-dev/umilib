"""WebSocket's opening handshake over HTTP: HTTP/1.1 Upgrade (RFC 6455 §4), and extended CONNECT over
HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220). Mirrors ``umilib::protocol::http::websocket``."""

from __future__ import annotations

import ctypes
import os

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library
from umilib.protocol.http import HTTPRequest, HTTPResponse, HTTPVersion
from umilib.protocol.websocket import WebSocketDeflateParameters

P = "umilib_protocol_http_websocket"
W = "umilib_protocol_websocket"

__all__ = ["WebSocketAgreement", "WebSocketHandshake", "WebSocketHandshakeError", "WebSocketOffer"]


class WebSocketHandshakeError(FFIError):
    """``Rejected``: a response that does not complete the handshake offered."""


Library.register_error("protocol.http.websocket", WebSocketHandshakeError)


class WebSocketOffer(Handle):
    """What a client's handshake offers: its key (none over HTTP/2 and HTTP/3), subprotocols and
    offers of permessage-deflate, in its order of preference."""

    FREE = f"{P}_websocket_offer_free"

    @property
    def key(self) -> bytes | None:
        return self.library.optional(f"{P}_websocket_offer_key", Buffer, self.handle)

    @property
    def protocols(self) -> list[str]:
        count = self.library.value(f"{P}_websocket_offer_protocol_count", ctypes.c_size_t, self.handle)
        return [self.library.output(f"{P}_websocket_offer_protocol", self.handle, index).decode("utf-8") for index in range(count)]

    @property
    def deflate(self) -> list[WebSocketDeflateParameters]:
        count = self.library.value(f"{P}_websocket_offer_deflate_count", ctypes.c_size_t, self.handle)
        offers = []
        for index in range(count):
            structure = self.library.type(f"{W}_WebSocketDeflateParameters")()
            self.library.call(f"{P}_websocket_offer_deflate", self.handle, index, ctypes.byref(structure))
            offers.append(WebSocketDeflateParameters.from_structure(structure))
        return offers


class WebSocketAgreement(Handle):
    """What the two ends agreed: a subprotocol and permessage-deflate's parameters, if any."""

    FREE = f"{P}_websocket_agreement_free"

    @property
    def protocol(self) -> str | None:
        protocol = self.library.optional(f"{P}_websocket_agreement_protocol", Buffer, self.handle)
        return None if protocol is None else protocol.decode("utf-8")

    @property
    def deflate(self) -> WebSocketDeflateParameters | None:
        found = ctypes.c_bool()
        structure = self.library.type(f"{W}_WebSocketDeflateParameters")()
        self.library.call(f"{P}_websocket_agreement_deflate", self.handle, ctypes.byref(found), ctypes.byref(structure))
        return WebSocketDeflateParameters.from_structure(structure) if found.value else None


class WebSocketHandshake:
    """The steps of the opening handshake."""

    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    @staticmethod
    def accept(key: bytes) -> bytes:
        """The Sec-WebSocket-Accept value of ``key`` (RFC 6455 §4.2.2)."""
        return Library.default().output(f"{P}_websocket_handshake_accept", *Bytes.readable(key))

    @staticmethod
    def request(
        scheme: bytes,
        authority: bytes,
        path: bytes,
        protocols: list[str] | None = None,
        deflate: WebSocketDeflateParameters | None = None,
        seed: bytes | None = None,
    ) -> tuple[HTTPRequest, bytes]:
        """A client's HTTP/1.1 request and its key."""
        pointers, lengths, count, _kept = Bytes.array([protocol.encode("utf-8") for protocol in protocols or []])
        request, key = ctypes.c_void_p(), Buffer()
        Library.default().call(
            f"{P}_websocket_handshake_request", *Bytes.readable(scheme), *Bytes.readable(authority), *Bytes.readable(path),
            pointers, lengths, count, WebSocketDeflateParameters.pointer(deflate), *Bytes.readable(seed or os.urandom(48)),
            ctypes.byref(request), ctypes.byref(key),
        )  # fmt: skip
        return HTTPRequest(request.value), Library.default().take(key)

    @staticmethod
    def connect_request(
        scheme: bytes, authority: bytes, path: bytes, protocols: list[str] | None = None, deflate: WebSocketDeflateParameters | None = None
    ) -> HTTPRequest:
        """A client's extended CONNECT over HTTP/2 or HTTP/3."""
        pointers, lengths, count, _kept = Bytes.array([protocol.encode("utf-8") for protocol in protocols or []])
        return HTTPRequest(
            Handle.create(
                f"{P}_websocket_handshake_connect_request", *Bytes.readable(scheme), *Bytes.readable(authority), *Bytes.readable(path),
                pointers, lengths, count, WebSocketDeflateParameters.pointer(deflate),
            )  # fmt: skip
        )

    @staticmethod
    def check_request(request: HTTPRequest, version: HTTPVersion) -> WebSocketOffer | HTTPResponse:
        """A server's check: the offer, or the response to send instead (400, or 426)."""
        offer, response = ctypes.c_void_p(), ctypes.c_void_p()
        Library.default().call(
            f"{P}_websocket_handshake_check_request", request, version.major, version.minor, ctypes.byref(offer), ctypes.byref(response)
        )
        return WebSocketOffer(offer.value) if offer.value else HTTPResponse(response.value)

    @staticmethod
    def agree(offer: WebSocketOffer, supported: list[str], deflate: bool) -> WebSocketAgreement:
        """The first of ``supported`` the client offered, and its first permessage-deflate if ``deflate``."""
        pointers, lengths, count, _kept = Bytes.array([protocol.encode("utf-8") for protocol in supported])
        return WebSocketAgreement(Handle.create(f"{P}_websocket_handshake_agree", offer, pointers, lengths, count, deflate))

    @staticmethod
    def response(offer: WebSocketOffer, agreement: WebSocketAgreement) -> HTTPResponse:
        """The response that accepts: 101 over HTTP/1.1, 200 otherwise."""
        return HTTPResponse(Handle.create(f"{P}_websocket_handshake_response", offer, agreement))

    @staticmethod
    def check_response(
        response: HTTPResponse, key: bytes | None, protocols: list[str] | None = None, deflate: WebSocketDeflateParameters | None = None
    ) -> WebSocketAgreement:
        """A client's check against what it offered; raises ``Rejected``."""
        pointers, lengths, count, _kept = Bytes.array([protocol.encode("utf-8") for protocol in protocols or []])
        key_data, key_length = Bytes.readable(key) if key is not None else (None, 0)
        return WebSocketAgreement(
            Handle.create(
                f"{P}_websocket_handshake_check_response", response, key_data, key_length, pointers, lengths, count,
                WebSocketDeflateParameters.pointer(deflate),
            )  # fmt: skip
        )
