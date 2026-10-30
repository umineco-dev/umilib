"""Tests of umilib.protocol.websocket and umilib.protocol.http.websocket: the frames of RFC 6455 §5.7,
the closing handshake (§7), the failures of §5 and §8, permessage-deflate (RFC 7692 §7.2.3), and the
opening handshake over HTTP/1.1 (§4, with the key of §1.3) and HTTP/2 (RFC 8441)."""

import pytest
from test_protocol_quic import NOW

from umilib.protocol.http import HTTPEventKind, HTTPVersion
from umilib.protocol.http.v1 import H1Connection
from umilib.protocol.http.v2 import H2Config, H2Connection
from umilib.protocol.http.websocket import WebSocketHandshake, WebSocketHandshakeError, WebSocketOffer
from umilib.protocol.websocket import (
    WebSocketCloseCode,
    WebSocketConnection,
    WebSocketDeflateParameters,
    WebSocketError,
    WebSocketEventKind,
    WebSocketRole,
    WebSocketState,
)


def events(connection) -> list:
    out = []
    while (event := connection.poll_event()) is not None:
        out.append(event)
    return out


def test_the_frames_of_section_5_7():
    client = WebSocketConnection(WebSocketRole.CLIENT, seed=bytes(48))
    client.receive(bytes.fromhex("810548656c6c6f"))
    client.receive(bytes.fromhex("010348656c") + bytes.fromhex("80026c6f"))
    client.receive(bytes.fromhex("890548656c6c6f"))
    assert [(event.kind, event.data) for event in events(client)] == [
        (WebSocketEventKind.TEXT, b"Hello"), (WebSocketEventKind.TEXT, b"Hello"), (WebSocketEventKind.PING, b"Hello"),
    ]  # fmt: skip
    pong = client.transmit()
    assert pong[0] == 0x8A and pong[1] == 0x85, "a masked Pong of the Ping's data (§5.5.3)"
    server = WebSocketConnection(WebSocketRole.SERVER, seed=bytes(48))
    server.receive(bytes.fromhex("818537fa213d7f9f4d5158"))
    assert events(server)[0].text == "Hello"
    server.send_text("Hello")
    assert server.transmit() == bytes.fromhex("810548656c6c6f")


def test_messages_and_closing():
    client = WebSocketConnection(WebSocketRole.CLIENT, seed=bytes([1]) * 48)
    server = WebSocketConnection(WebSocketRole.SERVER, seed=bytes([2]) * 48)
    client.send_text("héllo")
    client.send_binary(bytes(range(256)))
    server.receive(client.transmit())
    assert [(event.kind, event.data) for event in events(server)] == [
        (WebSocketEventKind.TEXT, "héllo".encode()), (WebSocketEventKind.BINARY, bytes(range(256))),
    ]  # fmt: skip
    client.close(WebSocketCloseCode.NORMAL, "bye")
    assert client.state == WebSocketState.CLOSING
    server.receive(client.transmit())
    closed = events(server)[0]
    assert (closed.kind, closed.code, closed.data) == (WebSocketEventKind.CLOSED, 1000, b"bye")
    client.receive(server.transmit())
    assert client.wants_close() and server.wants_close() and client.state == WebSocketState.CLOSED
    with pytest.raises(WebSocketError) as error:
        client.send_text("late")
    assert error.value.name == "Refused"
    with pytest.raises(WebSocketError):
        WebSocketConnection(WebSocketRole.CLIENT, seed=bytes(48)).close(1005)  # not to be sent (§7.4.1)


def test_failures():
    # An unmasked frame to a server (§5.1) and text that is not UTF-8 (§8.1).
    for role, frame, code in [
        (WebSocketRole.SERVER, "810548656c6c6f", WebSocketCloseCode.PROTOCOL_ERROR),
        (WebSocketRole.CLIENT, "8102c328", WebSocketCloseCode.INVALID_PAYLOAD),
        (WebSocketRole.CLIENT, "8300", WebSocketCloseCode.PROTOCOL_ERROR),
    ]:
        connection = WebSocketConnection(role, seed=bytes(48))
        connection.receive(bytes.fromhex(frame))
        assert events(connection)[-1].code == code
        assert connection.wants_close() is False or connection.state == WebSocketState.CLOSED
    lost = WebSocketConnection(WebSocketRole.CLIENT, seed=bytes(48))
    lost.receive_close()
    assert events(lost)[0].code == WebSocketCloseCode.ABNORMAL


def test_the_deflate_examples_of_rfc_7692():
    client = WebSocketConnection(WebSocketRole.CLIENT, deflate=WebSocketDeflateParameters(), seed=bytes(48))
    client.receive(bytes.fromhex("c107f248cdc9c90700"))  # §7.2.3.1
    client.receive(bytes.fromhex("c105f200110000"))  # §7.2.3.2: the shared window
    assert [event.text for event in events(client)] == ["Hello", "Hello"]
    offer = WebSocketDeflateParameters(client_max_window_bits=0)
    assert offer.accept().client_max_window_bits is None


def test_the_accept_value_of_section_1_3():
    assert WebSocketHandshake.accept(b"dGhlIHNhbXBsZSBub25jZQ==") == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_over_http_1_1():
    deflate = WebSocketDeflateParameters()
    request, key = WebSocketHandshake.request(b"http", b"example.com", b"/chat", ["chat"], deflate, seed=bytes(48))
    assert len(key) == 24
    client, server = H1Connection.client(NOW), H1Connection.server(NOW)
    stream = client.send_request(request, end=False)
    server.receive(client.transmit(), NOW)
    received = events(server)[0]
    offer = WebSocketHandshake.check_request(received.request, HTTPVersion(1, 1))
    assert isinstance(offer, WebSocketOffer) and offer.key == key and offer.protocols == ["chat"] and offer.deflate == [deflate]
    agreement = WebSocketHandshake.agree(offer, ["chat"], True)
    assert agreement.protocol == "chat" and agreement.deflate == deflate
    server.send_response(received.stream, WebSocketHandshake.response(offer, agreement))
    client.receive(server.transmit(), NOW)
    response = events(client)[0].response
    assert response.status == 101
    agreed = WebSocketHandshake.check_response(response, key, ["chat"], deflate)
    assert agreed.protocol == "chat"
    with pytest.raises(WebSocketHandshakeError):
        WebSocketHandshake.check_response(response, b"dGhlIHNhbXBsZSBub25jZQ==", ["chat"], deflate)
    # Messages through the tunnel (RFC 9112 §6.3).
    websocket = WebSocketConnection(WebSocketRole.CLIENT, deflate=agreed.deflate, seed=bytes(48))
    peer = WebSocketConnection(WebSocketRole.SERVER, deflate=agreement.deflate, seed=bytes(48))
    websocket.send_text("over the tunnel")
    client.send_data(stream, websocket.transmit())
    server.receive(client.transmit(), NOW)
    peer.receive(server.read_data(received.stream))
    assert events(peer)[0].text == "over the tunnel"
    # A request of another version is refused with 426 and the version (§4.4).
    other, _ = WebSocketHandshake.request(b"http", b"example.com", b"/", seed=bytes(48))
    fields = other.fields
    fields.set(b"sec-websocket-version", b"8")
    other.fields = fields
    refused = WebSocketHandshake.check_request(other, HTTPVersion(1, 1))
    assert refused.status == 426 and refused.fields.get(b"sec-websocket-version") == b"13"


def test_over_http_2():
    config = H2Config.default()
    config.enable_connect_protocol = True
    client, server = H2Connection.client(NOW), H2Connection.server(NOW, config)

    def move():
        for _ in range(6):
            server.receive(client.transmit(), NOW)
            client.receive(server.transmit(), NOW)

    move()
    request = WebSocketHandshake.connect_request(b"https", b"example.com", b"/chat")
    assert request.protocol == b"websocket" and request.method == b"CONNECT"
    client.send_request(request, end=False)
    move()
    received = [event for event in events(server) if event.kind == HTTPEventKind.REQUEST][0]
    offer = WebSocketHandshake.check_request(received.request, HTTPVersion(2, 0))
    assert offer.key is None
    server.send_response(received.stream, WebSocketHandshake.response(offer, WebSocketHandshake.agree(offer, [], False)))
    move()
    response = [event for event in events(client) if event.kind == HTTPEventKind.RESPONSE][0].response
    assert response.status == 200
    assert WebSocketHandshake.check_response(response, None).deflate is None


def test_window_bits_out_of_range():
    # A uint8 field would wrap 264 to 8: the value is refused instead.
    with pytest.raises(OverflowError):
        WebSocketConnection(WebSocketRole.CLIENT, deflate=WebSocketDeflateParameters(server_max_window_bits=264), seed=bytes(48))


def test_events_wait_for_the_application():
    server = WebSocketConnection(WebSocketRole.SERVER, seed=bytes(48))
    server.receive(bytes.fromhex("898001020304") * 5000 + bytes.fromhex("818537fa213d7f9f4d5158"))
    assert not server.wants_receive()
    received = events(server)
    assert len(received) == 5001 and received[-1].text == "Hello"
    assert server.wants_receive()
