"""Tests of umilib.protocol.http: fields (RFC 9110 §5), requests and responses, HTTPRule, and
exchanges over HTTP/1.1 (RFC 9112), HTTP/2 (RFC 9113) and HTTP/3 (RFC 9114) driven from Python."""

import pytest
from test_protocol_quic import CLIENT, NOW, SERVER
from test_protocol_tls import TIME, certified, verifier

from umilib.protocol.http import (
    HTTPConnection,
    HTTPError,
    HTTPEventKind,
    HTTPFields,
    HTTPRequest,
    HTTPReset,
    HTTPResponse,
    HTTPRule,
    HTTPStatus,
    HTTPVersion,
)
from umilib.protocol.http.v1 import H1Connection, H1Limits
from umilib.protocol.http.v2 import H2Config, H2Connection
from umilib.protocol.http.v3 import H3Connection, H3Session
from umilib.protocol.quic import QUICConfig, QUICEndpoint
from umilib.protocol.tls import TLSClientConfig, TLSConfig, TLSServerConfig


def test_fields():
    fields = HTTPFields.of([(b"Accept", b"text/html"), (b"accept", b"*/*")])
    assert fields.lines() == [(b"accept", b"text/html"), (b"accept", b"*/*")], "names are lowercased"
    assert fields.get(b"ACCEPT") == b"text/html, */*", "lines are joined (RFC 9110 §5.3)"
    assert fields.get(b"missing") is None
    fields.set(b"accept", b"application/json")
    assert len(fields) == 1 and fields.remove(b"accept") and not fields.remove(b"accept")
    for name, value in [(b"bad name", b"x"), (b"", b"x"), (b"x", b"a\r\nb"), (b"x", b"\x00")]:
        with pytest.raises(HTTPError) as error:
            fields.append(name, value)
        assert error.value.name == "Malformed"
    fields.append(b"authorization", b"secret")
    fields.set_sensitive(0, True)
    assert fields.line(0) == (b"authorization", b"secret", True)


def test_requests_and_responses():
    request = HTTPRequest.new(b"GET", b"HTTPS", b"example.com", b"/a?b")
    assert (request.method, request.scheme, request.host(), request.path) == (b"GET", b"https", b"example.com", b"/a?b")
    request.fields = HTTPFields.of([(b"x-a", b"1")])
    assert request.fields.get(b"x-a") == b"1"
    request.check()
    connect = HTTPRequest.connect(b"example.com")
    with pytest.raises(HTTPError):
        connect.check()  # a CONNECT needs a port (RFC 9110 §9.3.6)
    HTTPRequest.connect(b"example.com:443").check()
    request.protocol = b"websocket"
    assert request.protocol == b"websocket"
    with pytest.raises(HTTPError):
        HTTPRequest.new(b"G T", b"http", b"a", b"/")
    response = HTTPResponse.new(404)
    assert response.status == 404 and response.status.reason == "Not Found"
    assert HTTPStatus(418).reason == "(Unused)"


def test_rules():
    rule = HTTPRule.new(b"Auth.Example.com", b"/oauth/*").with_method(b"POST").with_field(b"Content-Type", b"application/json*")
    request = HTTPRequest.new(b"POST", b"https", b"auth.example.COM:8443", b"/oauth/token")
    assert not rule.matches(request)
    request.fields = HTTPFields.of([(b"content-type", b"application/json; charset=utf-8")])
    assert rule.matches(request)
    assert not rule.matches(HTTPRequest.new(b"POST", b"https", b"other.example.com", b"/oauth/token"))
    with pytest.raises(HTTPError) as error:
        HTTPRule.new(b"a*b", b"*")
    assert error.value.name == "InvalidPattern"


def events(connection: HTTPConnection) -> list:
    out = []
    while (event := connection.poll_event()) is not None:
        out.append(event)
    return out


def exchange(client: HTTPConnection, server: HTTPConnection, move) -> None:
    """A request with content and trailers, and a response, over ``move`` (which carries bytes both ways)."""
    request = HTTPRequest.new(b"POST", b"http", b"example.com", b"/upload")
    request.fields = HTTPFields.of([(b"content-type", b"text/plain")])
    stream = client.send_request(request, end=False)
    assert client.send_data(stream, b"hello ") == 6
    client.send_data(stream, b"server", end=False)
    client.send_trailers(stream, HTTPFields.of([(b"x-checksum", b"42")]))
    move()
    received = events(server)
    head = received[0]
    assert head.kind == HTTPEventKind.REQUEST and not head.end
    assert (head.request.method, head.request.path, head.request.fields.get(b"content-type")) == (b"POST", b"/upload", b"text/plain")
    assert server.read_data(head.stream) == b"hello server"
    trailers = [event for event in received if event.kind == HTTPEventKind.TRAILERS]
    assert trailers and trailers[0].fields.get(b"x-checksum") == b"42"
    response = HTTPResponse.new(200)
    response.fields = HTTPFields.of([(b"content-length", b"2")])
    server.send_response(head.stream, response)
    server.send_data(head.stream, b"ok", end=True)
    move()
    received = events(client)
    assert received[0].kind == HTTPEventKind.RESPONSE and received[0].response.status == 200
    assert client.read_data(stream) == b"ok"
    assert HTTPEventKind.END in [event.kind for event in received]


def test_http_1_1():
    client, server = H1Connection.client(NOW), H1Connection.server(NOW, H1Limits(maximum_pipelined=4))

    def move():
        for _ in range(4):
            server.receive(client.transmit(), NOW)
            client.receive(server.transmit(), NOW)

    exchange(client, server, move)
    assert client.version() == HTTPVersion(1, 1)
    # A request line that is not one: the server answers 400 and closes (RFC 9112 §3).
    bad = H1Connection.server(NOW)
    bad.receive(b"GET\r\n\r\n", NOW)
    assert bad.transmit().startswith(b"HTTP/1.1 400 ")
    assert bad.wants_close()
    assert bad.poll_timeout() is not None


def test_http_2():
    config = H2Config.default()
    assert config.max_concurrent_streams == 100 and config.http.maximum_events == 4096
    client, server = H2Connection.client(NOW), H2Connection.server(NOW, config)

    def move():
        for _ in range(6):
            server.receive(client.transmit(), NOW)
            client.receive(server.transmit(), NOW)

    move()
    exchange(client, server, move)
    assert server.version() == HTTPVersion(2, 0)
    stream = client.send_request(HTTPRequest.new(b"GET", b"https", b"example.com", b"/"), end=True)
    client.reset(stream, HTTPReset.CANCEL)
    move()
    resets = [event for event in events(server) if event.kind == HTTPEventKind.RESET]
    assert resets and resets[0].code == 0x8, "CANCEL (RFC 9113 §7)"
    client.ping(b"12345678")
    client.shutdown()
    move()
    assert HTTPEventKind.GO_AWAY in [event.kind for event in events(server)]


def test_http_3():
    tls = TLSConfig()
    tls.set_protocols([b"h3"])
    client_tls, server_tls = TLSClientConfig.new(tls, verifier()), TLSServerConfig.new(tls, [certified("server-p256")])
    config = QUICConfig()
    client_endpoint = QUICEndpoint(config, seed=bytes([1]) * 48)
    server_endpoint = QUICEndpoint(config, server_tls, seed=bytes([2]) * 48)
    quic = client_endpoint.connect(client_tls, "server.example", SERVER, NOW, TIME, seed=bytes([3]) * 48)
    client = H3Session(H3Connection.client(NOW), quic)
    sessions: list[H3Session] = []

    def move():
        for _ in range(50):
            while (out := client_endpoint.transmit(NOW)) is not None:
                server_endpoint.receive(out[1], CLIENT, NOW, TIME)
            while (out := server_endpoint.transmit(NOW)) is not None:
                client_endpoint.receive(out[1], SERVER, NOW, TIME)
            if (accepted := server_endpoint.accept()) is not None:
                sessions.append(H3Session(H3Connection.server(NOW), accepted))
            client.process(NOW)
            for session in sessions:
                session.process(NOW)

    move()
    exchange(client, sessions[0], move)
    assert client.version() == HTTPVersion(3, 0)
