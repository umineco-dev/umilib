"""Tests of umilib.protocol.quic: two endpoints driven from Python over a simulated network, with the
certificates OpenSSL made: the handshake (RFC 9000 §7, RFC 9001 §4), streams (RFC 9000 §2), DATAGRAM
frames (RFC 9221), Retry (RFC 9000 §8.1.2), closing (RFC 9000 §10.2) and the limits of the configuration."""

import pytest
from test_protocol_tls import TIME, certified, verifier

from umilib.protocol.ip import IPAddress, IPEndpoint
from umilib.protocol.quic import (
    QUICCloseReason,
    QUICConfig,
    QUICConnectionState,
    QUICEndpoint,
    QUICError,
    QUICEventKind,
    QUICLimits,
    QUICVersion,
)
from umilib.protocol.tls import TLSClientConfig, TLSConfig, TLSServerConfig

CLIENT = IPEndpoint(IPAddress.parse("192.0.2.2"), 50000)
SERVER = IPEndpoint(IPAddress.parse("192.0.2.1"), 443)
NOW = 1_000_000_000


def tls() -> tuple[TLSClientConfig, TLSServerConfig]:
    """The TLS configurations, with a protocol for ALPN (RFC 9001 §8.1)."""
    config = TLSConfig()
    config.set_protocols([b"test"])
    return TLSClientConfig.new(config, verifier()), TLSServerConfig.new(config, [certified("server-p256")])


def run(client: QUICEndpoint, server: QUICEndpoint) -> list[tuple[bool, bytes]]:
    """Moves datagrams both ways until both endpoints are quiet; returns them, with who sent each."""
    moved: list[tuple[bool, bytes]] = []
    for _ in range(1000):
        before = len(moved)
        while (out := client.transmit(NOW)) is not None:
            moved.append((True, out[1]))
            server.receive(out[1], CLIENT, NOW, TIME)
        while (out := server.transmit(NOW)) is not None:
            assert out[0] == CLIENT
            moved.append((False, out[1]))
            client.receive(out[1], SERVER, NOW, TIME)
        if len(moved) == before:
            return moved
    raise AssertionError("never quiet")


def pair(config: QUICConfig | None = None, **server: object):
    client_tls, server_tls = tls()
    config = config or QUICConfig()
    client = QUICEndpoint(config, seed=bytes([1]) * 48)
    endpoint = QUICEndpoint(config, server_tls, seed=bytes([2]) * 48, **server)
    connection = client.connect(client_tls, "server.example", SERVER, NOW, TIME, seed=bytes([3]) * 48)
    return client, endpoint, connection


def events(connection) -> list:
    out = []
    while (event := connection.poll_event()) is not None:
        out.append(event)
    return out


def test_a_handshake_and_a_stream():
    client, server, connection = pair()
    run(client, server)
    session = connection.session
    assert session.state == QUICConnectionState.ESTABLISHED and session.handshake_confirmed
    assert session.version == QUICVersion.V1
    assert connection.protocol == b"test"
    accepted = server.accept()
    assert accepted is not None and server.accept() is None
    stream = connection.open_stream(True)
    assert stream == 0
    assert connection.stream_send(stream, b"hello, server", fin=True) == 13
    run(client, server)
    kinds = [event.kind for event in events(accepted)]
    assert kinds[0] == QUICEventKind.CONNECTED and QUICEventKind.STREAM_OPENED in kinds
    assert accepted.stream_read(stream, 100) == (b"hello, server", True)
    accepted.stream_send(stream, b"hello, client", fin=True)
    run(client, server)
    assert connection.stream_read(stream, 100) == (b"hello, client", True)


def test_datagrams():
    config = QUICConfig()
    limits = config.limits
    limits.max_datagram_frame_size = 1200
    config.limits = limits
    client, server, connection = pair(config)
    run(client, server)
    connection.send_datagram(b"unreliable")
    run(client, server)
    accepted = server.accept()
    assert accepted.read_datagram() == b"unreliable"
    assert accepted.read_datagram() is None
    with pytest.raises(QUICError) as error:
        connection.send_datagram(bytes(1300))
    assert error.value.name == "State"


def test_retry():
    client, server, connection = pair(token_key=bytes(32), retry=True)
    datagrams = run(client, server)
    # A Retry: a long header of type 3 for version 1 (RFC 9000 §17.2.5).
    assert any(not from_client and data[0] & 0xF0 == 0xF0 for from_client, data in datagrams)
    assert connection.session.handshake_confirmed


def test_closing():
    client, server, connection = pair()
    run(client, server)
    accepted = server.accept()
    events(accepted)
    connection.close(42, b"bye", NOW)
    run(client, server)
    closed = [event for event in events(accepted) if event.kind == QUICEventKind.CLOSED]
    assert len(closed) == 1
    assert (closed[0].reason, closed[0].error, closed[0].data) == (QUICCloseReason.PEER_APPLICATION, 42, b"bye")
    assert accepted.session.state == QUICConnectionState.DRAINING
    timeout = client.poll_timeout()
    assert timeout is not None
    client.expire(timeout, TIME)


def test_limits():
    config = QUICConfig()
    limits = config.limits
    assert limits == QUICLimits()
    limits.datagram_size = 100
    with pytest.raises(QUICError) as error:
        config.limits = limits
    assert error.value.name == "Config"
    config.set_versions([QUICVersion.V2])
    config.set_reset_key(bytes(32))
    with pytest.raises(ValueError):
        config.set_reset_key(bytes(3))


def test_unknown_connections():
    client, server, connection = pair()
    run(client, server)
    from umilib.protocol.quic import QUICConnection

    with pytest.raises(QUICError) as error:
        QUICConnection(client, 99).ping()
    assert error.value.name == "UnknownConnection"
