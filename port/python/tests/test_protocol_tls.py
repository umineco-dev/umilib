"""Tests of umilib.protocol.tls: handshakes of TLS 1.3 and TLS 1.2 between a client and a server driven
from Python, with the certificates OpenSSL made, and what they negotiate: application protocols (RFC
7301), exporters (RFC 9846 §7.5), resumption and early data (RFC 9846 §2.2, §2.3), Encrypted ClientHello
(RFC 9849), and the alerts of failures (RFC 9846 §6.2)."""

import pytest
from vectors import ROOT

from umilib.auth.cert.key import PrivateKey
from umilib.auth.cert.path import TrustAnchor
from umilib.auth.cert.x509 import Certificate
from umilib.protocol.tls import (
    TLSAlertDescription,
    TLSCertifiedKey,
    TLSCipherSuite,
    TLSClientAuthentication,
    TLSClientConfig,
    TLSClientOptions,
    TLSConfig,
    TLSConnection,
    TLSECHKey,
    TLSECHStatus,
    TLSEarlyData,
    TLSError,
    TLSErrorKind,
    TLSEvent,
    TLSLimits,
    TLSNamedGroup,
    TLSPathVerifier,
    TLSRule,
    TLSServerConfig,
    TLSServerOptions,
    TLSSignatureScheme,
    TLSVersion,
)

CERTIFICATES = ROOT / "protocol" / "tls" / "certificates"
#: 2027-01-01, inside the validity of the certificates.
TIME = 1_798_761_600


def certificate(name: str) -> bytes:
    return (CERTIFICATES / f"{name}.der").read_bytes()


def certified(name: str) -> TLSCertifiedKey:
    return TLSCertifiedKey.new([certificate(name)], PrivateKey.from_pem((CERTIFICATES / f"{name}.key").read_text(encoding="utf-8")))


def verifier() -> TLSPathVerifier:
    return TLSPathVerifier.servers([TrustAnchor.from_certificate(Certificate.from_der(certificate("root")))])


def configs(versions: list[int] | None = None) -> tuple[TLSConfig, TLSConfig]:
    client, server = TLSConfig(), TLSConfig()
    if versions is not None:
        client.set_versions(versions)
        server.set_versions(versions)
    return client, server


def run(client: TLSConnection, server: TLSConnection) -> None:
    """Moves bytes both ways until neither side has more."""
    while True:
        moved = False
        if data := client.transmit():
            server.receive(data)
            moved = True
        if data := server.transmit():
            client.receive(data)
            moved = True
        if not moved:
            return


def events(connection: TLSConnection) -> list[TLSEvent]:
    found = []
    while (event := connection.poll_event()) is not None:
        found.append(event)
    return found


def pair(client: TLSClientConfig, server: TLSServerConfig, name: str = "server.example") -> tuple[TLSConnection, TLSConnection]:
    return TLSConnection.client(client, name, TIME), TLSConnection.server(server, TIME)


def echo(client: TLSConnection, server: TLSConnection, data: bytes) -> None:
    client.send(data)
    run(client, server)
    assert server.read(len(data) + 1) == data
    server.send(data)
    run(client, server)
    assert client.read(len(data) + 1) == data


@pytest.mark.parametrize("version", [TLSVersion.TLS1_3, TLSVersion.TLS1_2])
def test_a_handshake_and_data(version: int) -> None:
    client_config, server_config = configs([version])
    client_config.set_protocols([b"http/1.1", b"h2"])
    server_config.set_protocols([b"h2"])
    client, server = pair(TLSClientConfig.new(client_config, verifier()), TLSServerConfig.new(server_config, [certified("server-p256")]))
    run(client, server)
    assert events(client) == [TLSEvent.CONNECTED] and events(server) == [TLSEvent.CONNECTED]
    for connection in (client, server):
        session = connection.session
        assert session.version == version and not session.handshaking
        assert session.peer_signature_scheme in (None, TLSSignatureScheme.ECDSA_SECP256R1_SHA256)
        assert connection.protocol == b"h2"
    assert client.session.cipher_suite in (TLSCipherSuite.TLS_AES_128_GCM_SHA256, TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    assert client.peer_certificates == [certificate("server-p256")]
    assert server.server_name == "server.example"
    echo(client, server, b"hello from python")
    echo(client, server, bytes(range(256)) * 300)
    assert client.export(b"EXPORTER-test", b"context", 32) == server.export(b"EXPORTER-test", b"context", 32)
    client.close()
    run(client, server)
    assert TLSEvent.PEER_CLOSED in events(server)


def test_failures_tell_their_alert() -> None:
    client_config, server_config = configs()
    client, server = pair(TLSClientConfig.new(client_config, verifier()), TLSServerConfig.new(server_config, [certified("stranger")]))
    with pytest.raises(TLSError) as raised:
        run(client, server)
    assert raised.value.name == "Protocol"
    failure = client.error()
    assert failure is not None and failure.kind == TLSErrorKind.PROTOCOL and failure.alert == TLSAlertDescription.UNKNOWN_CA
    with pytest.raises(TLSError) as raised:
        server.receive(client.transmit())
    assert raised.value.name == "Alert"
    assert server.error() == client.error().__class__(TLSErrorKind.ALERT, TLSAlertDescription.UNKNOWN_CA)
    # Before the handshake completes no data can be sent.
    client, _ = pair(TLSClientConfig.new(configs()[0], verifier()), TLSServerConfig.new(configs()[1], [certified("server-p256")]))
    with pytest.raises(TLSError) as raised:
        client.send(b"too early")
    assert raised.value.name == "State"


def test_configuration() -> None:
    config = TLSConfig()
    assert config.limits == TLSLimits()
    assert config.limits.maximum_ignored_records == 32
    config.limits = TLSLimits(record_size_limit=512, maximum_key_updates=4)
    assert config.limits.record_size_limit == 512 and config.limits.maximum_key_updates == 4
    with pytest.raises(OverflowError):
        config.set_groups([0x1001D])
    config.set_groups([TLSNamedGroup.X25519])
    config.set_signature_schemes([TLSSignatureScheme.ED25519, TLSSignatureScheme.ECDSA_SECP256R1_SHA256])
    client = TLSClientConfig.new(config, verifier())
    client.set_options(TLSClientOptions(middlebox_compatibility=False))
    server = TLSServerConfig.new(config, [certified("server-p256")])
    a, b = pair(client, server)
    run(a, b)
    assert a.session.group == TLSNamedGroup.X25519
    # No version this build supports: Config.
    config.set_versions([0x0302])
    with pytest.raises(TLSError) as raised:
        TLSConnection.client(TLSClientConfig.new(config, verifier()), "server.example", TIME)
    assert raised.value.name == "Config"


def test_client_authentication() -> None:
    client_config, server_config = configs()
    client = TLSClientConfig.new(client_config, verifier())
    client.set_certificate(certified("client"))
    server = TLSServerConfig.new(server_config, [certified("server-p256")])
    server.set_options(TLSServerOptions(client_authentication=TLSClientAuthentication.REQUIRED))
    server.set_client_verifier(TLSPathVerifier.clients([TrustAnchor.from_certificate(Certificate.from_der(certificate("root")))]))
    a, b = pair(client, server)
    run(a, b)
    assert b.peer_certificates == [certificate("client")]


def test_resumption_and_early_data() -> None:
    client_config, server_config = configs()
    client = TLSClientConfig.new(client_config, verifier())
    client.set_session_cache(8)
    client.set_options(TLSClientOptions(early_data=True))
    server = TLSServerConfig.new(server_config, [certified("server-p256")])
    server.set_ticket_key(bytes(16), bytes(range(32)))
    server.set_replay_cache(10, 64)
    server.set_options(TLSServerOptions(maximum_early_data=1024))
    a, b = pair(client, server)
    run(a, b)
    assert not a.session.resumed
    a, b = pair(client, server)
    assert a.session.early_data == TLSEarlyData.OFFERED
    a.send(b"early")
    run(a, b)
    assert a.session.resumed and b.session.resumed
    assert a.session.early_data == TLSEarlyData.ACCEPTED
    assert b.read(16) == b"early"


def test_encrypted_client_hello() -> None:
    key = TLSECHKey.generate(7, "public.wild.example", maximum_name_length=32)
    client_config, server_config = configs()
    client = TLSClientConfig.new(client_config, verifier())
    client.set_ech_configs(key.config_list)
    server = TLSServerConfig.new(server_config, [certified("server-p256")])
    server.add_ech_key(key)
    a, b = pair(client, server)
    hello = a.transmit()
    assert b"server.example" not in hello and b"public.wild.example" in hello
    b.receive(hello)
    run(a, b)
    assert a.session.ech == TLSECHStatus.ACCEPTED and b.session.ech == TLSECHStatus.ACCEPTED
    assert b.server_name == "server.example"
    # A key rebuilt from its parts is the same key.
    again = TLSECHKey.new(key.config_list, bytes(key.private_key))
    assert again.config_list == key.config_list
    # A server of another key rejects ECH and gives its configuration to retry with.
    other = TLSECHKey.generate(7, "public.wild.example")
    server = TLSServerConfig.new(server_config, [certified("server-p256")])
    server.add_ech_key(other)
    a, b = pair(client, server)
    with pytest.raises(TLSError):
        run(a, b)
    assert a.error().alert == TLSAlertDescription.ECH_REQUIRED
    assert a.ech_retry_configs == other.config_list


def test_rules() -> None:
    client_config, server_config = configs()
    client_config.set_protocols([b"h2"])
    server_config.set_protocols([b"h2"])
    a, b = pair(TLSClientConfig.new(client_config, verifier()), TLSServerConfig.new(server_config, [certified("server-p256")]))
    hello = a.transmit()
    body = hello[9:]
    assert TLSRule.new("server.example").matches_client_hello(body)
    assert TLSRule.new("*.example", b"h2").matches_client_hello(body)
    assert not TLSRule.new("*.example", b"h3").matches_client_hello(body)
    assert not TLSRule.new("").matches_client_hello(body)
    b.receive(hello)
    run(a, b)
    assert TLSRule.new("*", b"h2").matches_session(b)
    assert not TLSRule.new("other.example").matches_session(b)
