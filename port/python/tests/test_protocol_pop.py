"""Tests of umilib.protocol.pop.v3 against the example session of RFC 1939 §10, the examples of
RFC 2449 and RFC 5034, and against the client of the Python standard library (poplib)."""

import base64
import poplib
import socket
import threading
import time

import pytest

from umilib.protocol.pop.v3 import (
    POP3Capabilities,
    POP3Client,
    POP3ClientEventKind,
    POP3Command,
    POP3Config,
    POP3Error,
    POP3MultiLineReader,
    POP3MultiLineWriter,
    POP3Response,
    POP3Server,
    POP3ServerConfig,
    POP3ServerEventKind,
    POP3State,
)


def exchange(client: POP3Client, server: POP3Server) -> None:
    while True:
        to_server, to_client = client.transmit(), server.transmit()
        if not to_server and not to_client:
            return
        server.receive(to_server, 0)
        client.receive(to_client, 0)


def events(endpoint):
    out = []
    while (event := endpoint.poll_event()) is not None:
        out.append(event)
    return out


def test_lines():
    # RFC 2449 §8: a response code.
    response = POP3Response.parse(b"-ERR [SYS/TEMP] try again")
    assert response == POP3Response(False, ["SYS", "TEMP"], b"try again")
    assert response.encode() == b"-ERR [SYS/TEMP] try again"
    assert response.has_code(["sys", "temp"])
    assert POP3Response.negative("in use", ["IN-USE"]).encode() == b"-ERR [IN-USE] in use"
    for bad in [b"+ok fine", b"OK", b"+OKfine"]:
        with pytest.raises(POP3Error):
            POP3Response.parse(bad)
    # RFC 1939 §7.
    greeting = POP3Response.parse(b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>")
    assert greeting.timestamp() == b"<1896.697170952@dbc.mtview.ca.us>"
    assert POP3Response.positive("ready").timestamp() is None
    assert POP3Command.apop_digest(b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf") == "c4c9334bac560ecc979e58001b3e22fb"
    assert str(POP3Command.apop("mrose", b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf")) == "APOP mrose c4c9334bac560ecc979e58001b3e22fb"
    assert POP3Command.apop_matches("c4c9334bac560ecc979e58001b3e22fb", b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf")
    assert not POP3Command.apop_matches("c4c9334bac560ecc979e58001b3e22fc", b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf")
    command = POP3Command.parse("top 1 10")
    assert (str(command), command.keyword, command.is_multi_line()) == ("TOP 1 10", "TOP", True)
    assert not POP3Command.parse("LIST 1").is_multi_line()
    for bad in ["RETR", "RETR 0", "STAT 1"]:
        with pytest.raises(POP3Error):
            POP3Command.parse(bad)


def test_capabilities_and_multi_line_responses():
    # RFC 2449 §6, its example.
    capabilities = POP3Capabilities.parse(
        b"TOP\r\nUSER\r\nSASL CRAM-MD5 KERBEROS_V4\r\nRESP-CODES\r\nLOGIN-DELAY 900\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\n"
        b"IMPLEMENTATION Shlemazle-Plotz-v302\r\n"
    )
    assert capabilities.sasl_mechanisms() == ["CRAM-MD5", "KERBEROS_V4"]
    assert capabilities.get("login-delay").parameters == ("900",)
    assert POP3Capabilities.parse(capabilities.encode()) == capabilities
    with POP3MultiLineWriter.new() as writer:
        written = writer.write(b"a\n.b\r") + writer.finish()
    assert written == b"a\r\n..b\r\n.\r\n"
    assert POP3MultiLineWriter.canonical_length(b"a\n.b\r") == 7
    with POP3MultiLineReader.new() as reader:
        assert reader.read(written + b"+OK next\r\n") == (len(written), b"a\r\n.b\r\n", True)


def test_a_session_of_rfc_1939_section_10():
    settings = POP3ServerConfig.default()
    settings.passwords_require_tls = False
    server = POP3Server.new(None, settings, False)
    # The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
    clear = POP3Config.default()
    assert clear.passwords_require_tls
    clear.passwords_require_tls = False
    client = POP3Client.new(clear, False, 0)
    server.greet(POP3Response.positive("POP3 server ready <1896.697170952@dbc.mtview.ca.us>"), 0)
    exchange(client, server)
    [greeting] = events(client)
    assert greeting.kind == POP3ClientEventKind.GREETING and greeting.response.timestamp() is not None
    assert client.state == POP3State.AUTHORIZATION

    def round(line, response, data=None):
        client.send(line, 0)
        exchange(client, server)
        [told] = events(server)
        assert (told.kind, str(told.command)) == (POP3ServerEventKind.COMMAND, line)
        server.reply(response, 0)
        if data is not None:
            server.send_data(data)
            server.end_data(0)
        exchange(client, server)
        told = events(client)
        assert (told[0].kind, str(told[0].command), told[0].response) == (POP3ClientEventKind.RESPONSE, line, response)
        return told

    command = POP3Command.parse("APOP mrose c4c9334bac560ecc979e58001b3e22fb")
    assert POP3Command.apop_matches(command.line.split(" ")[2], b"<1896.697170952@dbc.mtview.ca.us>", b"tanstaaf")
    round(str(command), POP3Response.positive("mrose's maildrop has 2 messages (320 octets)"))
    assert client.state == POP3State.TRANSACTION
    round("STAT", POP3Response.positive("2 320"))
    told = round("LIST", POP3Response.positive("2 messages (320 octets)"), b"1 120\r\n2 200\r\n")
    assert b"".join(event.data for event in told if event.kind == POP3ClientEventKind.DATA) == b"1 120\r\n2 200\r\n"
    assert told[-1].kind == POP3ClientEventKind.DATA_END
    round("DELE 1", POP3Response.positive("message 1 deleted"))
    told = round("QUIT", POP3Response.positive("dewey POP3 server signing off (maildrop empty)"))
    assert (told[-1].kind, told[-1].error) == (POP3ClientEventKind.CLOSED, None)
    assert client.state == POP3State.UPDATE and not client.is_open()
    with pytest.raises(POP3Error) as raised:
        client.send("NOOP", 0)
    assert raised.value.name == "Closed"


def test_rules_and_timeouts():
    server = POP3Server.new(None, None, False)
    # RFC 5034 §4: no passwords as they are without TLS, by default.
    assert not server.passwords_taken()
    assert POP3ServerConfig.default().to_structure().has_login_delay is False
    client = POP3Client.new(None, False, 0)
    server.greet(POP3Response.positive("ready"), 0)
    exchange(client, server)
    events(client)
    client.send("CAPA", 0)
    exchange(client, server)
    assert events(server) == []
    told = events(client)
    assert POP3Capabilities.parse(b"".join(event.data for event in told if event.kind == POP3ClientEventKind.DATA)) == server.capabilities()
    assert client.has_capability("uidl") and not client.has_capability("STLS")
    with pytest.raises(POP3Error) as raised:
        client.send("STLS", 0)
    assert raised.value.name == "State"
    # RFC 1939 §3: the autologout timer closes the connection without a response.
    deadline = server.poll_timeout()
    assert deadline >= 600 * 10**9
    server.expire(deadline)
    assert events(server)[-1].kind == POP3ServerEventKind.CLOSED and server.transmit() == b""
    config = POP3Config.default()
    assert POP3Config.from_structure(config.to_structure()) == config
    # Shutting down: -ERR (RFC 1939 §3), SYS/TEMP where response codes are announced (RFC 3206 §4).
    server = POP3Server.new(None, None, False)
    server.greet(POP3Response.positive("ready"), 0)
    server.transmit()
    with pytest.raises(POP3Error) as raised:
        server.shutdown("bye\r\n+OK")
    assert raised.value.name == "Syntax" and server.transmit() == b"" and server.is_open()
    server.shutdown("shutting down")
    assert server.transmit() == b"-ERR [SYS/TEMP] shutting down\r\n"
    assert not server.is_open() and events(server)[-1].kind == POP3ServerEventKind.CLOSED


MAILDROP = [b"Subject: one\r\n\r\nfirst\r\n.leading period\r\n", b"Subject: two\r\n\r\nsecond\r\n"]


def serve(listener: socket.socket, told: list) -> None:
    """A server of one connection of the maildrop ``MAILDROP``, its user ``tim`` of ``tanstaaf``."""
    connection, _ = listener.accept()
    with connection:
        settings = POP3ServerConfig.default()
        settings.sasl_mechanisms = ["PLAIN"]
        settings.passwords_require_tls = False
        server = POP3Server.new(None, settings, False)
        server.greet(POP3Response.positive("ready <1@umilib.test>"), time.monotonic_ns())
        deleted: set[int] = set()
        while True:
            while (event := server.poll_event()) is not None:
                now = time.monotonic_ns()
                if event.kind == POP3ServerEventKind.AUTH_RESPONSE:
                    told.append(("AUTH", event.data))
                    server.reply(POP3Response.positive("welcome"), now)
                if event.kind != POP3ServerEventKind.COMMAND:
                    continue
                command = event.command
                told.append(("COMMAND", str(command)))
                words = command.line.split(" ")
                if command.keyword in ("USER", "PASS", "APOP", "NOOP", "RSET"):
                    server.reply(POP3Response.positive(""), now)
                elif command.keyword == "AUTH":
                    server.auth_challenge(b"", now)
                elif command.keyword == "STAT":
                    server.reply(POP3Response.positive(f"{len(MAILDROP)} {sum(map(len, MAILDROP))}"), now)
                elif command.keyword == "LIST":
                    server.reply(POP3Response.positive(""), now)
                    for number, message in enumerate(MAILDROP, 1):
                        server.send_data(f"{number} {POP3MultiLineWriter.canonical_length(message)}\r\n".encode())
                    server.end_data(now)
                elif command.keyword == "RETR":
                    server.reply(POP3Response.positive(""), now)
                    server.send_data(MAILDROP[int(words[1]) - 1])
                    server.end_data(now)
                elif command.keyword == "DELE":
                    deleted.add(int(words[1]))
                    server.reply(POP3Response.positive("deleted"), now)
                elif command.keyword == "QUIT":
                    told.append(("DELETED", sorted(deleted)))
                    server.reply(POP3Response.positive("bye"), now)
                else:
                    server.reply(POP3Response.negative("unknown"), now)
            connection.sendall(server.transmit())
            if not server.is_open():
                break
            data = connection.recv(65536)
            if not data:
                break
            server.receive(data, time.monotonic_ns())


def run(client_session) -> list:
    listener = socket.create_server(("127.0.0.1", 0))
    told: list = []
    thread = threading.Thread(target=serve, args=(listener, told), daemon=True)
    thread.start()
    try:
        client = poplib.POP3("127.0.0.1", listener.getsockname()[1], timeout=10)
        client_session(client)
    finally:
        thread.join(10)
        listener.close()
    return told


def test_the_server_with_poplib():
    def session(client: poplib.POP3) -> None:
        assert client.getwelcome().startswith(b"+OK ready")
        capabilities = client.capa()
        assert "PIPELINING" in capabilities and capabilities["SASL"] == ["PLAIN"]
        client.user("tim")
        client.pass_("tanstaaf")
        assert client.stat() == (2, sum(map(len, MAILDROP)))
        _, listing, _ = client.list()
        assert listing == [f"{number} {len(message)}".encode() for number, message in enumerate(MAILDROP, 1)]
        _, lines, _ = client.retr(1)
        assert b"\r\n".join(lines) + b"\r\n" == MAILDROP[0]
        client.dele(2)
        client.quit()

    told = run(session)
    commands = [value for kind, value in told if kind == "COMMAND"]
    # CAPA is answered by the server itself (RFC 2449 §5).
    assert commands[:3] == ["USER tim", "PASS tanstaaf", "STAT"]
    assert ("DELETED", [2]) in told


def test_the_server_with_poplib_apop_and_auth():
    def session(client: poplib.POP3) -> None:
        client.apop("tim", "tanstaaf")
        client.quit()

    told = run(session)
    command = next(value for kind, value in told if kind == "COMMAND" and value.startswith("APOP"))
    assert POP3Command.apop_matches(command.split(" ")[2], b"<1@umilib.test>", b"tanstaaf")

    def sasl(client: poplib.POP3) -> None:
        # RFC 5034 §4 by hand: poplib has no AUTH; the response is base64 of authzid, authcid and password.
        client._putcmd("AUTH PLAIN")
        assert client._getline()[0].startswith(b"+ ")
        client._putcmd(base64.b64encode(b"\0tim\0tanstaaf").decode())
        assert client._getresp().startswith(b"+OK")
        client.quit()

    told = run(sasl)
    assert ("AUTH", b"\0tim\0tanstaaf") in told
