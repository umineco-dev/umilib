"""Tests of umilib.protocol.smtp against the examples and rules of RFC 5321, RFC 2034, RFC 3461 and
RFC 4954, and against the client of the Python standard library (smtplib)."""

import base64
import datetime
import smtplib
import socket
import threading
import time

import pytest

from umilib.crypto.random import HMACDRBG
from umilib.hash.sha.v2 import SHA256

from umilib.protocol.smtp import (
    SMTPClient,
    SMTPClientEventKind,
    SMTPCommand,
    SMTPConfig,
    SMTPData,
    SMTPDataReader,
    SMTPEnhancedStatus,
    SMTPError,
    SMTPExtensions,
    SMTPMailExchanger,
    SMTPMailbox,
    SMTPReply,
    SMTPServer,
    SMTPServerConfig,
    SMTPServerEventKind,
    SMTPXText,
)


def exchange(client: SMTPClient, server: SMTPServer, now: int = 0) -> None:
    while True:
        to_server, to_client = client.transmit(), server.transmit()
        if not to_server and not to_client:
            return
        server.receive(to_server, now)
        client.receive(to_client, now)


def events(endpoint):
    out = []
    while (event := endpoint.poll_event()) is not None:
        out.append(event)
    return out


def test_configurations_are_of_rfc_5321():
    config = SMTPConfig.default()
    # RFC 5321 §4.5.3.1 and §4.5.3.2: the minimums.
    assert config.maximum_command_line >= 512
    assert config.maximum_text_line >= 1000
    assert config.greeting_timeout >= datetime.timedelta(minutes=5)
    assert config.data_termination_timeout >= datetime.timedelta(minutes=10)
    assert SMTPConfig.from_structure(config.to_structure()) == config
    assert SMTPServerConfig.default().maximum_recipients >= 100


def test_replies():
    # RFC 5321 §4.2.1: a multiline reply.
    wire = b"250-foo.com greets bar.com\r\n250-8BITMIME\r\n250-SIZE 1000\r\n250 HELP\r\n"
    reply = SMTPReply.decode(wire)
    assert (reply.code, reply.lines) == (250, [b"foo.com greets bar.com", b"8BITMIME", b"SIZE 1000", b"HELP"])
    assert reply.encode() == wire
    assert reply.is_positive() and not reply.is_negative()
    extensions = SMTPExtensions.from_reply(reply)
    assert extensions.greeting == "foo.com greets bar.com"
    assert extensions.get("size").parameters == ("1000",)
    assert extensions.has("8bitmime") and not extensions.has("PIPELINING")
    for bad in [b"250 OK\n", b"250-OK\r\n", b"25 OK\r\n", b"250-a\r\n251 b\r\n"]:
        with pytest.raises(SMTPError) as raised:
            SMTPReply.decode(bad)
        assert raised.value.name == "Syntax"
    with pytest.raises(SMTPError):
        SMTPReply(250, [b"a\r\nb"]).encode()
    # RFC 2034 §4: the enhanced status code of the reply's class.
    assert SMTPReply.new(550, "5.1.1 Mailbox does not exist").status() == SMTPEnhancedStatus(5, 1, 1)
    assert SMTPReply.new(250, "5.1.1 not of its class").status() is None
    assert str(SMTPEnhancedStatus(2, 0, 0)) == "2.0.0"


def test_commands_mailboxes_xtext_and_data():
    # RFC 5321 §4.1.1: verbs in any case.
    command = SMTPCommand.parse("mail from:<Smith@bar.com> SIZE=500")
    assert (str(command), command.verb) == ("MAIL FROM:<Smith@bar.com> SIZE=500", "MAIL")
    for bad in ["MAIL FROM: Smith@bar.com", "RCPT TO:<>", "HELO", "DATA x"]:
        with pytest.raises(SMTPError):
            SMTPCommand.parse(bad)
    # RFC 6531 §3.3: UTF-8 only of SMTPUTF8.
    with pytest.raises(SMTPError):
        SMTPCommand.parse("RCPT TO:<用户@例子.广告>")
    assert str(SMTPCommand.parse("RCPT TO:<用户@例子.广告>", utf8=True)) == "RCPT TO:<用户@例子.广告>"
    # §4.1.2: a quoted local part.
    mailbox = SMTPMailbox.parse('"John Doe"@example.com')
    assert mailbox == SMTPMailbox("John Doe", "example.com")
    assert str(mailbox) == '"John Doe"@example.com'
    assert str(SMTPMailbox("Smith", "bar.com")) == "Smith@bar.com"
    # RFC 3461 §4.
    assert SMTPXText.encode(b"a+b=c d") == "a+2Bb+3Dc+20d"
    assert SMTPXText.decode("a+2Bb+3Dc+20d") == b"a+b=c d"
    with pytest.raises(SMTPError):
        SMTPXText.decode("a+2")
    # §4.5.2: transparency.
    data = SMTPData.encode(b"Subject: x\r\n\r\n.hidden\r\nlast")
    assert data == b"Subject: x\r\n\r\n..hidden\r\nlast\r\n.\r\n"
    with pytest.raises(SMTPError) as raised:
        SMTPData.encode(b"a\nb")
    assert raised.value.name == "Content"
    with pytest.raises(SMTPError) as raised:
        SMTPData.encode(b"x" * 999)
    assert raised.value.name == "TooLong"
    with SMTPDataReader.new(1 << 20, 1000) as reader:
        read, out = reader.read(data + b"QUIT\r\n")
        assert (read, out, reader.is_end(), reader.error()) == (len(data), b"Subject: x\r\n\r\n.hidden\r\nlast\r\n", True, None)
    with SMTPDataReader.new(4, 1000) as reader:
        reader.read(b"hello\r\n.\r\n")
        assert reader.is_end() and reader.error().name == "TooLarge"


def test_a_session_of_rfc_5321_appendix_d_1():
    settings = SMTPServerConfig.default()
    settings.domain = "foo.com"
    settings.auth_mechanisms = ["PLAIN"]
    settings.passwords_require_tls = False
    server = SMTPServer.new(None, settings, False)
    # The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
    clear = SMTPConfig.default()
    assert clear.passwords_require_tls
    clear.passwords_require_tls = False
    client = SMTPClient.new(clear, False, 0)
    assert client.poll_timeout() >= 5 * 60 * 10**9
    server.greet(server.greeting(), 0)
    exchange(client, server)
    [greeting] = events(client)
    assert greeting.kind == SMTPClientEventKind.GREETING and greeting.reply.code == 220

    client.send("EHLO bar.com", 0)
    exchange(client, server)
    [told] = events(server)
    assert (told.kind, str(told.command)) == (SMTPServerEventKind.COMMAND, "EHLO bar.com")
    server.reply(SMTPReply.new(250, "foo.com greets bar.com"), 0)
    exchange(client, server)
    [replied] = events(client)
    extensions = SMTPExtensions.from_reply(replied.reply)
    assert extensions.greeting == "foo.com greets bar.com"
    assert extensions.entries == server.extensions().entries
    assert extensions.get("AUTH").parameters == ("PLAIN",)
    assert client.has_extension("pipelining") and not client.has_extension("STARTTLS")
    with pytest.raises(SMTPError) as raised:
        client.send("STARTTLS", 0)
    assert raised.value.name == "State"

    # RFC 4954 §4: AUTH without an initial response, its empty challenge, the response.
    client.send("AUTH PLAIN", 0)
    exchange(client, server)
    assert str(events(server)[0].command) == "AUTH PLAIN"
    server.auth_challenge(b"", 0)
    exchange(client, server)
    [challenge] = events(client)
    assert (challenge.kind, challenge.data) == (SMTPClientEventKind.AUTH_CHALLENGE, b"")
    client.auth_respond(b"\0tim\0tanstaaftanstaaf", 0)
    exchange(client, server)
    [response] = events(server)
    assert (response.kind, response.data) == (SMTPServerEventKind.AUTH_RESPONSE, b"\0tim\0tanstaaftanstaaf")
    server.reply(SMTPReply.new(235, "2.7.0 Authentication successful"), 0)
    exchange(client, server)
    assert events(client)[0].reply.code == 235

    for line, answer in [
        ("MAIL FROM:<Smith@bar.com>", SMTPReply.new(250, "OK")),
        ("RCPT TO:<Jones@foo.com>", SMTPReply.new(250, "OK")),
        ("RCPT TO:<Green@foo.com>", SMTPReply.new(550, "No such user here")),
        ("RCPT TO:<Brown@foo.com>", SMTPReply.new(250, "OK")),
        ("DATA", SMTPReply.new(354, "Start mail input; end with <CRLF>.<CRLF>")),
    ]:
        client.send(line, 0)
        exchange(client, server)
        assert str(events(server)[0].command) == line
        server.reply(answer, 0)
        exchange(client, server)
        [replied] = events(client)
        assert (str(replied.command), replied.reply.code) == (line, answer.code)
        # RFC 2034 §3: a status code of the reply's class where it has none.
        if not answer.is_intermediate():
            assert replied.reply.status() == SMTPEnhancedStatus(answer.severity(), 0, 0)
    client.send_data(b"Blah blah blah...\r\n...etc. etc. etc.", 0)
    exchange(client, server)
    told = events(server)
    assert b"".join(event.data for event in told if event.kind == SMTPServerEventKind.DATA) == b"Blah blah blah...\r\n...etc. etc. etc.\r\n"
    assert (told[-1].kind, told[-1].last) == (SMTPServerEventKind.DATA_END, True)
    server.reply(SMTPReply.new(250, "OK"), 0)
    exchange(client, server)
    [replied] = events(client)
    assert (replied.kind, replied.reply.code) == (SMTPClientEventKind.DATA_REPLY, 250)

    client.send("QUIT", 0)
    exchange(client, server)
    assert events(server)[-1].kind == SMTPServerEventKind.CLOSED
    told = events(client)
    assert told[0].reply.code == 221 and (told[-1].kind, told[-1].error) == (SMTPClientEventKind.CLOSED, None)
    assert not client.is_open() and not server.is_open()
    with pytest.raises(SMTPError) as raised:
        client.send("NOOP", 0)
    assert raised.value.name == "Closed"


def test_timeouts_and_shutdown():
    config = SMTPConfig.default()
    config.greeting_timeout = datetime.timedelta(seconds=10)
    client = SMTPClient.new(config, False, 0)
    client.expire(9 * 10**9)
    assert client.poll_event() is None
    client.expire(10 * 10**9)
    [closed] = events(client)
    assert closed.kind == SMTPClientEventKind.CLOSED and closed.error.name == "Timeout"
    server = SMTPServer.new(config, None, False)
    # RFC 5321 §4.2: a reply is lines of text; a line break in the text would add a reply.
    with pytest.raises(SMTPError) as raised:
        server.shutdown("bye\r\n250 OK")
    assert raised.value.name == "Syntax" and server.transmit() == b"" and server.is_open()
    server.shutdown("Service not available")
    assert server.transmit().startswith(b"421 ")
    assert not server.is_open()


def serve(listener: socket.socket, received: list) -> None:
    """Runs a server of one connection that takes every recipient and message."""
    connection, _ = listener.accept()
    with connection:
        settings = SMTPServerConfig.default()
        settings.domain = "umilib.test"
        settings.auth_mechanisms = ["PLAIN"]
        settings.passwords_require_tls = False
        server = SMTPServer.new(None, settings, False)
        server.greet(server.greeting(), time.monotonic_ns())
        message = b""
        while True:
            connection.sendall(server.transmit())
            while (event := server.poll_event()) is not None:
                now = time.monotonic_ns()
                if event.kind == SMTPServerEventKind.COMMAND:
                    if event.command.verb == "AUTH":
                        received.append(("AUTH", str(event.command)))
                        server.reply(SMTPReply.new(235, "2.7.0 Authentication successful"), now)
                    elif event.command.verb == "DATA":
                        server.reply(SMTPReply.new(354, "Go ahead"), now)
                    else:
                        received.append(("COMMAND", str(event.command)))
                        server.reply(SMTPReply.new(250, "OK"), now)
                elif event.kind == SMTPServerEventKind.DATA:
                    message += event.data
                elif event.kind == SMTPServerEventKind.DATA_END:
                    received.append(("MESSAGE", message))
                    server.reply(SMTPReply.new(250, "Queued"), now)
            connection.sendall(server.transmit())
            if not server.is_open():
                break
            data = connection.recv(65536)
            if not data:
                break
            server.receive(data, time.monotonic_ns())


def test_the_server_with_smtplib():
    listener = socket.create_server(("127.0.0.1", 0))
    received: list = []
    thread = threading.Thread(target=serve, args=(listener, received), daemon=True)
    thread.start()
    try:
        with smtplib.SMTP("127.0.0.1", listener.getsockname()[1], local_hostname="client.test", timeout=10) as client:
            code, _ = client.ehlo()
            assert code == 250
            assert client.has_extn("pipelining") and client.has_extn("8bitmime") and client.has_extn("size")
            assert client.esmtp_features["auth"].strip() == "PLAIN"
            client.login("tim", "tanstaaftanstaaf")
            refused = client.sendmail("Smith@bar.com", ["Jones@foo.com"], b"Subject: test\r\n\r\n.leading period\r\nbody\r\n")
            assert refused == {}
    finally:
        thread.join(10)
        listener.close()
    commands = [value for kind, value in received if kind == "COMMAND"]
    assert commands[0] == "EHLO client.test"
    assert commands[1].startswith("MAIL FROM:<Smith@bar.com>")
    assert commands[2] == "RCPT TO:<Jones@foo.com>"
    auth = next(value for kind, value in received if kind == "AUTH")
    assert base64.b64decode(auth.split(" ")[2]) == b"\0tim\0tanstaaftanstaaf"
    assert ("MESSAGE", b"Subject: test\r\n\r\n.leading period\r\nbody\r\n") in received


def test_mail_exchangers():
    random = HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte", b"smtp")
    records = (
        "example.com. 300 IN MX 20 b.example.com.\n"
        "example.com. 300 IN MX 10 a1.example.com.\n"
        "example.com. 300 IN MX 10 a2.example.com.\n"
    )
    orders = set()
    for _ in range(32):
        hosts = SMTPMailExchanger.order("example.com.", records, [], random)
        assert sorted(hosts[:2], key=lambda host: host.host) == [SMTPMailExchanger(10, "a1.example.com."), SMTPMailExchanger(10, "a2.example.com.")]
        assert hosts[2] == SMTPMailExchanger(20, "b.example.com.")
        orders.add(tuple(host.host for host in hosts))
    assert len(orders) == 2
    assert SMTPMailExchanger.order("none.com.", records, [], random) == [SMTPMailExchanger(0, "none.com.")]
    assert len(SMTPMailExchanger.order("example.com.", records, ["b.example.com."], random)) == 2
    with pytest.raises(SMTPError) as raised:
        SMTPMailExchanger.order("null.com.", "null.com. 300 IN MX 0 .\n", [], random)
    assert raised.value.name == "NoMail"


def test_auth_failures_are_told():
    settings = SMTPServerConfig.default()
    settings.auth_mechanisms = ["SCRAM-SHA-256"]
    server = SMTPServer.new(None, settings, False)
    server.greet(server.greeting(), 0)
    assert server.wants_receive()
    server.receive(b"EHLO c\r\n", 0)
    server.poll_event()
    server.reply(SMTPReply.new(250, "mx"), 0)
    server.receive(b"AUTH SCRAM-SHA-256\r\n", 0)
    server.poll_event()
    server.auth_challenge(b"", 0)
    server.receive(b"!!!\r\n", 0)
    assert server.poll_event().kind == SMTPServerEventKind.AUTH_FAILED
