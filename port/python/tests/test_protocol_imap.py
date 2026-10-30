"""Tests of umilib.protocol.imap.v4 against the examples and rules of RFC 9051, RFC 3501 §5.1.3 and
RFC 7888, and against the client of the Python standard library (imaplib)."""

import imaplib
import socket
import threading
import time

import pytest

from umilib.protocol.imap.v4 import (
    IMAPBody,
    IMAPClient,
    IMAPClientEventKind,
    IMAPCommand,
    IMAPCondition,
    IMAPConfig,
    IMAPDateTime,
    IMAPEnvelope,
    IMAPError,
    IMAPMailbox,
    IMAPResponse,
    IMAPSection,
    IMAPSequenceSet,
    IMAPServer,
    IMAPServerConfig,
    IMAPServerEventKind,
    IMAPState,
)


def exchange(client: IMAPClient, server: IMAPServer) -> None:
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
    command = IMAPCommand.parse("a003 uid fetch 1:* (FLAGS UID)")
    assert (command.line, command.tag, command.name, command.body) == (b"a003 UID FETCH 1:* (FLAGS UID)", "a003", "UID FETCH", b"UID FETCH 1:* (FLAGS UID)")
    # RFC 9051 §4.3 and RFC 7888: literals are of the logical line.
    assert IMAPCommand.parse(b"A1 LOGIN {5}\r\nSMITH {6+}\r\nSESAME").line == b"A1 LOGIN SMITH SESAME"
    with pytest.raises(IMAPError) as raised:
        IMAPCommand.parse("a001 LOGIN SMITH")
    assert raised.value.name == "Syntax"
    for line in [b"* 18 EXISTS", b"* LIST (\\Noselect) \"/\" foo", b"A142 OK [READ-WRITE] SELECT completed"]:
        assert IMAPResponse.parse(line).line == line
    assert IMAPResponse.parse(b"A142 OK [READ-WRITE] SELECT completed").status() == ("A142", IMAPCondition.OK, "[READ-WRITE]", "SELECT completed")
    assert IMAPResponse.parse(b"* 18 EXISTS").status() is None
    assert IMAPResponse.tagged("a1", IMAPCondition.NO, "[TRYCREATE]", "no").line == b"a1 NO [TRYCREATE] no"
    assert IMAPResponse.untagged(IMAPCondition.BYE, None, "bye").line == b"* BYE bye"
    with pytest.raises(IMAPError):
        IMAPResponse.tagged("a1", IMAPCondition.BYE, None, "tagged BYE")


def test_parts():
    # RFC 3501 §5.1.3.
    assert IMAPMailbox.encode_modified_utf7("~peter/mail/台北/日本語") == "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
    assert IMAPMailbox.decode_modified_utf7("~peter/mail/&U,BTFw-/&ZeVnLIqe-") == "~peter/mail/台北/日本語"
    assert IMAPMailbox.decode_modified_utf7("&-") == "&"
    with pytest.raises(IMAPError):
        IMAPMailbox.decode_modified_utf7("&Jjo!")
    sequence = IMAPSequenceSet.parse("4:2,*,9:7")
    assert sequence.resolve(10) == [range(2, 5), range(7, 11)]
    assert sequence.contains(3, 10) and not sequence.contains(5, 10)
    with pytest.raises(IMAPError):
        IMAPSequenceSet.parse("0")
    date = IMAPDateTime.parse('"17-Jul-1996 02:44:25 -0700"')
    assert date == IMAPDateTime(837_596_665, -420) and str(date) == '"17-Jul-1996 02:44:25 -0700"'
    message = b"From: Pete <pete@silly.example>\r\nSubject: hi\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nabc\r\n"
    assert IMAPEnvelope.of_message(message).startswith(b'(NIL "hi" (("Pete" NIL "pete" "silly.example"))')
    assert IMAPBody.of_message(message, extensible=False) == b'("TEXT" "PLAIN" ("charset" "us-ascii") NIL NIL "7BIT" 5 1)'
    assert IMAPSection("[HEADER.FIELDS (SUBJECT)]").extract(message) == b"Subject: hi\r\n\r\n"
    assert IMAPSection("[TEXT]").extract(message) == b"abc\r\n"
    assert IMAPSection("[2]").extract(message) is None


def test_a_session():
    settings = IMAPServerConfig.default()
    settings.auth_mechanisms = ["PLAIN"]
    settings.passwords_require_tls = False
    server = IMAPServer.new(None, settings, False)
    assert "AUTH=PLAIN" in server.capabilities() and "IMAP4rev2" in server.capabilities()
    # The passwords of the examples go in the clear; refusing to is the default (RFC 2595 §2.3).
    clear = IMAPConfig.default()
    assert clear.passwords_require_tls
    clear.passwords_require_tls = False
    client = IMAPClient.new(clear, False, "a", 0)
    server.greet(IMAPCondition.OK, "IMAP4rev2 Service Ready", 0)
    exchange(client, server)
    [greeting] = events(client)
    assert greeting.kind == IMAPClientEventKind.GREETING and greeting.response.status()[1] == IMAPCondition.OK
    assert client.has_capability("imap4rev2")

    assert client.send("LOGIN {5}\r\nSMITH {6}\r\nSESAME", 0) == "a1"
    exchange(client, server)
    [told] = events(server)
    assert (told.kind, told.command.name, told.command.line) == (IMAPServerEventKind.COMMAND, "LOGIN", b"a1 LOGIN SMITH SESAME")
    server.complete(IMAPCondition.OK, None, "LOGIN completed", 0)
    exchange(client, server)
    [completed] = events(client)
    assert (completed.kind, completed.tag, completed.response.status()[1]) == (IMAPClientEventKind.COMPLETED, "a1", IMAPCondition.OK)
    assert client.state == IMAPState.AUTHENTICATED

    client.send("SELECT INBOX", 0)
    exchange(client, server)
    assert events(server)[0].command.name == "SELECT"
    for line in [b"* 18 EXISTS", b"* FLAGS (\\Seen \\Deleted)", b"* OK [UIDVALIDITY 3857529045] UIDs valid"]:
        server.respond(line)
    server.complete(IMAPCondition.OK, "[READ-WRITE]", "SELECT completed", 0)
    exchange(client, server)
    told = events(client)
    assert [event.kind for event in told] == [IMAPClientEventKind.UNTAGGED] * 3 + [IMAPClientEventKind.COMPLETED]
    assert server.state == IMAPState.SELECTED

    # IDLE (RFC 9051 §6.3.13): accepted, untagged responses, DONE.
    client.send("IDLE", 0)
    exchange(client, server)
    tag = events(server)[0].tag
    server.idle("idling", 0)
    exchange(client, server)
    assert events(client)[0].kind == IMAPClientEventKind.IDLING
    server.respond(b"* 19 EXISTS")
    exchange(client, server)
    assert events(client)[0].response.line == b"* 19 EXISTS"
    client.idle_done(0)
    exchange(client, server)
    assert [(event.kind, event.tag) for event in events(server)] == [(IMAPServerEventKind.IDLE_DONE, tag)]
    server.complete(IMAPCondition.OK, None, "IDLE terminated", 0)
    exchange(client, server)
    assert events(client)[0].kind == IMAPClientEventKind.COMPLETED

    client.send("LOGOUT", 0)
    exchange(client, server)
    assert events(server)[-1].kind == IMAPServerEventKind.CLOSED
    told = events(client)
    assert told[0].response.status()[1] == IMAPCondition.BYE
    assert (told[-1].kind, told[-1].error) == (IMAPClientEventKind.CLOSED, None)
    assert not client.is_open()


def test_rules():
    server = IMAPServer.new(None, IMAPServerConfig.default(), False)
    # RFC 9051 §6.2.3: no password without TLS by default.
    assert not server.passwords_taken() and "LOGINDISABLED" in server.capabilities()
    deadline = server.poll_timeout()
    server.greet(IMAPCondition.OK, "ready", 0)
    server.transmit()
    deadline = server.poll_timeout()
    assert deadline >= 60 * 10**9
    server.expire(deadline)
    assert server.transmit().startswith(b"* BYE")
    config = IMAPConfig.default()
    assert IMAPConfig.from_structure(config.to_structure()) == config


MAILBOX = [
    b"From: Pete <pete@silly.example>\r\nSubject: one\r\n\r\nfirst\r\n",
    b"From: Mary <mary@example.net>\r\nSubject: two\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsecond\r\n",
]


def serve(listener: socket.socket, told: list) -> None:
    """A server of one connection of the mailbox INBOX of ``MAILBOX``, its user ``tim``."""
    connection, _ = listener.accept()
    with connection:
        settings = IMAPServerConfig.default()
        settings.passwords_require_tls = False
        server = IMAPServer.new(None, settings, False)
        server.greet(IMAPCondition.OK, "umilib ready", time.monotonic_ns())
        while True:
            while (event := server.poll_event()) is not None:
                now = time.monotonic_ns()
                if event.kind != IMAPServerEventKind.COMMAND:
                    continue
                command = event.command
                told.append(command.line)
                if command.name == "LOGIN":
                    server.complete(IMAPCondition.OK, None, "LOGIN completed", now)
                elif command.name in ("SELECT", "EXAMINE"):
                    server.respond(f"* {len(MAILBOX)} EXISTS")
                    server.respond(b"* FLAGS (\\Seen \\Deleted)")
                    server.respond(b"* OK [UIDVALIDITY 1] UIDs valid")
                    server.complete(IMAPCondition.OK, "[READ-WRITE]", "SELECT completed", now)
                elif command.name == "FETCH":
                    words = command.line.split(b" ", 3)
                    for number in IMAPSequenceSet.parse(words[2].decode()).resolve(len(MAILBOX)):
                        for index in number:
                            message = MAILBOX[index - 1]
                            envelope = IMAPEnvelope.of_message(message)
                            body = IMAPBody.of_message(message)
                            literal = b"{%d}\r\n" % len(message) + message
                            server.respond(b"* %d FETCH (ENVELOPE %s BODYSTRUCTURE %s BODY[] %s)" % (index, envelope, body, literal))
                    server.complete(IMAPCondition.OK, None, "FETCH completed", now)
                elif command.name == "SEARCH":
                    server.respond(b"* SEARCH 1 2")
                    server.complete(IMAPCondition.OK, None, "SEARCH completed", now)
                else:
                    server.complete(IMAPCondition.OK, None, f"{command.name} completed", now)
            connection.sendall(server.transmit())
            if not server.is_open():
                break
            data = connection.recv(65536)
            if not data:
                break
            server.receive(data, time.monotonic_ns())


def test_the_server_with_imaplib():
    listener = socket.create_server(("127.0.0.1", 0))
    told: list = []
    thread = threading.Thread(target=serve, args=(listener, told), daemon=True)
    thread.start()
    try:
        client = imaplib.IMAP4("127.0.0.1", listener.getsockname()[1], timeout=10)
        assert "IMAP4REV1" in client.capabilities
        client.login("tim", "pass word")
        status, data = client.select("INBOX")
        assert (status, data) == ("OK", [b"2"])
        status, data = client.search(None, "ALL")
        assert (status, data) == ("OK", [b"1 2"])
        status, data = client.fetch("1:*", "(ENVELOPE BODYSTRUCTURE BODY[])")
        assert status == "OK"
        messages = [part[1] for part in data if isinstance(part, tuple)]
        assert messages == MAILBOX
        assert b'"one"' in data[0][0] and b'"TEXT" "PLAIN"' in data[0][0]
        client.logout()
    finally:
        thread.join(10)
        listener.close()
    # LOGIN of a password with a space: quoted (RFC 9051 §4.3).
    assert told[0].endswith(b'LOGIN tim "pass word"')
    assert any(line.endswith(b"SELECT INBOX") for line in told)


def test_server_state():
    server = IMAPServer.new(None, None, False)
    assert server.wants_receive() and not server.rev2
    server.greet(IMAPCondition.PREAUTH, "ready", 0)
    server.receive(b"a1 ENABLE IMAP4rev2\r\n", 0)
    assert server.rev2
