"""Tests of umilib.protocol.ftp against the examples and rules of RFC 959, RFC 2389, RFC 2428, RFC
2577 and RFC 3659, and against the client of the Python standard library (ftplib)."""

import ftplib
import io
import socket
import threading
import time

import pytest

from umilib.protocol.ftp import (
    FTPClient,
    FTPClientEventKind,
    FTPCommand,
    FTPConfig,
    FTPDataAddress,
    FTPError,
    FTPFacts,
    FTPFeatures,
    FTPReply,
    FTPServer,
    FTPServerConfig,
    FTPServerEventKind,
    FTPTime,
)


def exchange(client: FTPClient, server: FTPServer) -> None:
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


def test_parts():
    wire = b"211-Features:\r\n MDTM\r\n SIZE\r\n REST STREAM\r\n211 End\r\n"
    reply = FTPReply.decode(wire)
    assert (reply.code, reply.encode()) == (211, wire)
    features = FTPFeatures.from_reply(reply)
    assert features.has("mdtm") and features.get("REST").parameters == "STREAM"
    # RFC 959 §4.2: a text line beginning with digits is padded.
    assert FTPReply(214, [b"a", b"123 b", b"c"]).encode() == b"214-a\r\n 123 b\r\n214 c\r\n"
    with pytest.raises(FTPError):
        FTPReply.new(260, "x").encode()
    assert FTPReply.with_pathname('/usr/dm/"q"', "created").pathname() == '/usr/dm/"q"'
    assert FTPReply.new(257, '"/usr/dm" created').pathname() == "/usr/dm"
    command = FTPCommand.parse("retr a.txt")
    assert (str(command), command.verb, command.argument, command.transfers) == ("RETR a.txt", "RETR", "a.txt", True)
    assert not FTPCommand.parse("CWD /pub").transfers
    # RFC 959 §4.1.2, RFC 2428.
    assert FTPDataAddress.parse_port("192,168,1,2,7,138") == FTPDataAddress("192.168.1.2", 1930)
    assert FTPDataAddress("192.168.1.2", 1930).format_port() == "192,168,1,2,7,138"
    assert FTPDataAddress.from_pasv(FTPReply.new(227, "Entering Passive Mode (192,168,1,2,7,138)")) == FTPDataAddress("192.168.1.2", 1930)
    assert FTPDataAddress.parse_eprt("|2|1080::8:800:200C:417A|5282|") == FTPDataAddress("1080::8:800:200c:417a", 5282)
    assert FTPDataAddress.parse_eprt("|1|132.235.1.2|6275|").format_eprt() == "|1|132.235.1.2|6275|"
    assert FTPDataAddress.from_epsv(FTPReply.new(229, "Entering Extended Passive Mode (|||6446|)")) == FTPDataAddress(None, 6446)
    assert FTPDataAddress(None, 6446).epsv_reply().encode() == b"229 Entering Extended Passive Mode (|||6446|)\r\n"
    with pytest.raises(FTPError) as raised:
        FTPDataAddress.parse_eprt("|3|x|1|")
    assert raised.value.name == "State"
    # RFC 3659 §2.3, §7.
    assert FTPTime.parse("19980615100045.014") == FTPTime(897_904_845, 14_000_000)
    assert str(FTPTime(897_904_845, 14_000_000)) == "19980615100045.014"
    facts = FTPFacts.parse("Type=file;Size=1024990;Modify=19980615100045;Perm=r; /tmp/cap60.pcap")
    assert (facts.get("type"), facts.size(), facts.modify(), facts.pathname) == ("file", 1024990, FTPTime(897_904_845), "/tmp/cap60.pcap")
    assert str(facts) == "type=file;size=1024990;modify=19980615100045;perm=r; /tmp/cap60.pcap"


def test_a_session_of_rfc_959():
    server = FTPServer.new(None, None, "127.0.0.1", False)
    client = FTPClient.new(None, False, 0)
    server.greet(FTPReply.new(220, "Service ready for new user."), 0)
    exchange(client, server)
    assert events(client)[0].kind == FTPClientEventKind.GREETING

    def round(line, *replies):
        client.send(line, 0)
        exchange(client, server)
        [told] = events(server)
        assert (told.kind, str(told.command)) == (FTPServerEventKind.COMMAND, line)
        for reply in replies:
            server.reply(reply, 0)
        exchange(client, server)
        return events(client)

    round("USER anonymous", FTPReply.new(331, "User name okay, need password."))
    round("PASS guest", FTPReply.new(230, "User logged in, proceed."))
    client.send("FEAT", 0)
    exchange(client, server)
    assert events(server) == []
    assert FTPFeatures.from_reply(events(client)[0].reply) == server.features()
    assert client.has_feature("SIZE")
    told = round("EPSV", FTPDataAddress(None, 6446).epsv_reply())
    assert FTPDataAddress.from_epsv(told[0].reply).port == 6446
    told = round("RETR a.txt", FTPReply.new(150, "opening"), FTPReply.new(226, "Closing data connection."))
    assert [event.kind for event in told] == [FTPClientEventKind.PRELIMINARY, FTPClientEventKind.REPLY]
    # RFC 2577 §3: no PORT to another host.
    client.send("PORT 10,0,0,9,7,138", 0)
    exchange(client, server)
    assert events(server) == [] and events(client)[0].reply.code == 504
    client.send("QUIT", 0)
    exchange(client, server)
    assert events(server)[-1].kind == FTPServerEventKind.CLOSED
    told = events(client)
    assert told[0].reply.code == 221 and told[-1].kind == FTPClientEventKind.CLOSED
    with pytest.raises(FTPError) as raised:
        client.send("NOOP", 0)
    assert raised.value.name == "Closed"
    config = FTPConfig.default()
    assert FTPConfig.from_structure(config.to_structure()) == config


FILES = {"hello.txt": b"Hello, FTP!\r\nsecond line\r\n", "big.bin": bytes(range(256)) * 512}


def serve(listener: socket.socket, told: list) -> None:
    """A server of one control connection of ``FILES``, its data connections passive, and STOR kept."""
    connection, (peer, _) = listener.accept()
    with connection:
        server = FTPServer.new(None, None, peer, False)
        server.greet(FTPReply.new(220, "umilib FTP ready"), time.monotonic_ns())
        passive: socket.socket | None = None
        while True:
            connection.sendall(server.transmit())
            while (event := server.poll_event()) is not None:
                now = time.monotonic_ns()
                if event.kind != FTPServerEventKind.COMMAND:
                    continue
                command = event.command
                told.append(str(command))
                if command.verb == "USER":
                    server.reply(FTPReply.new(331, "Password required"), now)
                elif command.verb == "PASS":
                    server.reply(FTPReply.new(230, "Logged in"), now)
                elif command.verb == "PWD":
                    server.reply(FTPReply.with_pathname("/", "is the current directory"), now)
                elif command.verb in ("PASV", "EPSV"):
                    passive = socket.create_server(("127.0.0.1", 0))
                    address = FTPDataAddress("127.0.0.1" if command.verb == "PASV" else None, passive.getsockname()[1])
                    server.reply(address.pasv_reply() if command.verb == "PASV" else address.epsv_reply(), now)
                elif command.verb == "SIZE":
                    server.reply(FTPReply.new(213, str(len(FILES[command.argument]))), now)
                elif command.verb == "MDTM":
                    server.reply(FTPReply.new(213, str(FTPTime(897_904_845))), now)
                elif command.verb in ("RETR", "STOR", "LIST", "NLST", "MLSD") and passive is not None:
                    server.reply(FTPReply.new(150, "Opening data connection"), now)
                    connection.sendall(server.transmit())
                    data, _ = passive.accept()
                    with data:
                        if command.verb == "RETR":
                            data.sendall(FILES[command.argument])
                        elif command.verb == "STOR":
                            received = b""
                            while chunk := data.recv(65536):
                                received += chunk
                            told.append(("STORED", command.argument, received))
                        else:
                            for name, content in FILES.items():
                                line = f"type=file;size={len(content)}; {name}" if command.verb == "MLSD" else name
                                data.sendall(line.encode() + b"\r\n")
                    passive.close()
                    passive = None
                    server.reply(FTPReply.new(226, "Transfer complete"), time.monotonic_ns())
                else:
                    server.reply(FTPReply.new(250, "OK"), now)
            connection.sendall(server.transmit())
            if not server.is_open():
                break
            data = connection.recv(65536)
            if not data:
                break
            server.receive(data, time.monotonic_ns())


def test_the_server_with_ftplib():
    listener = socket.create_server(("127.0.0.1", 0))
    told: list = []
    thread = threading.Thread(target=serve, args=(listener, told), daemon=True)
    thread.start()
    try:
        client = ftplib.FTP()
        client.connect("127.0.0.1", listener.getsockname()[1], timeout=10)
        assert client.getwelcome().startswith("220 umilib")
        client.login("anonymous", "guest@example.com")
        assert client.pwd() == "/"
        assert client.sendcmd("TYPE I").startswith("200")
        assert client.size("big.bin") == len(FILES["big.bin"])
        assert client.voidcmd("MDTM hello.txt") == "213 19980615100045"
        out = io.BytesIO()
        client.retrbinary("RETR big.bin", out.write)
        assert out.getvalue() == FILES["big.bin"]
        client.storbinary("STOR upload.bin", io.BytesIO(b"\x00\x01uploaded"))
        assert sorted(client.nlst()) == sorted(FILES)
        assert dict(client.mlsd()) == {name: {"type": "file", "size": str(len(content))} for name, content in FILES.items()}
        # FEAT is answered by the server itself (RFC 2389).
        assert "MLST" in client.sendcmd("FEAT")
        # RFC 2577 §3: PORT to another host is refused with 504.
        with pytest.raises(ftplib.error_perm, match="^504"):
            client.sendcmd("PORT 10,0,0,9,7,138")
        client.quit()
    finally:
        thread.join(10)
        listener.close()
    assert ("STORED", "upload.bin", b"\x00\x01uploaded") in told
    assert told[0] == "USER anonymous"


def test_session_state():
    # RFC 959 §5.1 and RFC 4217 §9: what the session set is the application's to transfer by.
    server = FTPServer.new(None, None, "127.0.0.1", False)
    server.greet(FTPReply.new(220, "ready"), 0)
    assert server.wants_receive()
    server.receive(b"USER u\r\n", 0)
    server.poll_event()
    server.reply(FTPReply.new(230, "in"), 0)
    server.receive(b"TYPE I\r\nREST 7\r\n", 0)
    server.poll_event()
    server.reply(FTPReply.new(350, "restarting"), 0)
    session = server.session()
    assert (session.logged_in, session.representation, session.mode, session.structure, session.protection, session.restart) == (True, "I", "S", "F", "C", "7")
