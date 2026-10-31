"""SMTP (RFC 5321) without I/O: its replies, commands, paths and mail data; a client and a server of
one connection, with the extensions SIZE, PIPELINING, STARTTLS, AUTH, 8BITMIME, ENHANCEDSTATUSCODES,
CHUNKING, BINARYMIME, SMTPUTF8 and DSN. Mirrors ``umilib::protocol::smtp``.

An :class:`SMTPClient` or :class:`SMTPServer` does no I/O: give it what arrives with ``receive``, send
what ``transmit`` returns, take its events from ``poll_event`` and call ``expire`` at
``poll_timeout``. ``now`` is nanoseconds of a monotonic clock. Commands and replies cross the C ABI as
their text on the wire, which :class:`SMTPCommand` and :class:`SMTPReply` read and write. TLS and the
mechanisms of SASL are the caller's: the events tell when TLS starts and carry the data of AUTH.
Errors are :class:`SMTPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds, Text


__all__ = [
    "SMTPClient",
    "SMTPClientEvent",
    "SMTPClientEventKind",
    "SMTPCommand",
    "SMTPConfig",
    "SMTPData",
    "SMTPDataReader",
    "SMTPEnhancedStatus",
    "SMTPError",
    "SMTPExtension",
    "SMTPExtensions",
    "SMTPMailExchanger",
    "SMTPMailbox",
    "SMTPReply",
    "SMTPServer",
    "SMTPServerConfig",
    "SMTPServerEvent",
    "SMTPServerEventKind",
    "SMTPXText",
]


class SMTPError(FFIError):
    """An error of SMTP: ``Syntax``, ``TooLong`` (a line longer than the configuration takes),
    ``TooLarge``, ``State`` (not in this state, or of an extension not advertised), ``Content`` (a
    message not of its body type), ``Timeout``, ``Closed`` or ``NoMail`` (the domain takes no mail)."""


Library.register_error("protocol.smtp", SMTPError)


@dataclasses.dataclass(frozen=True)
class SMTPEnhancedStatus:
    """An enhanced status code (RFC 3463): ``class_`` (2, 4 or 5), subject and detail."""

    class_: int
    subject: int
    detail: int

    def __str__(self) -> str:
        return f"{self.class_}.{self.subject}.{self.detail}"


@dataclasses.dataclass
class SMTPReply:
    """A reply (RFC 5321 §4.2): a code of three digits and its lines of text."""

    code: int
    lines: list[bytes]

    @classmethod
    def new(cls, code: int, text: str) -> SMTPReply:
        return cls(code, [text.encode("utf-8")])

    @classmethod
    def decode(cls, wire: bytes) -> SMTPReply:
        """The reply of its text on the wire: its lines, each with its CRLF."""
        code, lines = ctypes.c_uint16(), Buffer()
        Library.default().call("umilib_protocol_smtp_smtp_reply_decode", *Bytes.readable(wire), ctypes.byref(code), ctypes.byref(lines))
        return cls(code.value, Library.default().take(lines).split(b"\n"))

    def encode(self) -> bytes:
        """The text on the wire; raises ``Syntax`` for a code or a line SMTP cannot carry."""
        return Library.default().output("umilib_protocol_smtp_smtp_reply_encode", self.code, *Bytes.readable(b"\n".join(self.lines)))

    def status(self) -> SMTPEnhancedStatus | None:
        """The enhanced status code at the start of the first line, of the reply's class (RFC 2034 §4)."""
        found, class_, subject, detail = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint16(), ctypes.c_uint16()
        Library.default().call(
            "umilib_protocol_smtp_smtp_reply_status", *Bytes.readable(self.encode()), ctypes.byref(found), ctypes.byref(class_),
            ctypes.byref(subject), ctypes.byref(detail),
        )  # fmt: skip
        return SMTPEnhancedStatus(class_.value, subject.value, detail.value) if found.value else None

    def severity(self) -> int:
        return self.code // 100

    def is_positive(self) -> bool:
        return self.severity() == 2

    def is_intermediate(self) -> bool:
        return self.severity() == 3

    def is_negative(self) -> bool:
        return self.severity() >= 4

    def text(self) -> str:
        return "\n".join(line.decode("utf-8", "replace") for line in self.lines)


@dataclasses.dataclass(frozen=True)
class SMTPCommand:
    """A command (RFC 5321 §4.1), held as its line as this library writes it, without its CRLF."""

    line: str

    @classmethod
    def parse(cls, line: bytes | str, utf8: bool = False) -> SMTPCommand:
        """The command of ``line``; UTF-8 in its paths only if ``utf8`` (RFC 6531). Raises ``Syntax``."""
        data = line.encode("utf-8") if isinstance(line, str) else line
        return cls(Library.default().output("umilib_protocol_smtp_smtp_command_normalize", *Bytes.readable(data), utf8).decode("utf-8"))

    @property
    def verb(self) -> str:
        return self.line.split(" ", 1)[0]

    def __str__(self) -> str:
        return self.line


@dataclasses.dataclass(frozen=True)
class SMTPMailbox:
    """A mailbox (RFC 5321 §4.1.2): a local part, unquoted, and a domain or an address literal."""

    local: str
    domain: str

    @classmethod
    def parse(cls, text: str, utf8: bool = False) -> SMTPMailbox:
        local, domain = Buffer(), Buffer()
        Library.default().call("umilib_protocol_smtp_smtp_mailbox_parse", *Text.encode(text), utf8, ctypes.byref(local), ctypes.byref(domain))
        return cls(Library.default().take(local).decode("utf-8"), Library.default().take(domain).decode("utf-8"))

    def __str__(self) -> str:
        """The mailbox as it is written, its local part quoted where it must be."""
        return Library.default().output("umilib_protocol_smtp_smtp_mailbox_format", *Text.encode(self.local), *Text.encode(self.domain)).decode("utf-8")


class SMTPXText:
    """The xtext of DSN (RFC 3461 §4)."""

    @staticmethod
    def encode(data: bytes) -> str:
        return Library.default().output("umilib_protocol_smtp_smtp_xtext_encode", *Bytes.readable(data)).decode("ascii")

    @staticmethod
    def decode(text: bytes | str) -> bytes:
        data = text.encode("ascii") if isinstance(text, str) else text
        return Library.default().output("umilib_protocol_smtp_smtp_xtext_decode", *Bytes.readable(data))


class SMTPData:
    """The mail data of DATA (RFC 5321 §4.5.2)."""

    @staticmethod
    def encode(message: bytes, maximum_line: int = 1000) -> bytes:
        """``message`` with a period added to each line that begins with one, a CRLF if it does not
        end with one, and the CRLF.CRLF that ends it. Raises ``Content`` for a CR or an LF alone and
        ``TooLong`` for a line longer than ``maximum_line`` with its CRLF."""
        return Library.default().output("umilib_protocol_smtp_smtp_data_encode", *Bytes.readable(message), maximum_line)


class SMTPDataReader(Handle):
    """A reader of mail data: removes the periods added for transparency and finds its end."""

    FREE = "umilib_protocol_smtp_smtp_data_reader_free"

    @classmethod
    def new(cls, maximum_size: int, maximum_line: int) -> SMTPDataReader:
        return cls(Handle.create("umilib_protocol_smtp_smtp_data_reader_new", maximum_size, maximum_line))

    def read(self, data: bytes) -> tuple[int, bytes]:
        """Reads ``data`` to the end of the mail data: how many octets were read, and the data."""
        read, out, end = ctypes.c_size_t(), Buffer(), ctypes.c_bool()
        self.library.call("umilib_protocol_smtp_smtp_data_reader_read", self.handle, *Bytes.readable(data), ctypes.byref(read), ctypes.byref(out), ctypes.byref(end))
        return read.value, self.library.take(out)

    def is_end(self) -> bool:
        return self.library.value("umilib_protocol_smtp_smtp_data_reader_is_end", ctypes.c_bool, self.handle)

    def error(self) -> SMTPError | None:
        """Why the data cannot be taken: too large, a CR or an LF alone, or a line too long."""
        status = ctypes.c_void_p()
        self.library.call("umilib_protocol_smtp_smtp_data_reader_error", self.handle, ctypes.byref(status))
        return self.library.error(status.value)


@dataclasses.dataclass(frozen=True)
class SMTPExtension:
    """An extension of the reply to EHLO (RFC 5321 §4.1.1.1): its keyword, in upper case, and parameters."""

    keyword: str
    parameters: tuple[str, ...] = ()

    @classmethod
    def parse(cls, line: str) -> SMTPExtension:
        keyword, *parameters = line.split(" ")
        return cls(keyword.upper(), tuple(parameters))


@dataclasses.dataclass
class SMTPExtensions:
    """The reply to EHLO: the greeting of its first line and the extensions of the others."""

    greeting: str
    entries: list[SMTPExtension]

    @classmethod
    def from_reply(cls, reply: SMTPReply) -> SMTPExtensions:
        greeting, entries = Buffer(), Buffer()
        Library.default().call("umilib_protocol_smtp_smtp_extensions_decode", *Bytes.readable(reply.encode()), ctypes.byref(greeting), ctypes.byref(entries))
        lines = Library.default().take(entries).decode("utf-8")
        return cls(Library.default().take(greeting).decode("utf-8"), [SMTPExtension.parse(line) for line in lines.split("\n") if line])

    def get(self, keyword: str) -> SMTPExtension | None:
        return next((entry for entry in self.entries if entry.keyword == keyword.upper()), None)

    def has(self, keyword: str) -> bool:
        return self.get(keyword) is not None


@dataclasses.dataclass(frozen=True)
class SMTPMailExchanger:
    """A host to deliver the mail of a domain to (RFC 5321 §5.1): an exchange of an MX record and its
    preference. Present when the library has ``protocol-dns``."""

    preference: int
    host: str

    @classmethod
    def order(cls, domain: str, records: str, local: list[str], random: Any) -> list[SMTPMailExchanger]:
        """The hosts of the mail of ``domain`` in the order to try them, of the MX records of the
        zone-file text ``records`` (absolute names, as :mod:`umilib.protocol.dns` writes them): by
        preference, the lowest first, those of one preference in an order drawn from ``random``; the
        domain itself if it has none. The hosts of ``local`` (this host) and those of a preference not
        lower than theirs are removed. Raises ``NoMail`` for a null MX (RFC 7505) and when none is left."""
        names = Text.array(local)
        text = Library.default().output(
            "umilib_protocol_smtp_smtp_mail_exchanger_order", *Text.encode(domain), *Text.encode(records), *names[:2], *random.source(),
        ).decode("utf-8")  # fmt: skip
        hosts = [line.split(" ", 1) for line in text.split("\n") if line]
        return [cls(int(preference), host) for preference, host in hosts]


@dataclasses.dataclass
class SMTPConfig:
    """The limits and times of a connection; the defaults are the minimums of RFC 5321 §4.5.3."""

    maximum_command_line: int
    maximum_reply_line: int
    maximum_reply_lines: int
    maximum_text_line: int
    maximum_auth_line: int
    #: The most octets held of what was received and not read.
    maximum_buffered: int
    greeting_timeout: datetime.timedelta
    command_timeout: datetime.timedelta
    data_initiation_timeout: datetime.timedelta
    data_termination_timeout: datetime.timedelta
    server_timeout: datetime.timedelta
    #: Whether a client sends a password as it is (AUTH PLAIN or LOGIN) only under TLS (RFC 2595 §2.3).
    passwords_require_tls: bool

    C_TYPE: ClassVar[str] = "umilib_protocol_smtp_SMTPConfig"
    DURATIONS: ClassVar[tuple[str, ...]] = (
        "greeting_timeout", "command_timeout", "data_initiation_timeout", "data_termination_timeout", "server_timeout",
    )  # fmt: skip

    @classmethod
    def default(cls) -> SMTPConfig:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call("umilib_protocol_smtp_smtp_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> SMTPConfig:
        values = {field.name: getattr(structure, field.name) for field in dataclasses.fields(cls)}
        for name in cls.DURATIONS:
            values[name] = Nanoseconds.to_timedelta(values[name])
        return cls(**values)

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            Fields.assign(structure, field.name, Nanoseconds.from_timedelta(value) if field.name in self.DURATIONS else value)
        return structure


@dataclasses.dataclass
class SMTPServerConfig:
    """What a server offers: its domain, the limits of a message, the extensions advertised, the SASL
    mechanisms (and those that send a password, only under TLS if ``passwords_require_tls``), what it
    requires before MAIL, and the verbs of extensions told to the caller instead of answered 500."""

    domain: str
    maximum_message_size: int
    maximum_recipients: int
    pipelining: bool
    eight_bit_mime: bool
    smtputf8: bool
    chunking: bool
    binary_mime: bool
    dsn: bool
    enhanced_status_codes: bool
    starttls: bool
    auth_mechanisms: list[str]
    plaintext_mechanisms: list[str]
    passwords_require_tls: bool
    requires_tls: bool
    requires_auth: bool
    commands: list[str]

    C_TYPE: ClassVar[str] = "umilib_protocol_smtp_SMTPServerConfig"
    LISTS: ClassVar[tuple[str, ...]] = ("domain", "auth_mechanisms", "plaintext_mechanisms", "commands")

    @classmethod
    def default(cls) -> SMTPServerConfig:
        """The defaults of the library: a domain of ``localhost``, no mechanism or command offered."""
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call("umilib_protocol_smtp_smtp_server_config_default", ctypes.byref(structure))
        values = {field.name: getattr(structure, field.name) for field in dataclasses.fields(cls) if field.name not in cls.LISTS}
        return cls(domain="localhost", auth_mechanisms=[], plaintext_mechanisms=[], commands=[], **values)

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        for field in dataclasses.fields(self):
            if field.name not in self.LISTS:
                Fields.assign(structure, field.name, getattr(self, field.name))
        return structure


class SMTPClientEventKind(enum.IntEnum):
    GREETING = 0
    REPLY = 1
    DATA_REPLY = 2
    AUTH_CHALLENGE = 3
    START_TLS = 4
    CLOSED = 5


class SMTPServerEventKind(enum.IntEnum):
    COMMAND = 0
    DATA = 1
    DATA_END = 2
    DATA_REJECTED = 3
    AUTH_RESPONSE = 4
    AUTH_CANCELLED = 5
    RESET = 6
    START_TLS = 7
    CLOSED = 8
    AUTH_FAILED = 9


@dataclasses.dataclass
class SMTPClientEvent:
    """An event of a client: the greeting, the reply to ``command``, the reply to the end of the mail
    data, a challenge of AUTH (``data``), the start of TLS, or the close (``error`` if it failed)."""

    kind: SMTPClientEventKind
    command: SMTPCommand | None = None
    reply: SMTPReply | None = None
    data: bytes = b""
    error: SMTPError | None = None

    @classmethod
    def poll(cls, client: SMTPClient) -> SMTPClientEvent | None:
        """The next event of ``client``, or ``None``."""
        library = Library.default()
        found, kind, last, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_void_p()
        command, reply, data = Buffer(), Buffer(), Buffer()
        library.call(
            "umilib_protocol_smtp_smtp_client_poll_event", client.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(reply), ctypes.byref(data), ctypes.byref(last), ctypes.byref(error),
        )  # fmt: skip
        line, wire, data_bytes = library.take(command), library.take(reply), library.take(data)
        if not found.value:
            return None
        return cls(
            SMTPClientEventKind(kind.value), SMTPCommand(line.decode("utf-8")) if line else None,
            SMTPReply.decode(wire) if wire else None, data_bytes, library.error(error.value),
        )  # fmt: skip


@dataclasses.dataclass
class SMTPServerEvent:
    """An event of a server: a command to answer, octets of mail data, the end of the data or of a
    chunk (``last``), data rejected (``error``), a response of AUTH (``data``), its cancel, the reset
    of the transaction, the start of TLS, the close (``error`` if it failed), or an AUTH exchange that
    failed with a reply of the server's own (a response not base64, a line too long)."""

    kind: SMTPServerEventKind
    command: SMTPCommand | None = None
    data: bytes = b""
    last: bool = False
    error: SMTPError | None = None

    @classmethod
    def poll(cls, server: SMTPServer) -> SMTPServerEvent | None:
        """The next event of ``server``, or ``None``."""
        library = Library.default()
        found, kind, last, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_bool(), ctypes.c_void_p()
        command, reply, data = Buffer(), Buffer(), Buffer()
        library.call(
            "umilib_protocol_smtp_smtp_server_poll_event", server.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(reply), ctypes.byref(data), ctypes.byref(last), ctypes.byref(error),
        )  # fmt: skip
        line, _, data_bytes = library.take(command), library.take(reply), library.take(data)
        if not found.value:
            return None
        return cls(
            SMTPServerEventKind(kind.value), SMTPCommand(line.decode("utf-8")) if line else None, data_bytes,
            last.value, library.error(error.value),
        )  # fmt: skip


class SMTPClient(Handle):
    """An SMTP client of one connection (RFC 5321 §4): it checks each command against the state and
    the extensions the server advertised, pipelines where PIPELINING allows (RFC 2920), and pairs
    each reply with its command."""

    FREE = "umilib_protocol_smtp_smtp_client_free"

    @classmethod
    def new(cls, config: SMTPConfig | None, secure: bool, now: int) -> SMTPClient:
        """A client of a new connection, ``secure`` if it is TLS from its start (RFC 8314)."""
        return cls(Handle.create("umilib_protocol_smtp_smtp_client_new", (config or SMTPConfig.default()).to_structure(), secure, now))

    def is_open(self) -> bool:
        return self.library.value("umilib_protocol_smtp_smtp_client_is_open", ctypes.c_bool, self.handle)

    def has_extension(self, keyword: str) -> bool:
        return self.library.value("umilib_protocol_smtp_smtp_client_has_extension", ctypes.c_bool, self.handle, *Text.encode(keyword))

    def receive(self, data: bytes, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_client_receive", self.handle, *Bytes.readable(data), now)

    def send(self, command: SMTPCommand | str, now: int, utf8: bool = False) -> None:
        """Queues ``command``; raises ``State`` for one the state or the server's extensions do not allow."""
        line = str(command).encode("utf-8")
        self.library.call("umilib_protocol_smtp_smtp_client_send", self.handle, *Bytes.readable(line), utf8, now)

    def send_data(self, message: bytes, now: int) -> None:
        """Sends ``message`` as the mail data, after the 354 to DATA."""
        self.library.call("umilib_protocol_smtp_smtp_client_send_data", self.handle, *Bytes.readable(message), now)

    def send_chunk(self, data: bytes, last: bool, now: int) -> None:
        """Sends ``data`` as a chunk of BDAT, the last of the message if ``last`` (RFC 3030)."""
        self.library.call("umilib_protocol_smtp_smtp_client_send_chunk", self.handle, *Bytes.readable(data), last, now)

    def auth_respond(self, response: bytes, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_client_auth_respond", self.handle, *Bytes.readable(response), now)

    def auth_cancel(self, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_client_auth_cancel", self.handle, now)

    def transmit(self) -> bytes:
        return self.library.output("umilib_protocol_smtp_smtp_client_transmit", self.handle)

    def poll_event(self) -> SMTPClientEvent | None:
        return SMTPClientEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional("umilib_protocol_smtp_smtp_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_client_expire", self.handle, now)


class SMTPServer(Handle):
    """An SMTP server of one connection (RFC 5321 §4): it answers what the RFCs decide (NOOP, RSET,
    QUIT, commands out of sequence or of extensions not offered, limits) and tells the caller each
    other command, one at a time, to answer with :meth:`reply`."""

    FREE = "umilib_protocol_smtp_smtp_server_free"

    @classmethod
    def new(cls, config: SMTPConfig | None, server: SMTPServerConfig | None, secure: bool) -> SMTPServer:
        server = server or SMTPServerConfig.default()
        mechanisms, plaintext, commands = Text.array(server.auth_mechanisms), Text.array(server.plaintext_mechanisms), Text.array(server.commands)
        return cls(Handle.create(
            "umilib_protocol_smtp_smtp_server_new", (config or SMTPConfig.default()).to_structure(), server.to_structure(),
            *Text.encode(server.domain), *mechanisms[:2], *plaintext[:2], *commands[:2], secure,
        ))  # fmt: skip

    def is_open(self) -> bool:
        return self.library.value("umilib_protocol_smtp_smtp_server_is_open", ctypes.c_bool, self.handle)

    def greeting(self) -> SMTPReply:
        """The 220 of the server's domain."""
        return SMTPReply.decode(self.library.output("umilib_protocol_smtp_smtp_server_greeting", self.handle))

    def greet(self, reply: SMTPReply, now: int) -> None:
        """Sends the greeting: 220, or 554 if the server takes no mail (RFC 5321 §3.1)."""
        self.library.call("umilib_protocol_smtp_smtp_server_greet", self.handle, *Bytes.readable(reply.encode()), now)

    def extensions(self) -> SMTPExtensions:
        """The extensions the server would advertise now."""
        return SMTPExtensions.from_reply(SMTPReply.decode(self.library.output("umilib_protocol_smtp_smtp_server_extensions", self.handle)))

    def wants_receive(self) -> bool:
        """Whether the server takes more input now: stop reading the connection while it is false,
        so that a peer that pipelines cannot make it hold more than ``maximum_buffered``."""
        return self.library.value("umilib_protocol_smtp_smtp_server_wants_receive", ctypes.c_bool, self.handle)

    def receive(self, data: bytes, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_server_receive", self.handle, *Bytes.readable(data), now)

    def reply(self, reply: SMTPReply, now: int) -> None:
        """Answers the command, data or AUTH exchange told; raises ``State`` if none waits."""
        self.library.call("umilib_protocol_smtp_smtp_server_reply", self.handle, *Bytes.readable(reply.encode()), now)

    def auth_challenge(self, challenge: bytes, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_server_auth_challenge", self.handle, *Bytes.readable(challenge), now)

    def shutdown(self, text: str) -> None:
        """Closes the connection with 421 (RFC 5321 §3.8); raises ``Syntax`` for a line break in ``text``."""
        self.library.call("umilib_protocol_smtp_smtp_server_shutdown", self.handle, *Text.encode(text))

    def transmit(self) -> bytes:
        return self.library.output("umilib_protocol_smtp_smtp_server_transmit", self.handle)

    def poll_event(self) -> SMTPServerEvent | None:
        return SMTPServerEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional("umilib_protocol_smtp_smtp_server_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call("umilib_protocol_smtp_smtp_server_expire", self.handle, now)
