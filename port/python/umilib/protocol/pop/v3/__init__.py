"""POP3 (RFC 1939) without I/O: its commands, status lines and multi-line responses; a client and a
server of one connection, with CAPA (RFC 2449), STLS (RFC 2595), AUTH (RFC 5034) and UTF8 and LANG
(RFC 6856). Mirrors ``umilib::protocol::pop::v3``.

A :class:`POP3Client` or :class:`POP3Server` does no I/O: give it what arrives with ``receive``, send
what ``transmit`` returns, take its events from ``poll_event`` and call ``expire`` at
``poll_timeout``. ``now`` is nanoseconds of a monotonic clock. Commands and status lines cross the C
ABI as their lines without CRLF, which :class:`POP3Command` and :class:`POP3Response` read and write.
The maildrop, TLS and the mechanisms of SASL are the caller's. Errors are :class:`POP3Error`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds, Text

P = "umilib_protocol_pop_v3"

__all__ = [
    "POP3Capabilities",
    "POP3Capability",
    "POP3Client",
    "POP3ClientEvent",
    "POP3ClientEventKind",
    "POP3Command",
    "POP3Config",
    "POP3Error",
    "POP3MultiLineReader",
    "POP3MultiLineWriter",
    "POP3Response",
    "POP3Server",
    "POP3ServerConfig",
    "POP3ServerEvent",
    "POP3ServerEventKind",
    "POP3State",
]


class POP3Error(FFIError):
    """An error of POP3: ``Syntax``, ``TooLong`` (a line longer than the configuration takes),
    ``State`` (not in this state, or of a capability not announced), ``Timeout`` or ``Closed``."""


Library.register_error("protocol.pop.v3", POP3Error)


class POP3State(enum.IntEnum):
    """The state of a session (RFC 1939 §3)."""

    AUTHORIZATION = 0
    TRANSACTION = 1
    UPDATE = 2


@dataclasses.dataclass
class POP3Response:
    """A status line (RFC 1939 §3, RFC 2449 §8): ``+OK`` or ``-ERR``, the levels of a response code
    if it has one, and text."""

    ok: bool
    code: list[str]
    text: bytes

    @classmethod
    def positive(cls, text: str) -> POP3Response:
        return cls(True, [], text.encode("utf-8"))

    @classmethod
    def negative(cls, text: str, code: list[str] | None = None) -> POP3Response:
        return cls(False, list(code or []), text.encode("utf-8"))

    @classmethod
    def parse(cls, line: bytes) -> POP3Response:
        """The response of a status line without its CRLF; raises ``Syntax``."""
        ok, code, text = ctypes.c_bool(), Buffer(), Buffer()
        Library.default().call(f"{P}_pop3_response_decode", *Bytes.readable(line), ctypes.byref(ok), ctypes.byref(code), ctypes.byref(text))
        code_text = Library.default().take(code).decode("utf-8")
        return cls(ok.value, code_text.split("/") if code_text else [], Library.default().take(text))

    def encode(self) -> bytes:
        """The status line without its CRLF; raises ``Syntax`` for a level or text it cannot have."""
        return Library.default().output(f"{P}_pop3_response_encode", self.ok, *Text.encode("/".join(self.code)), *Bytes.readable(self.text))

    def timestamp(self) -> bytes | None:
        """The timestamp of a greeting for APOP (RFC 1939 §7), its angle brackets included."""
        return Library.default().optional(f"{P}_pop3_response_timestamp", Buffer, *Bytes.readable(self.encode()))

    def has_code(self, levels: list[str]) -> bool:
        return len(self.code) == len(levels) and all(a.upper() == b.upper() for a, b in zip(self.code, levels))


@dataclasses.dataclass(frozen=True)
class POP3Command:
    """A command (RFC 1939 §3), held as its line as this library writes it, without its CRLF."""

    line: str

    @classmethod
    def parse(cls, line: bytes | str, utf8: bool = False) -> POP3Command:
        """The command of ``line``; UTF-8 arguments only if ``utf8`` (RFC 6856). Raises ``Syntax``."""
        data = line.encode("utf-8") if isinstance(line, str) else line
        return cls(Library.default().output(f"{P}_pop3_command_normalize", *Bytes.readable(data), utf8).decode("utf-8"))

    @classmethod
    def apop(cls, name: str, timestamp: bytes, secret: bytes) -> POP3Command:
        """The APOP command of ``name`` for the greeting's timestamp and the shared secret (RFC 1939 §7)."""
        return cls.parse(f"APOP {name} {cls.apop_digest(timestamp, secret)}", utf8=True)

    @staticmethod
    def apop_digest(timestamp: bytes, secret: bytes) -> str:
        """MD5 of the timestamp and the secret, in lower-case hexadecimal. Present when the library
        has ``hash-md-v5`` and ``secret``."""
        return Library.default().output(f"{P}_pop3_command_apop_digest", *Bytes.readable(timestamp), *Bytes.readable(secret)).decode("ascii")

    @staticmethod
    def apop_matches(digest: str, timestamp: bytes, secret: bytes) -> bool:
        """Whether ``digest`` is the APOP digest of the timestamp and the secret, compared in constant time."""
        return Library.default().value(
            f"{P}_pop3_command_apop_matches", ctypes.c_bool, *Text.encode(digest), *Bytes.readable(timestamp), *Bytes.readable(secret),
        )  # fmt: skip

    @property
    def keyword(self) -> str:
        return self.line.split(" ", 1)[0]

    def is_multi_line(self) -> bool:
        """Whether a positive response to the command has lines after it."""
        return Library.default().value(f"{P}_pop3_command_is_multi_line", ctypes.c_bool, *Text.encode(self.line))

    def __str__(self) -> str:
        return self.line


@dataclasses.dataclass(frozen=True)
class POP3Capability:
    """A capability of the CAPA list (RFC 2449 §5): a tag, in upper case, and parameters."""

    tag: str
    parameters: tuple[str, ...] = ()

    def line(self) -> str:
        return " ".join((self.tag, *self.parameters))


@dataclasses.dataclass
class POP3Capabilities:
    """The capabilities a server announced."""

    entries: list[POP3Capability]

    @classmethod
    def parse(cls, data: bytes) -> POP3Capabilities:
        """The capabilities of the lines of a CAPA list, its periods removed; other lines are left out."""
        text = Library.default().output(f"{P}_pop3_capabilities_decode", *Bytes.readable(data)).decode("utf-8")
        return cls([POP3Capability(words[0], tuple(words[1:])) for words in (line.split(" ") for line in text.split("\n") if line)])

    def get(self, tag: str) -> POP3Capability | None:
        return next((entry for entry in self.entries if entry.tag == tag.upper()), None)

    def has(self, tag: str) -> bool:
        return self.get(tag) is not None

    def sasl_mechanisms(self) -> list[str]:
        """The mechanisms of SASL (RFC 2449 §6.3)."""
        entry = self.get("SASL")
        return list(entry.parameters) if entry else []

    def encode(self) -> bytes:
        """The lines of the list, each with its CRLF, without the period that ends it."""
        return b"".join(entry.line().encode("utf-8") + b"\r\n" for entry in self.entries)


class POP3MultiLineReader(Handle):
    """A reader of the lines of a multi-line response: removes the periods added and finds its end.
    Only CRLF ends a line."""

    FREE = f"{P}_pop3_multi_line_reader_free"

    @classmethod
    def new(cls) -> POP3MultiLineReader:
        return cls(Handle.create(f"{P}_pop3_multi_line_reader_new"))

    def read(self, data: bytes) -> tuple[int, bytes, bool]:
        """Reads ``data`` to the end of the response: the octets read, the lines and whether it ended."""
        read, out, end = ctypes.c_size_t(), Buffer(), ctypes.c_bool()
        self.library.call(f"{P}_pop3_multi_line_reader_read", self.handle, *Bytes.readable(data), ctypes.byref(read), ctypes.byref(out), ctypes.byref(end))
        return read.value, self.library.take(out), end.value


class POP3MultiLineWriter(Handle):
    """A writer of the lines of a multi-line response, in pieces: every line break as CRLF, a period
    added before a line that begins with one."""

    FREE = f"{P}_pop3_multi_line_writer_free"

    @classmethod
    def new(cls) -> POP3MultiLineWriter:
        return cls(Handle.create(f"{P}_pop3_multi_line_writer_new"))

    def write(self, data: bytes) -> bytes:
        return self.library.output(f"{P}_pop3_multi_line_writer_write", self.handle, *Bytes.readable(data))

    def finish(self) -> bytes:
        """The end of the response: a CRLF if the last line has none, and the line of a period."""
        return self.library.output(f"{P}_pop3_multi_line_writer_finish", self.handle)

    @staticmethod
    def canonical_length(data: bytes) -> int:
        """The octets of ``data`` as the writer sends them, without the added periods and the end:
        the size of a message LIST gives (RFC 6856 §2.1)."""
        return Library.default().value(f"{P}_pop3_multi_line_canonical_length", ctypes.c_uint64, *Bytes.readable(data))


@dataclasses.dataclass
class POP3Config:
    """The limits and times of a connection; the autologout timer is at least 10 minutes (RFC 1939 §3)."""

    maximum_command_line: int
    maximum_response_line: int
    maximum_auth_line: int
    maximum_capabilities: int
    maximum_buffered: int
    response_timeout: datetime.timedelta
    autologout: datetime.timedelta
    #: Whether a client sends a password as it is (USER and PASS, APOP, PLAIN, LOGIN) only under TLS
    #: (RFC 2595 §2.3).
    passwords_require_tls: bool

    C_TYPE: ClassVar[str] = f"{P}_POP3Config"
    DURATIONS: ClassVar[tuple[str, ...]] = ("response_timeout", "autologout")

    @classmethod
    def default(cls) -> POP3Config:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_pop3_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> POP3Config:
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
class POP3ServerConfig:
    """What a server offers and requires (RFC 2449 §6): the capabilities announced, the SASL mechanisms
    (and those that send a password, taken only under TLS if ``passwords_require_tls``, with USER,
    PASS and APOP), and the commands of extensions told to the caller instead of refused."""

    user: bool
    top: bool
    uidl: bool
    pipelining: bool
    response_codes: bool
    stls: bool
    sasl_mechanisms: list[str]
    plaintext_mechanisms: list[str]
    passwords_require_tls: bool
    utf8: bool
    utf8_user: bool
    lang: bool
    login_delay: int | None
    expire: str | None
    implementation: str | None
    commands: list[str]

    C_TYPE: ClassVar[str] = f"{P}_POP3ServerConfig"
    BESIDE: ClassVar[tuple[str, ...]] = ("sasl_mechanisms", "plaintext_mechanisms", "login_delay", "expire", "implementation", "commands")

    @classmethod
    def default(cls) -> POP3ServerConfig:
        """The defaults of the library: no mechanism offered."""
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_pop3_server_config_default", ctypes.byref(structure))
        values = {field.name: getattr(structure, field.name) for field in dataclasses.fields(cls) if field.name not in cls.BESIDE}
        login_delay = structure.login_delay if structure.has_login_delay else None
        return cls(
            sasl_mechanisms=[], plaintext_mechanisms=[], login_delay=login_delay, expire=None, implementation=None,
            commands=[], **values,
        )  # fmt: skip

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        for field in dataclasses.fields(self):
            if field.name not in self.BESIDE:
                Fields.assign(structure, field.name, getattr(self, field.name))
        structure.has_login_delay = self.login_delay is not None
        Fields.assign(structure, "login_delay", self.login_delay or 0)
        return structure


class POP3ClientEventKind(enum.IntEnum):
    GREETING = 0
    RESPONSE = 1
    DATA = 2
    DATA_END = 3
    AUTH_CHALLENGE = 4
    START_TLS = 5
    CLOSED = 6


class POP3ServerEventKind(enum.IntEnum):
    COMMAND = 0
    AUTH_RESPONSE = 1
    AUTH_CANCELLED = 2
    START_TLS = 3
    CLOSED = 4
    AUTH_FAILED = 5


@dataclasses.dataclass
class POP3ClientEvent:
    """An event of a client: the greeting, the response to ``command`` (followed by its lines and
    their end if it is positive and multi-line), a challenge of AUTH (``data``), the start of TLS, or
    the close (``error`` if it failed)."""

    kind: POP3ClientEventKind
    command: POP3Command | None = None
    response: POP3Response | None = None
    data: bytes = b""
    error: POP3Error | None = None

    @classmethod
    def poll(cls, client: POP3Client) -> POP3ClientEvent | None:
        """The next event of ``client``, or ``None``."""
        library = Library.default()
        found, kind, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p()
        command, response, data = Buffer(), Buffer(), Buffer()
        library.call(
            f"{P}_pop3_client_poll_event", client.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(response), ctypes.byref(data), ctypes.byref(error),
        )  # fmt: skip
        line, status, data_bytes = library.take(command), library.take(response), library.take(data)
        if not found.value:
            return None
        return cls(
            POP3ClientEventKind(kind.value), POP3Command(line.decode("utf-8")) if line else None,
            POP3Response.parse(status) if status else None, data_bytes, library.error(error.value),
        )  # fmt: skip


@dataclasses.dataclass
class POP3ServerEvent:
    """An event of a server: a command to answer, a response of AUTH (``data``), its cancel, the start
    of TLS, or the close (``error`` if it failed)."""

    kind: POP3ServerEventKind
    command: POP3Command | None = None
    data: bytes = b""
    error: POP3Error | None = None

    @classmethod
    def poll(cls, server: POP3Server) -> POP3ServerEvent | None:
        """The next event of ``server``, or ``None``."""
        library = Library.default()
        found, kind, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p()
        command, response, data = Buffer(), Buffer(), Buffer()
        library.call(
            f"{P}_pop3_server_poll_event", server.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(response), ctypes.byref(data), ctypes.byref(error),
        )  # fmt: skip
        line, _, data_bytes = library.take(command), library.take(response), library.take(data)
        if not found.value:
            return None
        return cls(POP3ServerEventKind(kind.value), POP3Command(line.decode("utf-8")) if line else None, data_bytes, library.error(error.value))


class POP3Client(Handle):
    """A POP3 client of one connection (RFC 1939): commands sent in order, pipelined when the server
    announces PIPELINING (RFC 2449 §6.6), STLS and AUTH only when announced, each in its state."""

    FREE = f"{P}_pop3_client_free"

    @classmethod
    def new(cls, config: POP3Config | None, secure: bool, now: int) -> POP3Client:
        """A client of a new connection, ``secure`` if it is TLS from its start (RFC 8314)."""
        return cls(Handle.create(f"{P}_pop3_client_new", (config or POP3Config.default()).to_structure(), secure, now))

    @property
    def state(self) -> POP3State:
        return POP3State(self.library.value(f"{P}_pop3_client_state", ctypes.c_uint8, self.handle))

    def is_open(self) -> bool:
        return self.library.value(f"{P}_pop3_client_is_open", ctypes.c_bool, self.handle)

    def has_capability(self, tag: str) -> bool:
        return self.library.value(f"{P}_pop3_client_has_capability", ctypes.c_bool, self.handle, *Text.encode(tag))

    def receive(self, data: bytes, now: int) -> None:
        self.library.call(f"{P}_pop3_client_receive", self.handle, *Bytes.readable(data), now)

    def send(self, command: POP3Command | str, now: int, utf8: bool = False) -> None:
        """Queues ``command``; raises ``State`` for one the state or the capabilities do not allow."""
        self.library.call(f"{P}_pop3_client_send", self.handle, *Bytes.readable(str(command).encode("utf-8")), utf8, now)

    def auth_respond(self, response: bytes, now: int) -> None:
        self.library.call(f"{P}_pop3_client_auth_respond", self.handle, *Bytes.readable(response), now)

    def auth_cancel(self, now: int) -> None:
        self.library.call(f"{P}_pop3_client_auth_cancel", self.handle, now)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_pop3_client_transmit", self.handle)

    def poll_event(self) -> POP3ClientEvent | None:
        return POP3ClientEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_pop3_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call(f"{P}_pop3_client_expire", self.handle, now)


class POP3Server(Handle):
    """A POP3 server of one connection (RFC 1939): it answers CAPA, NOOP, QUIT in AUTHORIZATION and
    commands of the wrong state itself, and tells the caller each other command, one at a time."""

    FREE = f"{P}_pop3_server_free"

    @classmethod
    def new(cls, config: POP3Config | None, server: POP3ServerConfig | None, secure: bool) -> POP3Server:
        server = server or POP3ServerConfig.default()
        mechanisms, plaintext, commands = Text.array(server.sasl_mechanisms), Text.array(server.plaintext_mechanisms), Text.array(server.commands)
        return cls(Handle.create(
            f"{P}_pop3_server_new", (config or POP3Config.default()).to_structure(), server.to_structure(), *mechanisms[:2],
            *plaintext[:2], *commands[:2], *Text.encode(server.expire), *Text.encode(server.implementation), secure,
        ))  # fmt: skip

    def is_open(self) -> bool:
        return self.library.value(f"{P}_pop3_server_is_open", ctypes.c_bool, self.handle)

    def passwords_taken(self) -> bool:
        """Whether passwords sent as they are are taken now (RFC 5034 §4)."""
        return self.library.value(f"{P}_pop3_server_passwords_taken", ctypes.c_bool, self.handle)

    def capabilities(self) -> POP3Capabilities:
        """The capabilities the server would announce now."""
        return POP3Capabilities.parse(self.library.output(f"{P}_pop3_server_capabilities", self.handle))

    def greet(self, response: POP3Response, now: int) -> None:
        """Sends the greeting: +OK, with a timestamp if APOP is offered; -ERR closes the connection."""
        self.library.call(f"{P}_pop3_server_greet", self.handle, *Bytes.readable(response.encode()), now)

    def wants_receive(self) -> bool:
        """Whether the server takes more input now: stop reading the connection while it is false,
        so that a peer that pipelines cannot make it hold more than ``maximum_buffered``."""
        return self.library.value(f"{P}_pop3_server_wants_receive", ctypes.c_bool, self.handle)

    def receive(self, data: bytes, now: int) -> None:
        self.library.call(f"{P}_pop3_server_receive", self.handle, *Bytes.readable(data), now)

    def reply(self, response: POP3Response, now: int) -> None:
        """Answers the command told; a positive answer to a multi-line command is followed by
        :meth:`send_data` and :meth:`end_data`."""
        self.library.call(f"{P}_pop3_server_reply", self.handle, *Bytes.readable(response.encode()), now)

    def send_data(self, data: bytes) -> None:
        self.library.call(f"{P}_pop3_server_send_data", self.handle, *Bytes.readable(data))

    def end_data(self, now: int) -> None:
        self.library.call(f"{P}_pop3_server_end_data", self.handle, now)

    def auth_challenge(self, challenge: bytes, now: int) -> None:
        self.library.call(f"{P}_pop3_server_auth_challenge", self.handle, *Bytes.readable(challenge), now)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_pop3_server_transmit", self.handle)

    def poll_event(self) -> POP3ServerEvent | None:
        return POP3ServerEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_pop3_server_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call(f"{P}_pop3_server_expire", self.handle, now)
