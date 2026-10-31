"""FTP (RFC 959) of the control connection without I/O: its commands and replies, the addresses of
data connections (PORT, PASV, EPRT, EPSV of RFC 2428), the features of FEAT (RFC 2389), the times and
facts of RFC 3659, and a client and a server, with FTPS (RFC 4217). Mirrors ``umilib::protocol::ftp``.

An :class:`FTPClient` or :class:`FTPServer` does no I/O: give it what arrives with ``receive``, send
what ``transmit`` returns, take its events from ``poll_event`` and call ``expire`` at
``poll_timeout``. ``now`` is nanoseconds of a monotonic clock. Commands cross the C ABI as their lines
without CRLF, replies as their lines with CRLFs. The files, the data connections and TLS are the
caller's. Errors are :class:`FTPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
import ipaddress
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds, Text


__all__ = [
    "FTPClient",
    "FTPClientEvent",
    "FTPClientEventKind",
    "FTPCommand",
    "FTPConfig",
    "FTPDataAddress",
    "FTPError",
    "FTPFacts",
    "FTPFeature",
    "FTPFeatures",
    "FTPReply",
    "FTPServer",
    "FTPServerConfig",
    "FTPServerEvent",
    "FTPServerEventKind",
    "FTPSession",
    "FTPTime",
]


class FTPError(FFIError):
    """An error of FTP: ``Syntax``, ``TooLong`` (a line longer than the configuration takes),
    ``State`` (not in this state, or of a feature not listed), ``Timeout`` or ``Closed``."""


Library.register_error("protocol.ftp", FTPError)


@dataclasses.dataclass
class FTPReply:
    """A reply (RFC 959 §4.2): a code and its lines of text."""

    code: int
    lines: list[bytes]

    @classmethod
    def new(cls, code: int, text: str) -> FTPReply:
        return cls(code, [text.encode("utf-8")])

    @classmethod
    def decode(cls, wire: bytes) -> FTPReply:
        """The reply of its lines on the wire, each with its CRLF."""
        code, lines = ctypes.c_uint16(), Buffer()
        Library.default().call("umilib_protocol_ftp_ftp_reply_decode", *Bytes.readable(wire), ctypes.byref(code), ctypes.byref(lines))
        return cls(code.value, Library.default().take(lines).split(b"\n"))

    def encode(self) -> bytes:
        return Library.default().output("umilib_protocol_ftp_ftp_reply_encode", self.code, *Bytes.readable(b"\n".join(self.lines)))

    @classmethod
    def with_pathname(cls, pathname: str, text: str) -> FTPReply:
        """The reply to PWD or MKD of ``pathname`` (RFC 959 Appendix II): ``257 "name" text``."""
        return cls.decode(Library.default().output("umilib_protocol_ftp_ftp_reply_with_pathname", *Text.encode(pathname), *Text.encode(text)))

    def pathname(self) -> str | None:
        """The pathname of a reply to PWD or MKD, its doubled quotes undone."""
        name = Library.default().optional("umilib_protocol_ftp_ftp_reply_pathname", Buffer, *Bytes.readable(self.encode()))
        return None if name is None else name.decode("utf-8")

    def severity(self) -> int:
        return self.code // 100

    def is_preliminary(self) -> bool:
        return self.severity() == 1

    def is_positive(self) -> bool:
        return self.severity() == 2

    def is_intermediate(self) -> bool:
        return self.severity() == 3

    def is_negative(self) -> bool:
        return self.severity() >= 4

    def text(self) -> str:
        return "\n".join(line.decode("utf-8", "replace") for line in self.lines)


@dataclasses.dataclass(frozen=True)
class FTPCommand:
    """A command (RFC 959 §4.1): its line as this library writes it, and whether it transfers data."""

    line: str
    transfers: bool = False

    @classmethod
    def parse(cls, line: bytes | str) -> FTPCommand:
        data = line.encode("utf-8") if isinstance(line, str) else line
        transfers, out = ctypes.c_bool(), Buffer()
        Library.default().call("umilib_protocol_ftp_ftp_command_normalize", *Bytes.readable(data), ctypes.byref(transfers), ctypes.byref(out))
        return cls(Library.default().take(out).decode("utf-8"), transfers.value)

    @property
    def verb(self) -> str:
        return self.line.split(" ", 1)[0]

    @property
    def argument(self) -> str | None:
        parts = self.line.split(" ", 1)
        return parts[1] if len(parts) == 2 else None

    def __str__(self) -> str:
        return self.line


@dataclasses.dataclass(frozen=True)
class FTPFeature:
    """A feature of the reply to FEAT (RFC 2389 §3.2): a name, in upper case, and its parameters."""

    name: str
    parameters: str = ""


@dataclasses.dataclass
class FTPFeatures:
    """The features of a reply to FEAT."""

    entries: list[FTPFeature]

    @classmethod
    def from_reply(cls, reply: FTPReply) -> FTPFeatures:
        text = Library.default().output("umilib_protocol_ftp_ftp_features_decode", *Bytes.readable(reply.encode())).decode("utf-8")
        return cls([FTPFeature(*(line.split(" ", 1) + [""])[:2]) for line in text.split("\n") if line])

    def get(self, name: str) -> FTPFeature | None:
        return next((entry for entry in self.entries if entry.name == name.upper()), None)

    def has(self, name: str) -> bool:
        return self.get(name) is not None


@dataclasses.dataclass(frozen=True)
class FTPDataAddress:
    """The address of a data connection: of PORT and PASV (RFC 959 §4.1.2), of EPRT and EPSV (RFC
    2428). The reply to EPSV gives no host (``None``): the client connects to the server's."""

    host: str | None
    port: int

    C_TYPE: ClassVar[str] = "umilib_protocol_ftp_FTPDataAddress"

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        if self.host is not None:
            octets = ipaddress.ip_address(self.host).packed
            ctypes.memmove(structure.octets, octets, len(octets))
            structure.length = len(octets)
        Fields.assign(structure, "port", self.port)
        return structure

    @classmethod
    def from_structure(cls, structure: Any) -> FTPDataAddress:
        host = str(ipaddress.ip_address(bytes(structure.octets[: structure.length]))) if structure.length else None
        return cls(host, structure.port)

    @classmethod
    def parse_port(cls, text: str) -> FTPDataAddress:
        return cls.from_structure(Library.default().value("umilib_protocol_ftp_ftp_data_address_parse_port", Library.default().type(cls.C_TYPE), *Text.encode(text)))

    def format_port(self) -> str:
        return Library.default().output("umilib_protocol_ftp_ftp_data_address_format_port", self.to_structure()).decode("ascii")

    @classmethod
    def parse_eprt(cls, text: str) -> FTPDataAddress:
        """The address of EPRT; raises ``State`` for a network protocol not supported (522)."""
        return cls.from_structure(Library.default().value("umilib_protocol_ftp_ftp_data_address_parse_eprt", Library.default().type(cls.C_TYPE), *Text.encode(text)))

    def format_eprt(self) -> str:
        return Library.default().output("umilib_protocol_ftp_ftp_data_address_format_eprt", self.to_structure()).decode("ascii")

    @classmethod
    def from_pasv(cls, reply: FTPReply) -> FTPDataAddress:
        return cls.from_structure(Library.default().value("umilib_protocol_ftp_ftp_data_address_from_pasv", Library.default().type(cls.C_TYPE), *Bytes.readable(reply.encode())))

    def pasv_reply(self) -> FTPReply:
        return FTPReply.decode(Library.default().output("umilib_protocol_ftp_ftp_data_address_pasv_reply", self.to_structure()))

    @classmethod
    def from_epsv(cls, reply: FTPReply) -> FTPDataAddress:
        return cls.from_structure(Library.default().value("umilib_protocol_ftp_ftp_data_address_from_epsv", Library.default().type(cls.C_TYPE), *Bytes.readable(reply.encode())))

    def epsv_reply(self) -> FTPReply:
        return FTPReply.decode(Library.default().output("umilib_protocol_ftp_ftp_data_address_epsv_reply", self.to_structure()))


@dataclasses.dataclass(frozen=True, order=True)
class FTPTime:
    """A time of RFC 3659 §2.3 (MDTM, the modify fact), of UTC: seconds since 1970 and nanoseconds."""

    seconds: int
    nanoseconds: int = 0

    @classmethod
    def parse(cls, text: str) -> FTPTime:
        seconds, nanoseconds = ctypes.c_int64(), ctypes.c_uint32()
        Library.default().call("umilib_protocol_ftp_ftp_time_parse", *Text.encode(text), ctypes.byref(seconds), ctypes.byref(nanoseconds))
        return cls(seconds.value, nanoseconds.value)

    def __str__(self) -> str:
        return Library.default().output("umilib_protocol_ftp_ftp_time_format", self.seconds, self.nanoseconds).decode("ascii")


@dataclasses.dataclass(frozen=True)
class FTPFacts:
    """An entry of MLST and MLSD (RFC 3659 §7.2): its facts, names in lower case, and its pathname."""

    facts: tuple[tuple[str, str], ...]
    pathname: str

    @classmethod
    def parse(cls, line: str) -> FTPFacts:
        text = Library.default().output("umilib_protocol_ftp_ftp_facts_normalize", *Text.encode(line)).decode("utf-8")
        facts, pathname = text.split(" ", 1)
        pairs = tuple(tuple(fact.split("=", 1)) for fact in facts.split(";") if fact)
        return cls(pairs, pathname)  # type: ignore[arg-type]

    def get(self, name: str) -> str | None:
        return next((value for fact, value in self.facts if fact == name.lower()), None)

    def size(self) -> int | None:
        value = self.get("size")
        return int(value) if value is not None and value.isdigit() else None

    def modify(self) -> FTPTime | None:
        value = self.get("modify")
        if value is None:
            return None
        try:
            return FTPTime.parse(value)
        except FTPError:
            return None

    def __str__(self) -> str:
        return "".join(f"{name}={value};" for name, value in self.facts) + " " + self.pathname


@dataclasses.dataclass
class FTPConfig:
    """The limits and times of a control connection."""

    maximum_line: int
    maximum_reply_lines: int
    maximum_buffered: int
    reply_timeout: datetime.timedelta
    idle_timeout: datetime.timedelta

    C_TYPE: ClassVar[str] = "umilib_protocol_ftp_FTPConfig"
    DURATIONS: ClassVar[tuple[str, ...]] = ("reply_timeout", "idle_timeout")

    @classmethod
    def default(cls) -> FTPConfig:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call("umilib_protocol_ftp_ftp_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> FTPConfig:
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
class FTPServerConfig:
    """What a server offers and requires: its system's type, FTPS (RFC 4217) and what it requires of
    it, whether PORT and EPRT may name another host (RFC 2577), the features of RFC 3659, RFC 2640 and
    RFC 7151, other features, and the commands of extensions told to the caller instead of refused."""

    system: str
    tls: bool
    require_tls: bool
    require_protection: bool
    allow_ccc: bool
    allow_foreign_data: bool
    size: bool
    mdtm: bool
    rest_stream: bool
    mlst_facts: list[str]
    utf8: bool
    host: bool
    features: list[str]
    commands: list[str]

    C_TYPE: ClassVar[str] = "umilib_protocol_ftp_FTPServerConfig"
    BESIDE: ClassVar[tuple[str, ...]] = ("system", "mlst_facts", "features", "commands")

    @classmethod
    def default(cls) -> FTPServerConfig:
        """The defaults of the library: a UNIX system, the facts type, size, modify, perm and unique."""
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call("umilib_protocol_ftp_ftp_server_config_default", ctypes.byref(structure))
        values = {field.name: getattr(structure, field.name) for field in dataclasses.fields(cls) if field.name not in cls.BESIDE}
        facts = ["type*", "size*", "modify*", "perm", "unique"]
        return cls(system="UNIX Type: L8", mlst_facts=facts, features=[], commands=[], **values)

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        for field in dataclasses.fields(self):
            if field.name not in self.BESIDE:
                Fields.assign(structure, field.name, getattr(self, field.name))
        return structure


@dataclasses.dataclass(frozen=True)
class FTPSession:
    """What a session set, as :meth:`FTPServer.session` gives it: whether a user is logged in, the
    representation type (``A N``, ``I`` or ``L 8``), the mode, the structure, the protection of data
    connections (``C`` or ``P``, RFC 4217 §9) and the REST marker of the next transfer."""

    logged_in: bool
    representation: str
    mode: str
    structure: str
    protection: str
    restart: str | None


class FTPClientEventKind(enum.IntEnum):
    GREETING = 0
    PRELIMINARY = 1
    REPLY = 2
    START_TLS = 3
    CLEAR_COMMAND_CHANNEL = 4
    CLOSED = 5


class FTPServerEventKind(enum.IntEnum):
    COMMAND = 0
    START_TLS = 1
    CLEAR_COMMAND_CHANNEL = 2
    CLOSED = 3


@dataclasses.dataclass
class FTPClientEvent:
    """An event of a client: the greeting, a preliminary or final ``reply`` to ``command``, the start
    of TLS (234 to AUTH TLS), the end of it (200 to CCC), or the close (``error`` if it failed)."""

    kind: FTPClientEventKind
    command: FTPCommand | None = None
    reply: FTPReply | None = None
    error: FTPError | None = None

    @classmethod
    def poll(cls, client: FTPClient) -> FTPClientEvent | None:
        """The next event of ``client``, or ``None``."""
        library = Library.default()
        found, kind, error, command, reply = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p(), Buffer(), Buffer()
        library.call(
            "umilib_protocol_ftp_ftp_client_poll_event", client.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(reply), ctypes.byref(error),
        )  # fmt: skip
        line, wire = library.take(command), library.take(reply)
        if not found.value:
            return None
        return cls(
            FTPClientEventKind(kind.value), FTPCommand.parse(line) if line else None, FTPReply.decode(wire) if wire else None,
            library.error(error.value),
        )  # fmt: skip


@dataclasses.dataclass
class FTPServerEvent:
    """An event of a server: a ``command`` to answer, the start of TLS, the end of it, or the close."""

    kind: FTPServerEventKind
    command: FTPCommand | None = None
    error: FTPError | None = None

    @classmethod
    def poll(cls, server: FTPServer) -> FTPServerEvent | None:
        """The next event of ``server``, or ``None``."""
        library = Library.default()
        found, kind, error, command, reply = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p(), Buffer(), Buffer()
        library.call(
            "umilib_protocol_ftp_ftp_server_poll_event", server.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(command),
            ctypes.byref(reply), ctypes.byref(error),
        )  # fmt: skip
        line, _ = library.take(command), library.take(reply)
        if not found.value:
            return None
        return cls(FTPServerEventKind(kind.value), FTPCommand.parse(line) if line else None, library.error(error.value))


class FTPClient(Handle):
    """An FTP client of the control connection (RFC 959): commands sent one at a time (§5.4), but
    ABOR, STAT and QUIT during a transfer; the data connections are the caller's."""

    FREE = "umilib_protocol_ftp_ftp_client_free"

    @classmethod
    def new(cls, config: FTPConfig | None, secure: bool, now: int) -> FTPClient:
        """A client of a new control connection, ``secure`` if it is TLS from its start."""
        return cls(Handle.create("umilib_protocol_ftp_ftp_client_new", (config or FTPConfig.default()).to_structure(), secure, now))

    def is_open(self) -> bool:
        return self.library.value("umilib_protocol_ftp_ftp_client_is_open", ctypes.c_bool, self.handle)

    def has_feature(self, name: str) -> bool:
        return self.library.value("umilib_protocol_ftp_ftp_client_has_feature", ctypes.c_bool, self.handle, *Text.encode(name))

    def receive(self, data: bytes, now: int) -> None:
        self.library.call("umilib_protocol_ftp_ftp_client_receive", self.handle, *Bytes.readable(data), now)

    def send(self, command: FTPCommand | str, now: int) -> None:
        """Queues ``command``; raises ``State`` for one the state or the features do not allow."""
        self.library.call("umilib_protocol_ftp_ftp_client_send", self.handle, *Bytes.readable(str(command).encode("utf-8")), now)

    def transmit(self) -> bytes:
        return self.library.output("umilib_protocol_ftp_ftp_client_transmit", self.handle)

    def poll_event(self) -> FTPClientEvent | None:
        return FTPClientEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional("umilib_protocol_ftp_ftp_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call("umilib_protocol_ftp_ftp_client_expire", self.handle, now)


class FTPServer(Handle):
    """An FTP server of the control connection (RFC 959): it answers NOOP, FEAT, SYST, QUIT, TYPE,
    MODE, STRU, the commands of FTPS, those out of sequence, before login, of a data address refused
    (RFC 2577) or of a feature not offered itself, and tells the caller each other command."""

    FREE = "umilib_protocol_ftp_ftp_server_free"

    @classmethod
    def new(cls, config: FTPConfig | None, server: FTPServerConfig | None, peer: str, secure: bool) -> FTPServer:
        """A server of a control connection from the host ``peer``, the only one PORT and EPRT may name."""
        server = server or FTPServerConfig.default()
        facts, features, commands = Text.array(server.mlst_facts), Text.array(server.features), Text.array(server.commands)
        return cls(Handle.create(
            "umilib_protocol_ftp_ftp_server_new", (config or FTPConfig.default()).to_structure(), server.to_structure(),
            *Text.encode(server.system), *facts[:2], *features[:2], *commands[:2], *Bytes.readable(ipaddress.ip_address(peer).packed),
            secure,
        ))  # fmt: skip

    def is_open(self) -> bool:
        return self.library.value("umilib_protocol_ftp_ftp_server_is_open", ctypes.c_bool, self.handle)

    def session(self) -> FTPSession:
        """What the session set: the login, TYPE, MODE, STRU, PROT and a REST marker."""
        library = self.library
        logged_in, mode, structure, protection, has_restart = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_bool()
        representation, restart = Buffer(), Buffer()
        library.call(
            "umilib_protocol_ftp_ftp_server_session", self.handle, ctypes.byref(logged_in), ctypes.byref(representation), ctypes.byref(mode),
            ctypes.byref(structure), ctypes.byref(protection), ctypes.byref(has_restart), ctypes.byref(restart),
        )  # fmt: skip
        return FTPSession(
            logged_in.value, library.take(representation).decode("ascii"), chr(mode.value), chr(structure.value),
            chr(protection.value), library.take_optional_text(has_restart, restart),
        )  # fmt: skip

    def features(self) -> FTPFeatures:
        """The features the server lists now in its reply to FEAT."""
        return FTPFeatures.from_reply(FTPReply.decode(self.library.output("umilib_protocol_ftp_ftp_server_features", self.handle)))

    def greet(self, reply: FTPReply, now: int) -> None:
        """Sends the greeting: 220, or 421 (RFC 959 §5.4)."""
        self.library.call("umilib_protocol_ftp_ftp_server_greet", self.handle, *Bytes.readable(reply.encode()), now)

    def wants_receive(self) -> bool:
        """Whether the server takes more input now: stop reading the connection while it is false,
        so that a peer that pipelines cannot make it hold more than ``maximum_buffered``."""
        return self.library.value("umilib_protocol_ftp_ftp_server_wants_receive", ctypes.c_bool, self.handle)

    def receive(self, data: bytes, now: int) -> None:
        self.library.call("umilib_protocol_ftp_ftp_server_receive", self.handle, *Bytes.readable(data), now)

    def reply(self, reply: FTPReply, now: int) -> None:
        """Answers the command told: a transfer with a preliminary reply (1xx) and then its final one."""
        self.library.call("umilib_protocol_ftp_ftp_server_reply", self.handle, *Bytes.readable(reply.encode()), now)

    def shutdown(self, text: str) -> None:
        """Closes the connection with 421 (RFC 959 §4.2); raises ``Syntax`` for a line break in ``text``."""
        self.library.call("umilib_protocol_ftp_ftp_server_shutdown", self.handle, *Text.encode(text))

    def transmit(self) -> bytes:
        return self.library.output("umilib_protocol_ftp_ftp_server_transmit", self.handle)

    def poll_event(self) -> FTPServerEvent | None:
        return FTPServerEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional("umilib_protocol_ftp_ftp_server_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call("umilib_protocol_ftp_ftp_server_expire", self.handle, now)
