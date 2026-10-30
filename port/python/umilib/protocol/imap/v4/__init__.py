"""IMAP4rev2 (RFC 9051), and IMAP4rev1 (RFC 3501) for clients that do not enable it, without I/O:
commands and responses, mailbox names (modified UTF-7), sequence sets, date-times, the ENVELOPE,
BODYSTRUCTURE and sections of messages, and a client and a server of one connection. Mirrors
``umilib::protocol::imap::v4``.

An :class:`IMAPClient` or :class:`IMAPServer` does no I/O: give it what arrives with ``receive``, send
what ``transmit`` returns, take its events from ``poll_event`` and call ``expire`` at
``poll_timeout``. ``now`` is nanoseconds of a monotonic clock. Commands and responses are their
logical lines (RFC 9051 §2.2: literals in them, without the last CRLF), mailbox names of UTF-8; the
client and the server write them for the session (modified UTF-7 for IMAP4rev1). The mailboxes, TLS
and the mechanisms of SASL are the caller's. Errors are :class:`IMAPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.codec.mail import MailConfig
from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds, Text

P = "umilib_protocol_imap_v4"

__all__ = [
    "IMAPBody",
    "IMAPClient",
    "IMAPClientEvent",
    "IMAPClientEventKind",
    "IMAPCommand",
    "IMAPCondition",
    "IMAPConfig",
    "IMAPDateTime",
    "IMAPEnvelope",
    "IMAPError",
    "IMAPMailbox",
    "IMAPResponse",
    "IMAPSection",
    "IMAPSequenceSet",
    "IMAPServer",
    "IMAPServerConfig",
    "IMAPServerEvent",
    "IMAPServerEventKind",
    "IMAPState",
]


class IMAPError(FFIError):
    """An error of IMAP: ``Syntax`` (text not of the grammar of RFC 9051 §9), ``TooLong``, ``State``
    (not in this state, or of a capability not announced), ``Timeout``, ``Closed`` or
    ``UnknownValue`` (a number of no condition)."""


Library.register_error("protocol.imap.v4", IMAPError)


class IMAPCondition(enum.IntEnum):
    """The condition of a status response (RFC 9051 §7.1)."""

    OK = 0
    NO = 1
    BAD = 2
    PREAUTH = 3
    BYE = 4


class IMAPState(enum.IntEnum):
    """The state of a session (RFC 9051 §3)."""

    NOT_AUTHENTICATED = 0
    AUTHENTICATED = 1
    SELECTED = 2
    LOGOUT = 3


@dataclasses.dataclass(frozen=True)
class IMAPCommand:
    """A command (RFC 9051 §6): its logical line as this library writes it, its tag and its name (in
    upper case; ``UID`` and the command after it for one of UIDs)."""

    line: bytes
    tag: str
    name: str

    @classmethod
    def parse(cls, line: bytes | str) -> IMAPCommand:
        """The command of a logical line, a tag and a command; raises ``Syntax``."""
        data = line.encode("utf-8") if isinstance(line, str) else line
        tag, name, out = Buffer(), Buffer(), Buffer()
        Library.default().call(f"{P}_imap_command_normalize", *Bytes.readable(data), ctypes.byref(tag), ctypes.byref(name), ctypes.byref(out))
        library = Library.default()
        tag_text, name_text = library.take(tag).decode("utf-8"), library.take(name).decode("utf-8")
        return cls(library.take(out), tag_text, name_text)

    @property
    def body(self) -> bytes:
        """The command without its tag, as :meth:`IMAPClient.send` takes it."""
        return self.line[len(self.tag) + 1 :]

    def __str__(self) -> str:
        return self.line.decode("utf-8", "replace")


@dataclasses.dataclass(frozen=True)
class IMAPResponse:
    """A response (RFC 9051 §7): its logical line as this library writes it."""

    line: bytes

    @classmethod
    def parse(cls, line: bytes | str) -> IMAPResponse:
        data = line.encode("utf-8") if isinstance(line, str) else line
        return cls(Library.default().output(f"{P}_imap_response_normalize", *Bytes.readable(data)))

    @classmethod
    def tagged(cls, tag: str, condition: IMAPCondition, code: str | None, text: str) -> IMAPResponse:
        """The tagged status response of ``tag`` (OK, NO or BAD), its code with its brackets."""
        return cls(Library.default().output(
            f"{P}_imap_response_status_encode", *Text.encode(tag), int(condition), *Text.encode(code or ""), *Text.encode(text),
        ))  # fmt: skip

    @classmethod
    def untagged(cls, condition: IMAPCondition, code: str | None, text: str) -> IMAPResponse:
        return cls(Library.default().output(
            f"{P}_imap_response_status_encode", None, 0, int(condition), *Text.encode(code or ""), *Text.encode(text),
        ))  # fmt: skip

    def status(self) -> tuple[str | None, IMAPCondition, str | None, str] | None:
        """The tag (``None`` if untagged), condition, code (with its brackets) and text of a status
        response; ``None`` for a response of another kind."""
        library = Library.default()
        is_status, tagged, condition = ctypes.c_bool(), ctypes.c_bool(), ctypes.c_uint8()
        tag, code, text = Buffer(), Buffer(), Buffer()
        library.call(
            f"{P}_imap_response_status", *Bytes.readable(self.line), ctypes.byref(is_status), ctypes.byref(tagged),
            ctypes.byref(tag), ctypes.byref(condition), ctypes.byref(code), ctypes.byref(text),
        )  # fmt: skip
        tag_text, code_text, text_text = (library.take(buffer).decode("utf-8") for buffer in (tag, code, text))
        if not is_status.value:
            return None
        return (tag_text if tagged.value else None), IMAPCondition(condition.value), code_text or None, text_text

    def __str__(self) -> str:
        return self.line.decode("utf-8", "replace")


class IMAPMailbox:
    """Mailbox names: modified UTF-7 of IMAP4rev1 (RFC 3501 §5.1.3)."""

    @staticmethod
    def encode_modified_utf7(text: str) -> str:
        return Library.default().output(f"{P}_imap_mailbox_encode_modified_utf7", *Text.encode(text)).decode("ascii")

    @staticmethod
    def decode_modified_utf7(name: bytes | str) -> str:
        data = name.encode("ascii") if isinstance(name, str) else name
        return Library.default().output(f"{P}_imap_mailbox_decode_modified_utf7", *Bytes.readable(data)).decode("utf-8")


@dataclasses.dataclass(frozen=True)
class IMAPSequenceSet:
    """A sequence set (RFC 9051 §9): numbers, ranges, ``*`` the highest and ``$`` the saved result."""

    text: str

    @classmethod
    def parse(cls, text: str) -> IMAPSequenceSet:
        return cls(Library.default().output(f"{P}_imap_sequence_set_normalize", *Text.encode(text)).decode("ascii"))

    def resolve(self, last: int) -> list[range]:
        """The ranges of the set when ``last`` is the highest number, in order and merged."""
        text = Library.default().output(f"{P}_imap_sequence_set_resolve", *Text.encode(self.text), last).decode("ascii")
        ranges = []
        for part in filter(None, text.split(",")):
            first, _, end = part.partition(":")
            ranges.append(range(int(first), int(end or first) + 1))
        return ranges

    def contains(self, number: int, last: int) -> bool:
        return Library.default().value(f"{P}_imap_sequence_set_contains", ctypes.c_bool, *Text.encode(self.text), number, last)

    def __str__(self) -> str:
        return self.text


@dataclasses.dataclass(frozen=True)
class IMAPDateTime:
    """A date-time of RFC 9051 §9 (INTERNALDATE, APPEND): seconds since 1970 and the offset in minutes."""

    seconds: int
    offset: int = 0

    @classmethod
    def parse(cls, text: str) -> IMAPDateTime:
        """The date-time of ``text``, with its quotes: ``"17-Jul-1996 02:44:25 -0700"``."""
        seconds, offset = ctypes.c_int64(), ctypes.c_int16()
        Library.default().call(f"{P}_imap_date_time_parse", *Text.encode(text), ctypes.byref(seconds), ctypes.byref(offset))
        return cls(seconds.value, offset.value)

    def __str__(self) -> str:
        return Library.default().output(f"{P}_imap_date_time_format", self.seconds, self.offset).decode("ascii")


class IMAPEnvelope:
    """The ENVELOPE of a message (RFC 9051 §7.5.2), as its text in a FETCH response."""

    @staticmethod
    def of_message(message: bytes, config: MailConfig | None = None) -> bytes:
        return Library.default().output(f"{P}_imap_envelope_of_message", *Bytes.readable(message), (config or MailConfig()).to_structure())


class IMAPBody:
    """The BODYSTRUCTURE of a message (RFC 9051 §7.5.2), as its text in a FETCH response."""

    @staticmethod
    def of_message(message: bytes, config: MailConfig | None = None, extensible: bool = True) -> bytes:
        """With extension data (BODYSTRUCTURE) if ``extensible``, without it (BODY) otherwise."""
        return Library.default().output(f"{P}_imap_body_of_message", *Bytes.readable(message), (config or MailConfig()).to_structure(), extensible)


@dataclasses.dataclass(frozen=True)
class IMAPSection:
    """A section of BODY[...] (RFC 9051 §6.4.5), with its brackets: ``[1.HEADER]``, ``[TEXT]``."""

    text: str

    def extract(self, message: bytes, config: MailConfig | None = None) -> bytes | None:
        """The octets of the section of ``message``; ``None`` if it has none."""
        return Library.default().optional(
            f"{P}_imap_section_extract", Buffer, *Text.encode(self.text), *Bytes.readable(message), (config or MailConfig()).to_structure(),
        )  # fmt: skip


@dataclasses.dataclass
class IMAPConfig:
    """The limits and times of a connection; the autologout timer is at least 30 minutes (RFC 9051 §5.4)."""

    maximum_line: int
    maximum_literal: int
    maximum_command: int
    maximum_depth: int
    maximum_buffered: int
    command_timeout: datetime.timedelta
    autologout: datetime.timedelta
    login_timeout: datetime.timedelta
    #: Whether a client sends a password as it is (LOGIN, AUTHENTICATE PLAIN or LOGIN) only under TLS.
    passwords_require_tls: bool

    C_TYPE: ClassVar[str] = f"{P}_IMAPConfig"
    DURATIONS: ClassVar[tuple[str, ...]] = ("command_timeout", "autologout", "login_timeout")

    @classmethod
    def default(cls) -> IMAPConfig:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_imap_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> IMAPConfig:
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
class IMAPServerConfig:
    """What a server offers and requires: IMAP4rev1 beside IMAP4rev2, STARTTLS, the SASL mechanisms
    (and those besides PLAIN that send a password, taken only under TLS with LOGIN if
    ``passwords_require_tls``), LITERAL+, other capabilities, and the commands of extensions told to
    the caller instead of answered BAD."""

    rev1: bool
    starttls: bool
    auth_mechanisms: list[str]
    plaintext_mechanisms: list[str]
    passwords_require_tls: bool
    literal_plus: bool
    capabilities: list[str]
    commands: list[str]

    C_TYPE: ClassVar[str] = f"{P}_IMAPServerConfig"
    LISTS: ClassVar[tuple[str, ...]] = ("auth_mechanisms", "plaintext_mechanisms", "capabilities", "commands")

    @classmethod
    def default(cls) -> IMAPServerConfig:
        structure = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_imap_server_config_default", ctypes.byref(structure))
        values = {field.name: getattr(structure, field.name) for field in dataclasses.fields(cls) if field.name not in cls.LISTS}
        return cls(auth_mechanisms=[], plaintext_mechanisms=[], capabilities=[], commands=[], **values)

    def to_structure(self) -> Any:
        structure = Library.default().type(self.C_TYPE)()
        for field in dataclasses.fields(self):
            if field.name not in self.LISTS:
                Fields.assign(structure, field.name, getattr(self, field.name))
        return structure


class IMAPClientEventKind(enum.IntEnum):
    GREETING = 0
    UNTAGGED = 1
    COMPLETED = 2
    AUTHENTICATE_CHALLENGE = 3
    IDLING = 4
    START_TLS = 5
    CLOSED = 6


class IMAPServerEventKind(enum.IntEnum):
    COMMAND = 0
    AUTHENTICATE_RESPONSE = 1
    AUTHENTICATE_CANCELLED = 2
    IDLE_DONE = 3
    START_TLS = 4
    CLOSED = 5


@dataclasses.dataclass
class IMAPClientEvent:
    """An event of a client: the greeting or an untagged ``response``; a ``command`` completed by its
    tagged ``response``; a challenge of AUTHENTICATE (``tag``, ``data``); IDLE accepted (``tag``); the
    start of TLS; or the close (``error`` if it failed)."""

    kind: IMAPClientEventKind
    tag: str = ""
    command: IMAPCommand | None = None
    response: IMAPResponse | None = None
    data: bytes = b""
    error: IMAPError | None = None

    @classmethod
    def poll(cls, client: IMAPClient) -> IMAPClientEvent | None:
        """The next event of ``client``, or ``None``."""
        library = Library.default()
        found, kind, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p()
        tag, command, response, data = Buffer(), Buffer(), Buffer(), Buffer()
        library.call(
            f"{P}_imap_client_poll_event", client.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(tag),
            ctypes.byref(command), ctypes.byref(response), ctypes.byref(data), ctypes.byref(error),
        )  # fmt: skip
        tag_text = library.take(tag).decode("utf-8")
        line, wire, data_bytes = library.take(command), library.take(response), library.take(data)
        if not found.value:
            return None
        return cls(
            IMAPClientEventKind(kind.value), tag_text, IMAPCommand.parse(line) if line else None,
            IMAPResponse(wire) if wire else None, data_bytes, library.error(error.value),
        )  # fmt: skip


@dataclasses.dataclass
class IMAPServerEvent:
    """An event of a server: a ``command`` to respond to and complete; a response of AUTHENTICATE
    (``tag``, ``data``); its cancel or the end of IDLE (``tag``); the start of TLS; or the close
    (``error`` if it failed)."""

    kind: IMAPServerEventKind
    tag: str = ""
    command: IMAPCommand | None = None
    data: bytes = b""
    error: IMAPError | None = None

    @classmethod
    def poll(cls, server: IMAPServer) -> IMAPServerEvent | None:
        """The next event of ``server``, or ``None``."""
        library = Library.default()
        found, kind, error = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_void_p()
        tag, command, response, data = Buffer(), Buffer(), Buffer(), Buffer()
        library.call(
            f"{P}_imap_server_poll_event", server.handle, ctypes.byref(found), ctypes.byref(kind), ctypes.byref(tag),
            ctypes.byref(command), ctypes.byref(response), ctypes.byref(data), ctypes.byref(error),
        )  # fmt: skip
        tag_text = library.take(tag).decode("utf-8")
        line, _, data_bytes = library.take(command), library.take(response), library.take(data)
        if not found.value:
            return None
        return cls(IMAPServerEventKind(kind.value), tag_text, IMAPCommand.parse(line) if line else None, data_bytes, library.error(error.value))


class IMAPClient(Handle):
    """An IMAP client of one connection (RFC 9051): commands checked against the state and the
    capabilities, literals sent as the server takes them (RFC 7888), pipelined where the order of
    results cannot change (§5.5), and each tagged response paired with its command."""

    FREE = f"{P}_imap_client_free"

    @classmethod
    def new(cls, config: IMAPConfig | None, secure: bool, prefix: str, now: int) -> IMAPClient:
        """A client of a new connection, ``secure`` if it is TLS from its start (RFC 8314); its tags
        ``prefix`` and a number."""
        return cls(Handle.create(f"{P}_imap_client_new", (config or IMAPConfig.default()).to_structure(), secure, *Text.encode(prefix), now))

    @property
    def state(self) -> IMAPState:
        return IMAPState(self.library.value(f"{P}_imap_client_state", ctypes.c_uint8, self.handle))

    def is_open(self) -> bool:
        return self.library.value(f"{P}_imap_client_is_open", ctypes.c_bool, self.handle)

    def has_capability(self, capability: str) -> bool:
        return self.library.value(f"{P}_imap_client_has_capability", ctypes.c_bool, self.handle, *Text.encode(capability))

    def learn_capabilities(self, capabilities: list[str]) -> None:
        """Takes ``capabilities`` as those the server announced."""
        array = Text.array(capabilities)
        self.library.call(f"{P}_imap_client_learn_capabilities", self.handle, *array[:2])

    def receive(self, data: bytes, now: int) -> None:
        self.library.call(f"{P}_imap_client_receive", self.handle, *Bytes.readable(data), now)

    def send(self, body: bytes | str, now: int) -> str:
        """Queues the command ``body`` (without a tag) and returns its tag; raises ``State`` for one
        the state or the capabilities do not allow."""
        data = body.encode("utf-8") if isinstance(body, str) else body
        return self.library.output(f"{P}_imap_client_send", self.handle, *Bytes.readable(data), now).decode("utf-8")

    def send_with_tag(self, tag: str, body: bytes | str, now: int) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.library.call(f"{P}_imap_client_send_with_tag", self.handle, *Text.encode(tag), *Bytes.readable(data), now)

    def authenticate_respond(self, response: bytes, now: int) -> None:
        self.library.call(f"{P}_imap_client_authenticate_respond", self.handle, *Bytes.readable(response), now)

    def authenticate_cancel(self, now: int) -> None:
        self.library.call(f"{P}_imap_client_authenticate_cancel", self.handle, now)

    def idle_done(self, now: int) -> None:
        self.library.call(f"{P}_imap_client_idle_done", self.handle, now)

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_imap_client_transmit", self.handle)

    def poll_event(self) -> IMAPClientEvent | None:
        return IMAPClientEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_imap_client_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call(f"{P}_imap_client_expire", self.handle, now)


class IMAPServer(Handle):
    """An IMAP server of one connection (RFC 9051): it answers CAPABILITY, LOGOUT, ENABLE, commands of
    another state, LOGIN and plaintext mechanisms without TLS where passwords need it, and literals
    too large itself, and tells the caller each other command, one at a time."""

    FREE = f"{P}_imap_server_free"

    @classmethod
    def new(cls, config: IMAPConfig | None, server: IMAPServerConfig | None, secure: bool) -> IMAPServer:
        server = server or IMAPServerConfig.default()
        arrays = [Text.array(getattr(server, name)) for name in IMAPServerConfig.LISTS]
        arguments = [argument for array in arrays for argument in array[:2]]
        return cls(Handle.create(f"{P}_imap_server_new", (config or IMAPConfig.default()).to_structure(), server.to_structure(), *arguments, secure))

    @property
    def state(self) -> IMAPState:
        return IMAPState(self.library.value(f"{P}_imap_server_state", ctypes.c_uint8, self.handle))

    @property
    def rev2(self) -> bool:
        """Whether IMAP4rev2 is in use: SEARCH is answered with ESEARCH then."""
        return self.library.value(f"{P}_imap_server_rev2", ctypes.c_bool, self.handle)

    def is_open(self) -> bool:
        return self.library.value(f"{P}_imap_server_is_open", ctypes.c_bool, self.handle)

    def capabilities(self) -> list[str]:
        """The capabilities the server announces now (RFC 9051 §7.2.2)."""
        return self.library.output(f"{P}_imap_server_capabilities", self.handle).decode("utf-8").split(" ")

    def passwords_taken(self) -> bool:
        return self.library.value(f"{P}_imap_server_passwords_taken", ctypes.c_bool, self.handle)

    def greet(self, condition: IMAPCondition, text: str, now: int) -> None:
        """Sends the greeting: OK, PREAUTH or BYE, with the capabilities (RFC 9051 §7.1)."""
        self.library.call(f"{P}_imap_server_greet", self.handle, int(condition), *Text.encode(text), now)

    def wants_receive(self) -> bool:
        """Whether the server takes more input now: stop reading the connection while it is false,
        so that a peer that pipelines cannot make it hold more than ``maximum_buffered``."""
        return self.library.value(f"{P}_imap_server_wants_receive", ctypes.c_bool, self.handle)

    def receive(self, data: bytes, now: int) -> None:
        self.library.call(f"{P}_imap_server_receive", self.handle, *Bytes.readable(data), now)

    def respond(self, response: IMAPResponse | bytes | str) -> None:
        """Sends an untagged response of the command told."""
        line = response.line if isinstance(response, IMAPResponse) else response
        data = line.encode("utf-8") if isinstance(line, str) else line
        self.library.call(f"{P}_imap_server_respond", self.handle, *Bytes.readable(data))

    def complete(self, condition: IMAPCondition, code: str | None, text: str, now: int) -> None:
        """Completes the command told with OK, NO or BAD, the code with its brackets (RFC 9051 §7.1)."""
        self.library.call(f"{P}_imap_server_complete", self.handle, int(condition), *Text.encode(code or ""), *Text.encode(text), now)

    def authenticate_challenge(self, challenge: bytes, now: int) -> None:
        self.library.call(f"{P}_imap_server_authenticate_challenge", self.handle, *Bytes.readable(challenge), now)

    def idle(self, text: str, now: int) -> None:
        """Accepts the IDLE told with a continuation request (RFC 9051 §6.3.13)."""
        self.library.call(f"{P}_imap_server_idle", self.handle, *Text.encode(text), now)

    def shutdown(self, text: str) -> None:
        """Closes the connection with an untagged BYE (RFC 9051 §7.1.5)."""
        self.library.call(f"{P}_imap_server_shutdown", self.handle, *Text.encode(text))

    def transmit(self) -> bytes:
        return self.library.output(f"{P}_imap_server_transmit", self.handle)

    def poll_event(self) -> IMAPServerEvent | None:
        return IMAPServerEvent.poll(self)

    def poll_timeout(self) -> int | None:
        return self.library.optional(f"{P}_imap_server_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        self.library.call(f"{P}_imap_server_expire", self.handle, now)
