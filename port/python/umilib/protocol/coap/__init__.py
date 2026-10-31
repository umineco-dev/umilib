"""CoAP, the Constrained Application Protocol over UDP (RFC 7252): its messages, with the extended
tokens of RFC 8974, and options; an endpoint of the message layer and of requests and responses;
observation (RFC 7641); block-wise transfers (RFC 7959); the CoRE Link Format of resource discovery
(RFC 6690); and the rule of a router by path. Mirrors ``umilib::protocol::coap``.

A :class:`CoAPEndpoint` does no I/O: give it each datagram that arrives with
:meth:`CoAPEndpoint.receive`, send what :meth:`CoAPEndpoint.transmit` returns until it returns
``None``, and call :meth:`CoAPEndpoint.expire` at :meth:`CoAPEndpoint.poll_timeout`. ``now`` is
nanoseconds of a monotonic clock. The methods that draw randomness (Message IDs, tokens, the timeouts
of retransmission) take a generator of :mod:`umilib.crypto.random`, as ``random``. Errors are
:class:`CoAPError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import enum
from typing import Any, ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Fields, Handle, Library, Nanoseconds, Text
from umilib.protocol.ip import IPEndpoint


__all__ = [
    "CoAPBlock",
    "CoAPBlockwise",
    "CoAPCode",
    "CoAPConfig",
    "CoAPContentFormat",
    "CoAPEndpoint",
    "CoAPError",
    "CoAPEvent",
    "CoAPEventKind",
    "CoAPLink",
    "CoAPLinks",
    "CoAPMessage",
    "CoAPObserver",
    "CoAPObservers",
    "CoAPOptionDefinition",
    "CoAPOptionFormat",
    "CoAPOptionNumber",
    "CoAPOptions",
    "CoAPRule",
    "CoAPTransmission",
    "CoAPType",
]


class CoAPError(FFIError):
    """An error of CoAP: ``Malformed`` (a message format error), ``Option`` (an option of a value its
    definition does not allow), ``TooLarge``, ``State`` (not possible now), ``Config`` (a
    configuration that cannot work) or ``Random`` (the source of randomness failed)."""


Library.register_error("protocol.coap", CoAPError)


class CoAPType(enum.IntEnum):
    """The type of a message (RFC 7252 §3, §4), of the value of its two bits."""

    CONFIRMABLE = 0
    NON_CONFIRMABLE = 1
    ACKNOWLEDGEMENT = 2
    RESET = 3

    @classmethod
    def from_bits(cls, bits: int) -> CoAPType:
        return cls(bits & 3)

    def bits(self) -> int:
        return int(self)


class CoAPCode(int):
    """The code of a message (RFC 7252 §3, §12.1): a class of 3 bits and a detail of 5, written c.dd."""

    EMPTY: ClassVar[CoAPCode]
    GET: ClassVar[CoAPCode]
    POST: ClassVar[CoAPCode]
    PUT: ClassVar[CoAPCode]
    DELETE: ClassVar[CoAPCode]
    FETCH: ClassVar[CoAPCode]
    PATCH: ClassVar[CoAPCode]
    IPATCH: ClassVar[CoAPCode]
    CREATED: ClassVar[CoAPCode]
    DELETED: ClassVar[CoAPCode]
    VALID: ClassVar[CoAPCode]
    CHANGED: ClassVar[CoAPCode]
    CONTENT: ClassVar[CoAPCode]
    CONTINUE: ClassVar[CoAPCode]
    BAD_REQUEST: ClassVar[CoAPCode]
    UNAUTHORIZED: ClassVar[CoAPCode]
    BAD_OPTION: ClassVar[CoAPCode]
    FORBIDDEN: ClassVar[CoAPCode]
    NOT_FOUND: ClassVar[CoAPCode]
    METHOD_NOT_ALLOWED: ClassVar[CoAPCode]
    NOT_ACCEPTABLE: ClassVar[CoAPCode]
    REQUEST_ENTITY_INCOMPLETE: ClassVar[CoAPCode]
    CONFLICT: ClassVar[CoAPCode]
    PRECONDITION_FAILED: ClassVar[CoAPCode]
    REQUEST_ENTITY_TOO_LARGE: ClassVar[CoAPCode]
    UNSUPPORTED_CONTENT_FORMAT: ClassVar[CoAPCode]
    UNPROCESSABLE_ENTITY: ClassVar[CoAPCode]
    INTERNAL_SERVER_ERROR: ClassVar[CoAPCode]
    NOT_IMPLEMENTED: ClassVar[CoAPCode]
    BAD_GATEWAY: ClassVar[CoAPCode]
    SERVICE_UNAVAILABLE: ClassVar[CoAPCode]
    GATEWAY_TIMEOUT: ClassVar[CoAPCode]
    PROXYING_NOT_SUPPORTED: ClassVar[CoAPCode]

    @classmethod
    def new(cls, class_: int, detail: int) -> CoAPCode:
        return cls((class_ & 7) << 5 | (detail & 31))

    def class_(self) -> int:
        """The class, the first 3 bits (``class`` is a keyword of Python)."""
        return int(self) >> 5

    def detail(self) -> int:
        return int(self) & 31

    def is_empty(self) -> bool:
        return int(self) == 0

    def is_request(self) -> bool:
        """A request: of class 0 but not empty (RFC 7252 §12.1.1)."""
        return self.class_() == 0 and not self.is_empty()

    def is_response(self) -> bool:
        """A response: of class 2, 4 or 5 (RFC 7252 §12.1.2)."""
        return self.class_() in (2, 4, 5)

    def __str__(self) -> str:
        return f"{self.class_()}.{self.detail():02}"

    def __repr__(self) -> str:
        return f"CoAPCode({self})"


CoAPCode.EMPTY = CoAPCode.new(0, 0)
CoAPCode.GET = CoAPCode.new(0, 1)
CoAPCode.POST = CoAPCode.new(0, 2)
CoAPCode.PUT = CoAPCode.new(0, 3)
CoAPCode.DELETE = CoAPCode.new(0, 4)
CoAPCode.FETCH = CoAPCode.new(0, 5)
CoAPCode.PATCH = CoAPCode.new(0, 6)
CoAPCode.IPATCH = CoAPCode.new(0, 7)
CoAPCode.CREATED = CoAPCode.new(2, 1)
CoAPCode.DELETED = CoAPCode.new(2, 2)
CoAPCode.VALID = CoAPCode.new(2, 3)
CoAPCode.CHANGED = CoAPCode.new(2, 4)
CoAPCode.CONTENT = CoAPCode.new(2, 5)
CoAPCode.CONTINUE = CoAPCode.new(2, 31)
CoAPCode.BAD_REQUEST = CoAPCode.new(4, 0)
CoAPCode.UNAUTHORIZED = CoAPCode.new(4, 1)
CoAPCode.BAD_OPTION = CoAPCode.new(4, 2)
CoAPCode.FORBIDDEN = CoAPCode.new(4, 3)
CoAPCode.NOT_FOUND = CoAPCode.new(4, 4)
CoAPCode.METHOD_NOT_ALLOWED = CoAPCode.new(4, 5)
CoAPCode.NOT_ACCEPTABLE = CoAPCode.new(4, 6)
CoAPCode.REQUEST_ENTITY_INCOMPLETE = CoAPCode.new(4, 8)
CoAPCode.CONFLICT = CoAPCode.new(4, 9)
CoAPCode.PRECONDITION_FAILED = CoAPCode.new(4, 12)
CoAPCode.REQUEST_ENTITY_TOO_LARGE = CoAPCode.new(4, 13)
CoAPCode.UNSUPPORTED_CONTENT_FORMAT = CoAPCode.new(4, 15)
CoAPCode.UNPROCESSABLE_ENTITY = CoAPCode.new(4, 22)
CoAPCode.INTERNAL_SERVER_ERROR = CoAPCode.new(5, 0)
CoAPCode.NOT_IMPLEMENTED = CoAPCode.new(5, 1)
CoAPCode.BAD_GATEWAY = CoAPCode.new(5, 2)
CoAPCode.SERVICE_UNAVAILABLE = CoAPCode.new(5, 3)
CoAPCode.GATEWAY_TIMEOUT = CoAPCode.new(5, 4)
CoAPCode.PROXYING_NOT_SUPPORTED = CoAPCode.new(5, 5)


class CoAPContentFormat(int):
    """A Content-Format (RFC 7252 §12.3, IANA's registry)."""

    TEXT_PLAIN: ClassVar[CoAPContentFormat]
    LINK_FORMAT: ClassVar[CoAPContentFormat]
    XML: ClassVar[CoAPContentFormat]
    OCTET_STREAM: ClassVar[CoAPContentFormat]
    EXI: ClassVar[CoAPContentFormat]
    JSON: ClassVar[CoAPContentFormat]
    CBOR: ClassVar[CoAPContentFormat]


CoAPContentFormat.TEXT_PLAIN = CoAPContentFormat(0)
CoAPContentFormat.LINK_FORMAT = CoAPContentFormat(40)
CoAPContentFormat.XML = CoAPContentFormat(41)
CoAPContentFormat.OCTET_STREAM = CoAPContentFormat(42)
CoAPContentFormat.EXI = CoAPContentFormat(47)
CoAPContentFormat.JSON = CoAPContentFormat(50)
CoAPContentFormat.CBOR = CoAPContentFormat(60)


class CoAPOptionFormat(enum.IntEnum):
    """The format of an option's value (RFC 7252 §3.2)."""

    EMPTY = 0
    OPAQUE = 1
    UINT = 2
    STRING = 3


@dataclasses.dataclass(frozen=True)
class CoAPOptionDefinition:
    """The definition of a known option (RFC 7252 table 4): its format, least and greatest length,
    and whether it may repeat."""

    format: CoAPOptionFormat
    least: int
    greatest: int
    repeatable: bool


class CoAPOptionNumber(int):
    """The number of an option (RFC 7252 §5.4, §12.2, IANA's registry)."""

    IF_MATCH: ClassVar[CoAPOptionNumber]
    URI_HOST: ClassVar[CoAPOptionNumber]
    ETAG: ClassVar[CoAPOptionNumber]
    IF_NONE_MATCH: ClassVar[CoAPOptionNumber]
    OBSERVE: ClassVar[CoAPOptionNumber]
    URI_PORT: ClassVar[CoAPOptionNumber]
    LOCATION_PATH: ClassVar[CoAPOptionNumber]
    URI_PATH: ClassVar[CoAPOptionNumber]
    CONTENT_FORMAT: ClassVar[CoAPOptionNumber]
    MAX_AGE: ClassVar[CoAPOptionNumber]
    URI_QUERY: ClassVar[CoAPOptionNumber]
    ACCEPT: ClassVar[CoAPOptionNumber]
    LOCATION_QUERY: ClassVar[CoAPOptionNumber]
    BLOCK2: ClassVar[CoAPOptionNumber]
    BLOCK1: ClassVar[CoAPOptionNumber]
    SIZE2: ClassVar[CoAPOptionNumber]
    PROXY_URI: ClassVar[CoAPOptionNumber]
    PROXY_SCHEME: ClassVar[CoAPOptionNumber]
    SIZE1: ClassVar[CoAPOptionNumber]

    def flag(self, name: str) -> bool:
        """The property ``name`` of the number (RFC 7252 §5.4.6)."""
        return Library.default().value(f"umilib_protocol_coap_coap_option_number_{name}", ctypes.c_bool, int(self))

    def is_critical(self) -> bool:
        """Critical: an endpoint that does not know it cannot ignore it (RFC 7252 §5.4.1)."""
        return self.flag("is_critical")

    def is_unsafe(self) -> bool:
        """Unsafe to forward by a proxy that does not know it (RFC 7252 §5.4.2)."""
        return self.flag("is_unsafe")

    def is_no_cache_key(self) -> bool:
        """Not part of the cache key (RFC 7252 §5.4.2, §5.4.6)."""
        return self.flag("is_no_cache_key")

    def definition(self) -> CoAPOptionDefinition | None:
        """The definition of a known option, or ``None``."""
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_coap_CoAPOptionDefinition")()
        Library.default().call("umilib_protocol_coap_coap_option_number_definition", int(self), ctypes.byref(found), ctypes.byref(structure))
        if not found.value:
            return None
        return CoAPOptionDefinition(CoAPOptionFormat(structure.format), structure.least, structure.greatest, structure.repeatable)


CoAPOptionNumber.IF_MATCH = CoAPOptionNumber(1)
CoAPOptionNumber.URI_HOST = CoAPOptionNumber(3)
CoAPOptionNumber.ETAG = CoAPOptionNumber(4)
CoAPOptionNumber.IF_NONE_MATCH = CoAPOptionNumber(5)
CoAPOptionNumber.OBSERVE = CoAPOptionNumber(6)
CoAPOptionNumber.URI_PORT = CoAPOptionNumber(7)
CoAPOptionNumber.LOCATION_PATH = CoAPOptionNumber(8)
CoAPOptionNumber.URI_PATH = CoAPOptionNumber(11)
CoAPOptionNumber.CONTENT_FORMAT = CoAPOptionNumber(12)
CoAPOptionNumber.MAX_AGE = CoAPOptionNumber(14)
CoAPOptionNumber.URI_QUERY = CoAPOptionNumber(15)
CoAPOptionNumber.ACCEPT = CoAPOptionNumber(17)
CoAPOptionNumber.LOCATION_QUERY = CoAPOptionNumber(20)
CoAPOptionNumber.BLOCK2 = CoAPOptionNumber(23)
CoAPOptionNumber.BLOCK1 = CoAPOptionNumber(27)
CoAPOptionNumber.SIZE2 = CoAPOptionNumber(28)
CoAPOptionNumber.PROXY_URI = CoAPOptionNumber(35)
CoAPOptionNumber.PROXY_SCHEME = CoAPOptionNumber(39)
CoAPOptionNumber.SIZE1 = CoAPOptionNumber(60)


@dataclasses.dataclass(frozen=True)
class CoAPBlock:
    """A Block1 or Block2 option (RFC 7959 §2.2): the block's number, whether more follow, and its size
    as SZX, 2^(SZX + 4) bytes."""

    MAXIMUM_NUMBER: ClassVar[int] = (1 << 20) - 1

    number: int
    more: bool
    exponent: int

    @classmethod
    def new(cls, number: int, more: bool, size: int) -> CoAPBlock:
        """The block of ``size`` bytes, 16 to 1024 in powers of 2; raises ``Option`` for another size
        or a number of more than 20 bits."""
        structure = Library.default().type("umilib_protocol_coap_CoAPBlock")()
        Library.default().call("umilib_protocol_coap_coap_block_new", number, more, size, ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def decode(cls, value: bytes | bytearray | memoryview) -> CoAPBlock:
        """The block of an option's value; raises ``Option`` for a value longer than 3 bytes or of the
        reserved SZX 7."""
        structure = Library.default().type("umilib_protocol_coap_CoAPBlock")()
        Library.default().call("umilib_protocol_coap_coap_block_decode", *Bytes.readable(value), ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> CoAPBlock:
        return cls(structure.number, bool(structure.more), structure.exponent)

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a field that does not fit."""
        structure = Library.default().type("umilib_protocol_coap_CoAPBlock")()
        Fields.assign(structure, "number", self.number)
        structure.more = self.more
        Fields.assign(structure, "exponent", self.exponent)
        return structure

    def encode(self) -> bytes:
        return Library.default().output("umilib_protocol_coap_coap_block_encode", self.to_structure())

    def size(self) -> int:
        return Library.default().value("umilib_protocol_coap_coap_block_size", ctypes.c_size_t, self.to_structure())

    def offset(self) -> int:
        """The offset of the block in the whole body (RFC 7959 §2.2)."""
        return Library.default().value("umilib_protocol_coap_coap_block_offset", ctypes.c_size_t, self.to_structure())

    def slice(self, body: bytes) -> tuple[bytes, bool] | None:
        """The block of ``body`` at this block's number and size and whether more follow (RFC 7959
        §2.4), or ``None`` past its end."""
        body = bytes(body)
        found, length, more = ctypes.c_bool(), ctypes.c_size_t(), ctypes.c_bool()
        Library.default().call(
            "umilib_protocol_coap_coap_block_slice", self.to_structure(), *Bytes.readable(body), ctypes.byref(found), ctypes.byref(length),
            ctypes.byref(more),
        )  # fmt: skip
        if not found.value:
            return None
        start = self.offset()
        return body[start : start + length.value], more.value


class CoAPOptions(Handle):
    """The options of a message, in the order of their numbers, repeated ones in the order given
    (RFC 7252 §3.1, §5.4.5)."""

    FREE = "umilib_protocol_coap_coap_options_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_protocol_coap_coap_options_new"))

    @classmethod
    def new(cls) -> CoAPOptions:
        return cls()

    def clone(self) -> CoAPOptions:
        return CoAPOptions(Handle.create("umilib_protocol_coap_coap_options_clone", self.handle))

    def __len__(self) -> int:
        return self.library.value("umilib_protocol_coap_coap_options_count", ctypes.c_size_t, self.handle)

    def entry(self, index: int) -> tuple[CoAPOptionNumber, bytes]:
        """The number and value of the option ``index``; raises ``InvalidArgument`` past the end."""
        number, value = ctypes.c_uint16(), Buffer()
        self.library.call("umilib_protocol_coap_coap_options_entry", self.handle, index, ctypes.byref(number), ctypes.byref(value))
        return CoAPOptionNumber(number.value), self.library.take(value)

    @property
    def entries(self) -> list[tuple[CoAPOptionNumber, bytes]]:
        return [self.entry(index) for index in range(len(self))]

    def push(self, number: int, value: bytes) -> None:
        """Adds an option after those of its number and before greater ones."""
        self.library.call("umilib_protocol_coap_coap_options_push", self.handle, number, *Bytes.readable(value))

    def set(self, number: int, value: bytes) -> None:
        """Sets the one option ``number``, replacing those there are."""
        self.library.call("umilib_protocol_coap_coap_options_set", self.handle, number, *Bytes.readable(value))

    def remove(self, number: int) -> None:
        self.library.call("umilib_protocol_coap_coap_options_remove", self.handle, number)

    def get(self, number: int) -> bytes | None:
        """The value of the first option ``number``, or ``None``."""
        return self.library.optional("umilib_protocol_coap_coap_options_get", Buffer, self.handle, number)

    def all(self, number: int) -> list[bytes]:
        """The values of the options ``number``, in their order."""
        return [value for found, value in self.entries if found == number]

    def contains(self, number: int) -> bool:
        return self.library.value("umilib_protocol_coap_coap_options_contains", ctypes.c_bool, self.handle, number)

    @staticmethod
    def uint_bytes(value: int) -> bytes:
        """The bytes of the uint ``value``, without leading zeros (RFC 7252 §3.2)."""
        return Library.default().output("umilib_protocol_coap_coap_options_uint_bytes", value)

    @staticmethod
    def uint_of(data: bytes | bytearray | memoryview) -> int | None:
        """The uint of ``data``, of at most 4 bytes (RFC 7252 §3.2), or ``None``."""
        return Library.default().optional("umilib_protocol_coap_coap_options_uint_of", ctypes.c_uint32, *Bytes.readable(data))

    def uint(self, number: int) -> int | None:
        return self.library.optional("umilib_protocol_coap_coap_options_uint", ctypes.c_uint32, self.handle, number)

    def set_uint(self, number: int, value: int) -> None:
        self.library.call("umilib_protocol_coap_coap_options_set_uint", self.handle, number, value)

    def check(self) -> CoAPOptionNumber | None:
        """The number of the first option that makes the message one to reject (RFC 7252 §5.4.1,
        §5.4.3, §5.4.5) — a critical option unknown, of a value its definition does not allow, or
        repeated though it may not be — or ``None``. Elective ones so are ignored (:meth:`usable`)."""
        number = self.library.optional("umilib_protocol_coap_coap_options_check", ctypes.c_uint16, self.handle)
        return None if number is None else CoAPOptionNumber(number)

    def usable(self) -> CoAPOptions:
        """The options without the elective ones to ignore: unknown, of a value out of their
        definition, or repeated beyond the first (RFC 7252 §5.4.1, §5.4.5)."""
        return CoAPOptions(Handle.create("umilib_protocol_coap_coap_options_usable", self.handle))

    def path(self) -> list[str]:
        """The path of the Uri-Path options (RFC 7252 §6.5), each segment as given, as text."""
        return [segment.decode("utf-8", "replace") for segment in self.all(CoAPOptionNumber.URI_PATH)]

    def queries(self) -> list[str]:
        return [query.decode("utf-8", "replace") for query in self.all(CoAPOptionNumber.URI_QUERY)]

    def set_uri(self, path: str, query: str | None = None) -> None:
        """Sets the Uri-Path options of ``path`` ("/a/b") and the Uri-Query options of ``query``
        ("x=1&y"), as RFC 7252 §6.4 splits a URI."""
        self.library.call("umilib_protocol_coap_coap_options_set_uri", self.handle, *Text.encode(path), *Text.encode(query))

    def content_format(self) -> CoAPContentFormat | None:
        value = self.library.optional("umilib_protocol_coap_coap_options_content_format", ctypes.c_uint16, self.handle)
        return None if value is None else CoAPContentFormat(value)

    def max_age(self) -> int:
        """The Max-Age in seconds: 60 without the option (RFC 7252 §5.10.5)."""
        return self.library.value("umilib_protocol_coap_coap_options_max_age", ctypes.c_uint32, self.handle)

    def observe(self) -> int | None:
        """The Observe value (RFC 7641 §2): of 24 bits."""
        return self.library.optional("umilib_protocol_coap_coap_options_observe", ctypes.c_uint32, self.handle)

    def block(self, number: int) -> CoAPBlock | None:
        """The Block1 or Block2 option ``number``, or ``None``; raises ``Option`` for one not valid."""
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_coap_CoAPBlock")()
        self.library.call("umilib_protocol_coap_coap_options_block", self.handle, number, ctypes.byref(found), ctypes.byref(structure))
        return CoAPBlock.from_structure(structure) if found.value else None

    def __repr__(self) -> str:
        return f"CoAPOptions({self.entries!r})"


class CoAPMessage(Handle):
    """A CoAP message (RFC 7252 §3): its type, code, Message ID, token (of up to 65804 bytes, RFC 8974
    §2.1), options and payload. :attr:`options` is a copy: assign it to change them."""

    FREE = "umilib_protocol_coap_coap_message_free"
    VERSION: ClassVar[int] = 1
    #: The default port of CoAP over UDP (RFC 7252 §6.1).
    PORT: ClassVar[int] = 5683
    #: The largest token (RFC 8974 §2.1).
    MAXIMUM_TOKEN: ClassVar[int] = 65804

    @classmethod
    def new(cls, kind: CoAPType, code: int, id: int) -> CoAPMessage:
        return cls(Handle.create("umilib_protocol_coap_coap_message_new", int(kind), int(code), id))

    @classmethod
    def empty(cls, kind: CoAPType, id: int) -> CoAPMessage:
        """An empty message of ``kind`` and ``id``: an ACK or a RST (RFC 7252 §4.1, §4.2)."""
        return cls(Handle.create("umilib_protocol_coap_coap_message_empty", int(kind), id))

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> CoAPMessage:
        """The message of ``data`` (RFC 7252 §3); raises ``Malformed`` for a message format error:
        another version, a token length of 15, an option of delta or length 15, a payload marker
        without payload, or an empty message with a token, options or payload (§4.1)."""
        return cls(Handle.create("umilib_protocol_coap_coap_message_decode", *Bytes.readable(data)))

    def encode(self) -> bytes:
        """The bytes of the message; raises ``TooLarge`` for a token or an option value above its largest length."""
        return self.library.output("umilib_protocol_coap_coap_message_encode", self.handle)

    @staticmethod
    def header(data: bytes | bytearray | memoryview) -> tuple[CoAPType, int] | None:
        """The type and Message ID of ``data`` if it has a header of version 1: what a message that
        cannot be read otherwise is rejected by (RFC 7252 §4.2, §4.3)."""
        found, kind, id = ctypes.c_bool(), ctypes.c_uint8(), ctypes.c_uint16()
        Library.default().call("umilib_protocol_coap_coap_message_header", *Bytes.readable(data), ctypes.byref(found), ctypes.byref(kind), ctypes.byref(id))
        return (CoAPType(kind.value), id.value) if found.value else None

    def clone(self) -> CoAPMessage:
        return CoAPMessage(Handle.create("umilib_protocol_coap_coap_message_clone", self.handle))

    @property
    def kind(self) -> CoAPType:
        return CoAPType(self.library.value("umilib_protocol_coap_coap_message_kind", ctypes.c_uint8, self.handle))

    @kind.setter
    def kind(self, kind: CoAPType) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_kind", self.handle, int(kind))

    @property
    def code(self) -> CoAPCode:
        return CoAPCode(self.library.value("umilib_protocol_coap_coap_message_code", ctypes.c_uint8, self.handle))

    @code.setter
    def code(self, code: int) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_code", self.handle, int(code))

    @property
    def id(self) -> int:
        return self.library.value("umilib_protocol_coap_coap_message_id", ctypes.c_uint16, self.handle)

    @id.setter
    def id(self, id: int) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_id", self.handle, id)

    @property
    def token(self) -> bytes:
        return self.library.output("umilib_protocol_coap_coap_message_token", self.handle)

    @token.setter
    def token(self, token: bytes) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_token", self.handle, *Bytes.readable(token))

    @property
    def options(self) -> CoAPOptions:
        """A copy of the options; assign to change them."""
        return CoAPOptions(Handle.create("umilib_protocol_coap_coap_message_options", self.handle))

    @options.setter
    def options(self, options: CoAPOptions) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_options", self.handle, options)

    @property
    def payload(self) -> bytes:
        return self.library.output("umilib_protocol_coap_coap_message_payload", self.handle)

    @payload.setter
    def payload(self, payload: bytes) -> None:
        self.library.call("umilib_protocol_coap_coap_message_set_payload", self.handle, *Bytes.readable(payload))

    def __repr__(self) -> str:
        return f"CoAPMessage({self.kind.name}, {self.code}, {self.id:#06x})"


@dataclasses.dataclass(frozen=True)
class CoAPConfig:
    """The transmission parameters (RFC 7252 §4.8) and the limits of an endpoint. The durations
    cross the C ABI in whole milliseconds; ``ack_random_factor`` is in thousandths (1500 for 1.5)."""

    ack_timeout: datetime.timedelta
    ack_random_factor: int
    max_retransmit: int
    #: The most interactions outstanding with one peer (NSTART); more wait.
    nstart: int
    #: How long a Message ID and its response are remembered (RFC 7252 §4.8.2).
    exchange_lifetime: datetime.timedelta
    non_lifetime: datetime.timedelta
    #: How long a server waits for the application's response to a Confirmable request before it
    #: acknowledges it alone and responds separately (RFC 7252 §5.2.2).
    ack_delay: datetime.timedelta
    #: The longest token taken in requests: 8 unless extended (RFC 8974 §2.2.1).
    maximum_token: int
    #: The most messages remembered to find duplicates (RFC 7252 §4.5).
    maximum_seen: int
    #: The most requests received and not yet answered or ignored; when full, a Confirmable request is
    #: answered 5.03 and a Non-confirmable one is ignored.
    maximum_incoming: int

    DURATIONS: ClassVar[tuple[str, ...]] = ("ack_timeout", "exchange_lifetime", "non_lifetime", "ack_delay")
    COUNTS: ClassVar[tuple[str, ...]] = ("ack_random_factor", "max_retransmit", "nstart", "maximum_token", "maximum_seen", "maximum_incoming")

    @classmethod
    def default(cls) -> CoAPConfig:
        structure = Library.default().type("umilib_protocol_coap_CoAPConfig")()
        Library.default().call("umilib_protocol_coap_coap_config_default", ctypes.byref(structure))
        return cls.from_structure(structure)

    @classmethod
    def from_structure(cls, structure: Any) -> CoAPConfig:
        values: dict[str, Any] = {name: datetime.timedelta(milliseconds=getattr(structure, name)) for name in cls.DURATIONS}
        values.update({name: getattr(structure, name) for name in cls.COUNTS})
        return cls(**values)

    def to_structure(self) -> Any:
        """The C structure; raises ``OverflowError`` for a field that does not fit."""
        structure = Library.default().type("umilib_protocol_coap_CoAPConfig")()
        for name in self.DURATIONS:
            Fields.assign(structure, name, Nanoseconds.from_timedelta(getattr(self, name)) // 1_000_000)
        for name in self.COUNTS:
            Fields.assign(structure, name, getattr(self, name))
        return structure


class CoAPEventKind(enum.IntEnum):
    REQUEST = 0
    RESPONSE = 1
    TIMEOUT = 2
    RESET = 3


@dataclasses.dataclass(frozen=True)
class CoAPEvent:
    """What an endpoint tells: a ``REQUEST`` from ``peer`` of the ``exchange`` to answer with
    :meth:`CoAPEndpoint.respond`; a ``RESPONSE`` to the ``request`` (or a notification of its
    observation, RFC 7641 §3.2); the ``TIMEOUT`` of a Confirmable message or of a request not answered;
    a ``RESET`` of a message by the peer (RFC 7252 §4.2). ``message`` is the message of a request or a
    response, and the handle of the message that timed out or was reset."""

    kind: CoAPEventKind
    exchange: int = 0
    request: int = 0
    message: CoAPMessage | int = 0
    peer: IPEndpoint | None = None

    def to_structure(self) -> Any:
        structure = Library.default().type("umilib_protocol_coap_CoAPEvent")()
        structure.kind = int(self.kind)
        Fields.assign(structure, "exchange", self.exchange)
        Fields.assign(structure, "request", self.request)
        Fields.assign(structure, "message", self.message if isinstance(self.message, int) else 0)
        if self.peer is not None:
            structure.peer = self.peer.to_structure()
        return structure


@dataclasses.dataclass(frozen=True)
class CoAPTransmission:
    """A datagram to send to ``peer``."""

    peer: IPEndpoint
    message: bytes


class CoAPEndpoint(Handle):
    """A CoAP endpoint over UDP (RFC 7252), client and server, without I/O: the message layer —
    Message IDs, retransmission of Confirmable messages with exponential backoff (§4.2), duplicates
    answered as before or ignored (§4.5), RST of what cannot be processed — and the matching of
    responses to requests by token (§5.3.2), piggybacked or separate (§5.2), with the notifications of
    observations (RFC 7641 §3)."""

    FREE = "umilib_protocol_coap_coap_endpoint_free"

    @classmethod
    def new(cls, config: CoAPConfig | None, random: Any) -> CoAPEndpoint:
        """An endpoint of ``config`` (the default if ``None``), its first Message ID drawn from
        ``random`` (§4.4); raises ``Config`` for a configuration that cannot work."""
        structure = (config or CoAPConfig.default()).to_structure()
        return cls(Handle.create("umilib_protocol_coap_coap_endpoint_new", ctypes.byref(structure), *random.source()))

    def request(self, peer: IPEndpoint, message: CoAPMessage, now: int, random: Any) -> int:
        """Sends the request ``message`` (Confirmable or Non-confirmable, a random token of 8 bytes if
        it has none) to ``peer``; the handle its response and notifications come with. It waits while
        NSTART interactions with the peer are outstanding (§4.7). Raises ``State`` for another message."""
        return self.library.value(
            "umilib_protocol_coap_coap_endpoint_request", ctypes.c_uint64, self.handle, ctypes.byref(peer.to_structure()), message, now,
            *random.source(),
        )  # fmt: skip

    def receive(self, peer: IPEndpoint, data: bytes, now: int, random: Any) -> None:
        """Takes the datagram ``data`` from ``peer``."""
        self.library.call("umilib_protocol_coap_coap_endpoint_receive", self.handle, ctypes.byref(peer.to_structure()), *Bytes.readable(data), now, *random.source())

    def respond(self, exchange: int, response: CoAPMessage, now: int, random: Any) -> None:
        """Answers the request ``exchange`` with the code, options and payload of ``response``:
        piggybacked in the ACK of a Confirmable request not yet acknowledged (§5.2.1), else separately,
        Confirmable for a Confirmable request (§5.2.2), Non-confirmable for a Non-confirmable one.
        Raises ``State`` for an exchange not awaiting its answer."""
        self.library.call("umilib_protocol_coap_coap_endpoint_respond", self.handle, exchange, response, now, *random.source())

    def ignore(self, exchange: int) -> None:
        """Does not answer the request ``exchange`` (RFC 7967, or a multicast request, RFC 7252 §8.2): it is
        forgotten, and a Confirmable request not yet acknowledged is acknowledged by an empty ACK. Raises
        ``State`` for an exchange not awaiting its answer."""
        self.library.call("umilib_protocol_coap_coap_endpoint_ignore", self.handle, exchange)

    def notify(self, peer: IPEndpoint, message: CoAPMessage, now: int, random: Any) -> int:
        """Sends the notification ``message`` of an observation to ``peer`` (RFC 7641 §4.2); its handle,
        to learn of a RST or a timeout, which end the observation (§3.6, §4.5)."""
        return self.library.value(
            "umilib_protocol_coap_coap_endpoint_notify", ctypes.c_uint64, self.handle, ctypes.byref(peer.to_structure()), message, now,
            *random.source(),
        )  # fmt: skip

    def cancel(self, handle: int, now: int) -> None:
        """Stops awaiting the request ``handle`` at ``now``: its observation forgotten, so that
        notifications are rejected (RFC 7641 §3.6), and what waited for it may go."""
        self.library.call("umilib_protocol_coap_coap_endpoint_cancel", self.handle, handle, now)

    def poll_timeout(self) -> int | None:
        """When :meth:`expire` is next due, in nanoseconds."""
        return self.library.optional("umilib_protocol_coap_coap_endpoint_poll_timeout", ctypes.c_uint64, self.handle)

    def expire(self, now: int) -> None:
        """Does what is due at ``now``: retransmissions, the end of what is not answered, the empty ACK
        of a request not yet answered (RFC 7252 §4.2, §5.2.2)."""
        self.library.call("umilib_protocol_coap_coap_endpoint_expire", self.handle, now)

    def transmit(self) -> CoAPTransmission | None:
        """The next datagram to send, or ``None``."""
        found = ctypes.c_bool()
        peer = Library.default().type("umilib_protocol_ip_IPEndpoint")()
        buffer = Buffer()
        self.library.call("umilib_protocol_coap_coap_endpoint_transmit", self.handle, ctypes.byref(found), ctypes.byref(peer), ctypes.byref(buffer))
        data = self.library.take(buffer)
        return CoAPTransmission(IPEndpoint.from_structure(peer), data) if found.value else None

    def poll_event(self) -> CoAPEvent | None:
        found = ctypes.c_bool()
        structure = Library.default().type("umilib_protocol_coap_CoAPEvent")()
        message = ctypes.c_void_p()
        self.library.call("umilib_protocol_coap_coap_endpoint_poll_event", self.handle, ctypes.byref(found), ctypes.byref(structure), ctypes.byref(message))
        if not found.value:
            return None
        kind = CoAPEventKind(structure.kind)
        return CoAPEvent(
            kind=kind,
            exchange=structure.exchange,
            request=structure.request,
            message=CoAPMessage(message.value) if message.value else structure.message,
            peer=IPEndpoint.from_structure(structure.peer) if kind == CoAPEventKind.REQUEST else None,
        )

    @staticmethod
    def is_fresher(freshest: int, at: int, value: int, now: int) -> bool:
        """Whether a notification of Observe ``value`` received at ``now`` was sent after the freshest
        one, of ``freshest`` received at ``at`` (RFC 7641 §3.4)."""
        return Library.default().value("umilib_protocol_coap_coap_endpoint_is_fresher", ctypes.c_bool, freshest, at, value, now)


@dataclasses.dataclass(frozen=True)
class CoAPObserver:
    """A client observing a resource (RFC 7641 §4.1): where it is and its token."""

    peer: IPEndpoint
    token: bytes


class CoAPObservers(Handle):
    """The observers of a server's resources (RFC 7641 §4): they register with GET and Observe 0,
    deregister with Observe 1 (§3.6) or by rejecting a notification (RST), and are dropped when a
    Confirmable notification times out (§4.5) or after a notification of an error (§4.2).

    :meth:`handle` is the method of the Rust type, so the object itself, not ``.handle``, is what the
    C functions take."""

    FREE = "umilib_protocol_coap_coap_observers_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_protocol_coap_coap_observers_new"))

    @property
    def confirm_interval(self) -> datetime.timedelta:
        """A notification at least this often is Confirmable (RFC 7641 §4.5: 24 hours)."""
        milliseconds = self.library.value("umilib_protocol_coap_coap_observers_confirm_interval", ctypes.c_uint64, self)
        return datetime.timedelta(milliseconds=milliseconds)

    @confirm_interval.setter
    def confirm_interval(self, interval: datetime.timedelta) -> None:
        self.library.call("umilib_protocol_coap_coap_observers_set_confirm_interval", self, Nanoseconds.from_timedelta(interval) // 1_000_000)

    @property
    def maximum(self) -> int:
        """The most observers kept."""
        return self.library.value("umilib_protocol_coap_coap_observers_maximum", ctypes.c_size_t, self)

    @maximum.setter
    def maximum(self, maximum: int) -> None:
        self.library.call("umilib_protocol_coap_coap_observers_set_maximum", self, maximum)

    def __len__(self) -> int:
        return self.library.value("umilib_protocol_coap_coap_observers_count", ctypes.c_size_t, self)

    def observer(self, index: int) -> CoAPObserver:
        peer, token = Library.default().type("umilib_protocol_ip_IPEndpoint")(), Buffer()
        self.library.call("umilib_protocol_coap_coap_observers_observer", self, index, ctypes.byref(peer), ctypes.byref(token))
        return CoAPObserver(IPEndpoint.from_structure(peer), self.library.take(token))

    @property
    def observers(self) -> list[CoAPObserver]:
        return [self.observer(index) for index in range(len(self))]

    def register(self, peer: IPEndpoint, request: CoAPMessage, now: int) -> bool:
        """Takes the GET or FETCH ``request`` of ``peer``: with Observe 0 the client observes the
        resource (§4.1); with Observe 1 it stops (§3.6). Whether the response is to carry Observe
        (:meth:`next_value`)."""
        return self.library.value("umilib_protocol_coap_coap_observers_register", ctypes.c_bool, self, ctypes.byref(peer.to_structure()), request, now)

    def next_value(self) -> int:
        """The next Observe value, of 24 bits, strictly increasing (§4.4)."""
        return self.library.value("umilib_protocol_coap_coap_observers_next_value", ctypes.c_uint32, self)

    def notify(self, endpoint: CoAPEndpoint, path: list[str], response: CoAPMessage, confirmable: bool, now: int, random: Any) -> None:
        """Sends the state of the resource at ``path`` (its segments) to its observers through
        ``endpoint`` (§4.2): ``response`` with each one's token and the next Observe value, Confirmable
        if ``confirmable`` or if the observer has not had a Confirmable one for the interval. A response
        of another class than 2 has no Observe, and ends the observations."""
        segments, count, _kept = Text.array(path)
        self.library.call("umilib_protocol_coap_coap_observers_notify", self, endpoint, segments, count, response, confirmable, now, *random.source())

    def handle(self, event: CoAPEvent) -> bool:
        """Takes an event of the endpoint: a notification rejected or not acknowledged ends its
        observation (§3.6, §4.5). Whether it was one."""
        return self.library.value("umilib_protocol_coap_coap_observers_handle", ctypes.c_bool, self, ctypes.byref(event.to_structure()))


class CoAPBlockwise(Handle):
    """The block-wise transfer of a body (RFC 7959): what a server gives of a body block by block
    (:meth:`respond`), and what a receiver puts together."""

    FREE = "umilib_protocol_coap_coap_blockwise_free"

    @classmethod
    def new(cls, maximum: int) -> CoAPBlockwise:
        """A receiver of a body of at most ``maximum`` bytes."""
        return cls(Handle.create("umilib_protocol_coap_coap_blockwise_new", maximum))

    @staticmethod
    def respond(request: CoAPMessage, body: bytes, size: int, response: CoAPMessage) -> None:
        """Sets the block of ``body`` that ``request`` asks for in its Block2 (its number, at most the
        size ``size``), or the first, as ``response``'s payload with its Block2 option, if the body is
        larger than a block or a block was asked for (§2.4); and Size2 if the request has it (§4).
        Raises ``Option`` for a block past the end, which is 4.02 (§2.4)."""
        Library.default().call("umilib_protocol_coap_coap_blockwise_respond", request, *Bytes.readable(body), size, response)

    def receive(self, block: CoAPBlock, payload: bytes, etag: bytes | None = None) -> bool:
        """Takes the block ``block`` of ``payload``, of the message's ETag: in order, each but the last
        of the full size and of the same ETag (§2.4, §2.5). Whether the body is whole."""
        # An ETag of no bytes is a non-null pointer; no ETag is null.
        etag_data, etag_length = (bytes(etag), len(etag)) if etag is not None else (None, 0)
        return self.library.value(
            "umilib_protocol_coap_coap_blockwise_receive", ctypes.c_bool, self.handle, block.to_structure(), *Bytes.readable(payload), etag_data,
            etag_length,
        )  # fmt: skip

    def next_request(self, options: CoAPOptions, size: int) -> CoAPOptions:
        """The options of the request for the next block: ``options`` with Block2 of the next number
        and ``size``, without Observe (§2.4)."""
        return CoAPOptions(Handle.create("umilib_protocol_coap_coap_blockwise_next_request", self.handle, options, size))

    @property
    def body(self) -> bytes:
        """The body received so far."""
        return self.library.output("umilib_protocol_coap_coap_blockwise_body", self.handle)


class CoAPLink(Handle):
    """A link of the CoRE Link Format (RFC 6690 §2): its target and its attributes, each with a value
    or none."""

    FREE = "umilib_protocol_coap_coap_link_free"
    #: The path of resource discovery (RFC 6690 §4).
    WELL_KNOWN_CORE: ClassVar[str] = "/.well-known/core"

    @classmethod
    def new(cls, target: str) -> CoAPLink:
        return cls(Handle.create("umilib_protocol_coap_coap_link_new", *Text.encode(target)))

    def clone(self) -> CoAPLink:
        return CoAPLink(Handle.create("umilib_protocol_coap_coap_link_clone", self.handle))

    def with_(self, name: str, value: str | None = None) -> CoAPLink:
        """Adds the attribute ``name`` of ``value`` (none if ``None``) and returns the link (``with``
        is a keyword of Python)."""
        self.library.call("umilib_protocol_coap_coap_link_with", self.handle, *Text.encode(name), *Text.encode(value))
        return self

    @property
    def target(self) -> str:
        return self.library.output("umilib_protocol_coap_coap_link_target", self.handle).decode("utf-8")

    def lookup(self, name: str) -> tuple[bool, str | None]:
        """Whether the link has an attribute ``name`` (in any case), and the value of the first."""
        found, has_value, buffer = ctypes.c_bool(), ctypes.c_bool(), Buffer()
        self.library.call(
            "umilib_protocol_coap_coap_link_attribute", self.handle, *Text.encode(name), ctypes.byref(found), ctypes.byref(has_value),
            ctypes.byref(buffer),
        )  # fmt: skip
        value = self.library.take(buffer).decode("utf-8")
        return found.value, value if has_value.value else None

    def attribute(self, name: str) -> str | None:
        """The value of the first attribute ``name`` (in any case): ``None`` if there is none or it has
        no value; :meth:`has_attribute` tells which."""
        return self.lookup(name)[1]

    def has_attribute(self, name: str) -> bool:
        return self.lookup(name)[0]

    @property
    def attributes(self) -> list[tuple[str, str | None]]:
        count = self.library.value("umilib_protocol_coap_coap_link_attribute_count", ctypes.c_size_t, self.handle)
        attributes = []
        for index in range(count):
            name, has_value, value = Buffer(), ctypes.c_bool(), Buffer()
            self.library.call(
                "umilib_protocol_coap_coap_link_attribute_entry", self.handle, index, ctypes.byref(name), ctypes.byref(has_value), ctypes.byref(value),
            )  # fmt: skip
            text = self.library.take(value).decode("utf-8")
            attributes.append((self.library.take(name).decode("utf-8"), text if has_value.value else None))
        return attributes

    @staticmethod
    def parse(text: str) -> list[CoAPLink]:
        """The links of ``text`` (RFC 6690 §2): "<target>;name=value;name=\\"quoted\\",..."; raises
        ``Malformed`` for text not of the link format."""
        with CoAPLinks(Handle.create("umilib_protocol_coap_coap_link_parse", *Text.encode(text))) as links:
            return links.links()

    @staticmethod
    def format(links: list[CoAPLink]) -> str:
        """The text of ``links`` (RFC 6690 §2): values quoted unless they are tokens."""
        with CoAPLinks.of(links) as made:
            return Library.default().output("umilib_protocol_coap_coap_link_format", made).decode("utf-8")

    def __repr__(self) -> str:
        return f"CoAPLink({self.target!r}, {self.attributes!r})"


class CoAPLinks(Handle):
    """A list of :class:`CoAPLink`, as the C ABI parses and formats them."""

    FREE = "umilib_protocol_coap_coap_links_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create("umilib_protocol_coap_coap_links_new"))

    @classmethod
    def of(cls, links: list[CoAPLink]) -> CoAPLinks:
        made = cls()
        for link in links:
            made.push(link)
        return made

    def push(self, link: CoAPLink) -> None:
        """Appends a copy of ``link``."""
        self.library.call("umilib_protocol_coap_coap_links_push", self.handle, link)

    def __len__(self) -> int:
        return self.library.value("umilib_protocol_coap_coap_links_count", ctypes.c_size_t, self.handle)

    def get(self, index: int) -> CoAPLink:
        """A copy of the link ``index``; raises ``InvalidArgument`` past the end."""
        return CoAPLink(Handle.create("umilib_protocol_coap_coap_links_get", self.handle, index))

    def links(self) -> list[CoAPLink]:
        return [self.get(index) for index in range(len(self))]


class CoAPRule(Handle):
    """The rule of a router that routes CoAP requests by their path (its Uri-Path options, the rule's
    segments first) and, if given, their method."""

    FREE = "umilib_protocol_coap_coap_rule_free"

    @classmethod
    def new(cls, path: str) -> CoAPRule:
        """The requests of paths at or below ``path`` ("/sensors/temp")."""
        return cls(Handle.create("umilib_protocol_coap_coap_rule_new", *Text.encode(path)))

    def with_method(self, method: int) -> CoAPRule:
        """Limits the rule to the requests of ``method`` and returns it."""
        self.library.call("umilib_protocol_coap_coap_rule_with_method", self.handle, int(method))
        return self

    def matches(self, message: CoAPMessage) -> bool:
        return self.library.value("umilib_protocol_coap_coap_rule_matches", ctypes.c_bool, self.handle, message)
