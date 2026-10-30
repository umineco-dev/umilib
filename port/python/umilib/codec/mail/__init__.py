"""The Internet Message Format (RFC 5322, with UTF-8 of RFC 6532) and MIME. Mirrors ``umilib::codec::mail``.

Header sections are :class:`MailFields`, messages :class:`MailMessage`; addresses, dates and message
identifiers are values (:class:`MailAddress`, :class:`MailMailbox`, :class:`MailDate`,
:class:`MailMessageID`). Media types, dispositions and parameters (:class:`MIMEContentType`,
:class:`MIMEDisposition`, :class:`MIMEParameters`, with RFC 2231), transfer encodings
(:class:`MIMETransferEncoding`, :class:`MIMEQuotedPrintable`), encoded words
(:class:`MIMEEncodedWord`, RFC 2047) and character sets (:class:`MIMECharset`) are as in Rust. The
structure of a message is a tree of :class:`MIMEEntity`, whose ranges are byte offsets in the text it
was read from. Every limit is in :class:`MailConfig`. Errors are :class:`MailError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from typing import ClassVar

from umilib.ffi import Buffer, Bytes, FFIError, Handle, Library, Structures, Text

P = "umilib_codec_mail"

__all__ = [
    "MIMECharset", "MIMEContentType", "MIMEDisposition", "MIMEEncodedWord", "MIMEEntity", "MIMEMultipart",
    "MIMEParameter", "MIMEParameters", "MIMEQuotedPrintable", "MIMETransferEncoding", "MIMEWordEncoding",
    "MailAddress", "MailAddresses", "MailConfig", "MailDate", "MailError", "MailField", "MailFields", "MailMailbox",
    "MailMessage", "MailMessageID", "MailMessageIDs",
]  # fmt: skip


class MailError(FFIError):
    """An error of a message or of MIME: ``Syntax``, ``TooLong``, ``TooMany``, ``Charset`` (a
    character set not converted), ``Encoding`` (a transfer encoding not decoded), ``Base64``,
    ``NoSuchEntry``, ``NotAGroup`` or ``UnknownValue``."""


Library.register_error("codec.mail", MailError)


@dataclasses.dataclass
class MailConfig:
    """The limits of reading messages: what RFC 5322 and MIME leave unbounded, bounded."""

    C_TYPE: ClassVar[str] = f"{P}_MailConfig"

    maximum_length: int = 64 * 1024 * 1024
    maximum_field_length: int = 64 * 1024
    maximum_fields: int = 4096
    maximum_parts: int = 4096
    maximum_depth: int = 32
    utf8: bool = True

    def to_structure(self) -> object:
        return Structures.to_structure(self)


@dataclasses.dataclass(frozen=True)
class MailDate:
    """A date-time of RFC 5322 §3.3: seconds since 1970 (UTC), the offset of its zone in minutes east,
    and whether its local time is unknown (``-0000``, and the military zones of §4.3)."""

    C_TYPE: ClassVar[str] = f"{P}_MailDate"

    seconds: int
    offset: int = 0
    zone_unknown: bool = False

    @classmethod
    def parse(cls, text: bytes) -> MailDate:
        """The date-time of ``text``, with the obsolete forms of §4.3."""
        out = Library.default().type(cls.C_TYPE)()
        Library.default().call(f"{P}_mail_date_parse", *Bytes.readable(text), ctypes.byref(out))
        return Structures.from_structure(cls, out)

    def format(self) -> str:
        """The date-time as §3.3 writes it: ``Thu, 29 Oct 2026 12:00:00 +0900``."""
        return Library.default().output(f"{P}_mail_date_format", Structures.to_structure(self)).decode("ascii")

    def __str__(self) -> str:
        return self.format()


@dataclasses.dataclass(frozen=True)
class MailMailbox:
    """A mailbox (RFC 5322 §3.4): a display name, if any, a local part and a domain."""

    name: str | None
    local: str
    domain: str

    @staticmethod
    def parse(text: bytes, utf8: bool = True) -> MailMailbox:
        """The mailbox of ``text``."""
        with MailAddresses(Handle.create(f"{P}_mail_mailbox_parse", *Bytes.readable(text), utf8)) as handle:
            address = handle.to_list()[0]
        assert isinstance(address, MailAddress.Mailbox)
        return address.mailbox

    @staticmethod
    def parse_list(text: bytes, utf8: bool = True) -> list[MailMailbox]:
        """The mailboxes of a mailbox list (one or more)."""
        with MailAddresses(Handle.create(f"{P}_mail_mailbox_parse_list", *Bytes.readable(text), utf8)) as handle:
            return [mailbox for address in handle.to_list() for mailbox in address.mailboxes()]

    @staticmethod
    def quote_if_needed(text: str, dotted: bool) -> str:
        """``text`` as it is if it is a dot-atom (``dotted``) or atoms and spaces, else quoted."""
        return Library.default().output(f"{P}_mail_mailbox_quote_if_needed", *Text.encode(text), dotted).decode("utf-8")

    def address(self) -> str:
        """The address: the local part, quoted if need be, ``@``, and the domain."""
        with MailAddresses.of([MailAddress.Mailbox(self)]) as handle:
            return handle.library.output(f"{P}_mail_addresses_address", handle.handle, 0, 0).decode("utf-8")

    def __str__(self) -> str:
        return MailAddress.format_list([MailAddress.Mailbox(self)])


class MailAddress:
    """An address (RFC 5322 §3.4): a :class:`MailAddress.Mailbox`, or a :class:`MailAddress.Group`
    of mailboxes, as the variants of the Rust enum."""

    @dataclasses.dataclass(frozen=True)
    class Mailbox:
        mailbox: MailMailbox

        def mailboxes(self) -> list[MailMailbox]:
            return [self.mailbox]

        def __str__(self) -> str:
            return MailAddress.format_list([self])

    @dataclasses.dataclass(frozen=True)
    class Group:
        name: str
        members: tuple[MailMailbox, ...] = ()

        def mailboxes(self) -> list[MailMailbox]:
            return list(self.members)

        def __str__(self) -> str:
            return MailAddress.format_list([self])

    @staticmethod
    def parse(text: bytes, utf8: bool = True) -> MailAddress.Mailbox | MailAddress.Group:
        """The one address of ``text`` (Sender, which RFC 6854 lets be a group)."""
        with MailAddresses(Handle.create(f"{P}_mail_address_parse", *Bytes.readable(text), utf8)) as handle:
            return handle.to_list()[0]

    @staticmethod
    def parse_list(text: bytes, utf8: bool = True) -> list[MailAddress.Mailbox | MailAddress.Group]:
        """The addresses of an address list, with the empty elements of §4.4."""
        with MailAddresses(Handle.create(f"{P}_mail_address_parse_list", *Bytes.readable(text), utf8)) as handle:
            return handle.to_list()

    @staticmethod
    def format_list(addresses: list[MailAddress.Mailbox | MailAddress.Group]) -> str:
        """``addresses`` written as an address list, separated by commas."""
        with MailAddresses.of(addresses) as handle:
            return handle.library.output(f"{P}_mail_addresses_format", handle.handle).decode("utf-8")


class MailAddresses(Handle):
    """A list of addresses as the C ABI holds it, made of and turned into lists of :class:`MailAddress`."""

    FREE = f"{P}_mail_addresses_free"

    @classmethod
    def of(cls, addresses: list[MailAddress.Mailbox | MailAddress.Group]) -> MailAddresses:
        out = cls(Handle.create(f"{P}_mail_addresses_new"))
        for address in addresses:
            if isinstance(address, MailAddress.Group):
                out.library.call(f"{P}_mail_addresses_push_group", out.handle, *Text.encode(address.name))
                for member in address.members:
                    out.push(f"{P}_mail_addresses_push_member", member)
            else:
                out.push(f"{P}_mail_addresses_push_mailbox", address.mailbox)
        return out

    def push(self, function: str, mailbox: MailMailbox) -> None:
        self.library.call(function, self.handle, *Text.encode(mailbox.name), *Text.encode(mailbox.local), *Text.encode(mailbox.domain))

    def to_list(self) -> list[MailAddress.Mailbox | MailAddress.Group]:
        count = self.library.value(f"{P}_mail_addresses_count", ctypes.c_size_t, self.handle)
        addresses: list[MailAddress.Mailbox | MailAddress.Group] = []
        for index in range(count):
            group, has_name, name, members = ctypes.c_bool(), ctypes.c_bool(), Buffer(), ctypes.c_size_t()
            self.library.call(f"{P}_mail_addresses_get", self.handle, index, ctypes.byref(group), ctypes.byref(has_name), ctypes.byref(name), ctypes.byref(members))
            group_name = Library.default().take_optional_text(has_name, name)
            mailboxes = [self.mailbox(index, member) for member in range(members.value)]
            if group.value:
                addresses.append(MailAddress.Group(group_name or "", tuple(mailboxes)))
            else:
                addresses.append(MailAddress.Mailbox(mailboxes[0]))
        return addresses

    def mailbox(self, index: int, member: int) -> MailMailbox:
        has_name, name, local, domain = ctypes.c_bool(), Buffer(), Buffer(), Buffer()
        self.library.call(f"{P}_mail_addresses_mailbox", self.handle, index, member, ctypes.byref(has_name), ctypes.byref(name), ctypes.byref(local), ctypes.byref(domain))
        return MailMailbox(Library.default().take_optional_text(has_name, name), self.library.take(local).decode("utf-8"), self.library.take(domain).decode("utf-8"))


@dataclasses.dataclass(frozen=True)
class MailMessageID:
    """A message identifier (RFC 5322 §3.6.4): ``<left@right>``."""

    left: str
    right: str

    @staticmethod
    def parse(text: bytes, utf8: bool = True) -> MailMessageID:
        with MailMessageIDs(Handle.create(f"{P}_mail_message_id_parse", *Bytes.readable(text), utf8)) as handle:
            return handle.to_list()[0]

    @staticmethod
    def parse_list(text: bytes, utf8: bool = True) -> list[MailMessageID]:
        """The identifiers of Message-ID, In-Reply-To or References, with the obsolete forms of §4.5.4."""
        with MailMessageIDs(Handle.create(f"{P}_mail_message_id_parse_list", *Bytes.readable(text), utf8)) as handle:
            return handle.to_list()

    def __str__(self) -> str:
        return f"<{self.left}@{self.right}>"


class MailMessageIDs(Handle):
    """A list of message identifiers as the C ABI holds it, turned into lists of :class:`MailMessageID`."""

    FREE = f"{P}_mail_message_ids_free"

    def to_list(self) -> list[MailMessageID]:
        count = self.library.value(f"{P}_mail_message_ids_count", ctypes.c_size_t, self.handle)
        identifiers = []
        for index in range(count):
            left, right = Buffer(), Buffer()
            self.library.call(f"{P}_mail_message_ids_get", self.handle, index, ctypes.byref(left), ctypes.byref(right))
            identifiers.append(MailMessageID(self.library.take(left).decode("utf-8"), self.library.take(right).decode("utf-8")))
        return identifiers


@dataclasses.dataclass(frozen=True)
class MailField:
    """A header field: its name and its value as it is in the message, folded or not."""

    MAXIMUM_LINE: ClassVar[int] = 998
    LINE: ClassVar[int] = 78

    name: str
    value: bytes

    @staticmethod
    def is_name(name: str) -> bool:
        """Whether ``name`` is a field name: printable US-ASCII but the colon (RFC 5322 §3.6.8)."""
        return bool(Library.default().value(f"{P}_mail_field_is_name", ctypes.c_bool, *Text.encode(name)))

    def unfolded(self) -> bytes:
        """The value, each line break followed by white space removed (§2.2.3)."""
        return Library.default().output(f"{P}_mail_field_unfolded", *Bytes.readable(self.value))


class MailFields(Handle):
    """The fields of a header section, in order; names compare without case."""

    FREE = f"{P}_mail_fields_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create(f"{P}_mail_fields_new"))

    @classmethod
    def decode(cls, text: bytes, config: MailConfig | None = None) -> tuple[MailFields, int]:
        """The fields of the header section that begins ``text``, and where the body begins."""
        out, body = ctypes.c_void_p(), ctypes.c_size_t()
        structure = (config or MailConfig()).to_structure()
        Library.default().call(f"{P}_mail_fields_decode", *Bytes.readable(text), structure, ctypes.byref(out), ctypes.byref(body))
        return cls(out.value), body.value

    @property
    def entries(self) -> list[MailField]:
        count = self.library.value(f"{P}_mail_fields_count", ctypes.c_size_t, self.handle)
        fields = []
        for index in range(count):
            name, value = Buffer(), Buffer()
            self.library.call(f"{P}_mail_fields_get", self.handle, index, ctypes.byref(name), ctypes.byref(value))
            fields.append(MailField(self.library.take(name).decode("utf-8"), self.library.take(value)))
        return fields

    def all(self, name: str) -> list[MailField]:
        """The fields named ``name``, in order."""
        return [field for field in self.entries if field.name.lower() == name.lower()]

    def field(self, name: str) -> MailField | None:
        """The first field named ``name``."""
        found = self.all(name)
        return found[0] if found else None

    def get(self, name: str) -> bytes | None:
        """The value of the first field named ``name``."""
        field = self.field(name)
        return field.value if field else None

    def contains(self, name: str) -> bool:
        return self.field(name) is not None

    def push(self, name: str, value: bytes) -> None:
        """Adds a field at the end; fails for a name that is not one or a value with a line break."""
        self.library.call(f"{P}_mail_fields_push", self.handle, *Text.encode(name), *Bytes.readable(value))

    def set(self, name: str, value: bytes) -> None:
        """Replaces the fields named ``name`` by one, where the first was, or at the end."""
        self.library.call(f"{P}_mail_fields_set", self.handle, *Text.encode(name), *Bytes.readable(value))

    def remove(self, name: str) -> None:
        self.library.call(f"{P}_mail_fields_remove", self.handle, *Text.encode(name))

    def encode(self) -> bytes:
        """The fields, each a line, folded where their values allow."""
        return self.library.output(f"{P}_mail_fields_encode", self.handle)

    def date(self, name: str) -> MailDate | None:
        """The date-time of the first field named ``name`` (Date, Resent-Date)."""
        value = self.get(name)
        return None if value is None else MailDate.parse(value)

    def addresses(self, name: str) -> list[MailAddress.Mailbox | MailAddress.Group] | None:
        """The addresses of the first field named ``name`` (To, Cc, Bcc, Reply-To, From)."""
        value = self.get(name)
        return None if value is None else MailAddress.parse_list(value)

    def mailboxes(self, name: str) -> list[MailMailbox] | None:
        value = self.get(name)
        return None if value is None else MailMailbox.parse_list(value)

    def mailbox(self, name: str) -> MailMailbox | None:
        value = self.get(name)
        return None if value is None else MailMailbox.parse(value)

    def address(self, name: str) -> MailAddress.Mailbox | MailAddress.Group | None:
        value = self.get(name)
        return None if value is None else MailAddress.parse(value)

    def message_ids(self, name: str) -> list[MailMessageID] | None:
        """The identifiers of the first field named ``name`` (Message-ID, In-Reply-To, References)."""
        value = self.get(name)
        return None if value is None else MailMessageID.parse_list(value)

    def text(self, name: str) -> str | None:
        """The unstructured text of the first field named ``name``, unfolded, its encoded words
        decoded, white space at its ends removed."""
        value = self.get(name)
        return None if value is None else MIMEEncodedWord.decode_text(value).strip(" \t")


@dataclasses.dataclass
class MailMessage:
    """A message (RFC 5322 §2.1): a header section and a body."""

    SINGLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Message-ID", "In-Reply-To", "References", "Subject",
    )  # fmt: skip

    fields: MailFields = dataclasses.field(default_factory=MailFields)
    body: bytes = b""

    @classmethod
    def decode(cls, text: bytes, config: MailConfig | None = None) -> MailMessage:
        out, body = ctypes.c_void_p(), Buffer()
        structure = (config or MailConfig()).to_structure()
        Library.default().call(f"{P}_mail_message_decode", *Bytes.readable(text), structure, ctypes.byref(out), ctypes.byref(body))
        fields = MailFields(out.value)
        return cls(fields, Library.default().take(body))

    def encode(self) -> bytes:
        """The fields, an empty line, the body."""
        return self.fields.library.output(f"{P}_mail_message_encode", self.fields.handle, *Bytes.readable(self.body))

    def validate(self) -> None:
        """Raises :class:`MailError` for what RFC 5322 (and RFC 6854) requires of a message and it lacks."""
        self.fields.library.call(f"{P}_mail_message_validate", self.fields.handle, *Bytes.readable(self.body))


class MIMECharset(enum.IntEnum):
    """A character set converted to and from Unicode."""

    USASCII = 0
    UTF8 = 1
    ISO88591 = 2
    Windows1252 = 3

    @staticmethod
    def from_name(name: str) -> MIMECharset | None:
        """The character set of a name of the IANA registry, in any case."""
        value = Library.default().optional(f"{P}_mime_charset_from_name", ctypes.c_uint8, *Text.encode(name))
        return None if value is None else MIMECharset(value)

    def preferred_name(self) -> str:
        """The preferred MIME name of the character set."""
        return Library.default().output(f"{P}_mime_charset_preferred_name", int(self)).decode("ascii")

    def decode(self, data: bytes) -> str:
        return Library.default().output(f"{P}_mime_charset_decode", int(self), *Bytes.readable(data)).decode("utf-8")

    def encode(self, text: str) -> bytes:
        return Library.default().output(f"{P}_mime_charset_encode", int(self), *Text.encode(text))

    @staticmethod
    def decode_named(name: str, data: bytes) -> str:
        """The text of ``data`` of the character set named ``name``: one converted, or ISO 8859 and
        Windows-125x when ``data`` is US-ASCII; raises ``Charset`` for others."""
        return Library.default().output(f"{P}_mime_charset_decode_named", *Text.encode(name), *Bytes.readable(data)).decode("utf-8")


class MIMEWordEncoding(enum.IntEnum):
    """The encoding of an encoded word (RFC 2047 §4)."""

    B = 0
    Q = 1


@dataclasses.dataclass(frozen=True)
class MIMEEncodedWord:
    """An encoded word (RFC 2047 §2) with the language of RFC 2231 §5."""

    MAXIMUM_LENGTH: ClassVar[int] = 75

    charset: str
    language: str | None
    encoding: MIMEWordEncoding
    data: bytes

    @classmethod
    def parse(cls, word: bytes) -> MIMEEncodedWord:
        charset, has_language, language, encoding, data = Buffer(), ctypes.c_bool(), Buffer(), ctypes.c_uint8(), Buffer()
        library = Library.default()
        library.call(f"{P}_mime_encoded_word_parse", *Bytes.readable(word), ctypes.byref(charset), ctypes.byref(has_language), ctypes.byref(language), ctypes.byref(encoding), ctypes.byref(data))
        return cls(library.take(charset).decode("utf-8"), Library.default().take_optional_text(has_language, language), MIMEWordEncoding(encoding.value), library.take(data))

    @staticmethod
    def decode_q(text: bytes) -> bytes:
        return Library.default().output(f"{P}_mime_encoded_word_decode_q", *Bytes.readable(text))

    def text(self) -> str:
        """The text of the word, if its character set is converted."""
        return MIMECharset.decode_named(self.charset, self.data)

    def encode(self) -> str:
        arguments = (*Text.encode(self.charset), *Text.encode(self.language), int(self.encoding), *Bytes.readable(self.data))
        return Library.default().output(f"{P}_mime_encoded_word_encode", *arguments).decode("ascii")

    @staticmethod
    def decode_text(text: bytes) -> str:
        """Unstructured header text unfolded, its encoded words decoded (§6.2)."""
        return Library.default().output(f"{P}_mime_encoded_word_decode_text", *Bytes.readable(text)).decode("utf-8")

    @staticmethod
    def encode_text(text: str) -> str:
        """``text`` for a header of US-ASCII: as it is, or encoded words of UTF-8."""
        return Library.default().output(f"{P}_mime_encoded_word_encode_text", *Text.encode(text)).decode("ascii")


@dataclasses.dataclass(frozen=True)
class MIMEQuotedPrintable:
    """The Quoted-Printable encoding (RFC 2045 §6.7); ``binary`` encodes line breaks too."""

    LINE: ClassVar[int] = 76

    binary: bool = False

    def encode(self, data: bytes) -> bytes:
        return Library.default().output(f"{P}_mime_quoted_printable_encode", self.binary, *Bytes.readable(data))

    def decode(self, text: bytes) -> bytes:
        return Library.default().output(f"{P}_mime_quoted_printable_decode", self.binary, *Bytes.readable(text))


@dataclasses.dataclass(frozen=True)
class MIMETransferEncoding:
    """A Content-Transfer-Encoding (RFC 2045 §6), by its name: the variants of the Rust enum are
    ``SevenBit``, ``EightBit``, ``Binary``, ``QuotedPrintable``, ``Base64`` and ``Other(name)``."""

    BASE64_LINE: ClassVar[int] = 76
    SevenBit: ClassVar[MIMETransferEncoding]
    EightBit: ClassVar[MIMETransferEncoding]
    Binary: ClassVar[MIMETransferEncoding]
    QuotedPrintable: ClassVar[MIMETransferEncoding]
    Base64: ClassVar[MIMETransferEncoding]

    name: str

    @classmethod
    def Other(cls, name: str) -> MIMETransferEncoding:  # noqa: N802 - the variant of the Rust enum
        return cls(name)

    @classmethod
    def parse(cls, value: bytes) -> MIMETransferEncoding:
        return cls(Library.default().output(f"{P}_mime_transfer_encoding_parse", *Bytes.readable(value)).decode("ascii"))

    def is_identity(self) -> bool:
        """Whether the body is the data (§6.2)."""
        return self.name in ("7bit", "8bit", "binary")

    def decode(self, body: bytes) -> bytes:
        """The data of ``body``; raises ``Encoding`` for another encoding."""
        return Library.default().output(f"{P}_mime_transfer_encoding_decode", *Text.encode(self.name), *Bytes.readable(body))

    def encode(self, data: bytes) -> bytes:
        return Library.default().output(f"{P}_mime_transfer_encoding_encode", *Text.encode(self.name), *Bytes.readable(data))

    @staticmethod
    def decode_base64(body: bytes) -> bytes:
        """The data of Base64 text of a body, characters not of the alphabet ignored (§6.8)."""
        return MIMETransferEncoding.Base64.decode(body)


MIMETransferEncoding.SevenBit = MIMETransferEncoding("7bit")
MIMETransferEncoding.EightBit = MIMETransferEncoding("8bit")
MIMETransferEncoding.Binary = MIMETransferEncoding("binary")
MIMETransferEncoding.QuotedPrintable = MIMETransferEncoding("quoted-printable")
MIMETransferEncoding.Base64 = MIMETransferEncoding("base64")


@dataclasses.dataclass(frozen=True)
class MIMEParameter:
    """A parameter of a MIME field, its sections joined and its octets decoded (RFC 2231)."""

    name: str
    value: bytes
    charset: str | None = None
    language: str | None = None

    def text(self) -> str:
        """The value as text: of its character set, or of UTF-8 if none is given."""
        return MIMECharset.decode_named(self.charset or "UTF-8", self.value)


class MIMEParameters(Handle):
    """The parameters of a MIME field, in order."""

    FREE = f"{P}_mime_parameters_free"

    def __init__(self, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create(f"{P}_mime_parameters_new"))

    @property
    def entries(self) -> list[MIMEParameter]:
        count = self.library.value(f"{P}_mime_parameters_count", ctypes.c_size_t, self.handle)
        parameters = []
        for index in range(count):
            name, value, has_charset, charset, has_language, language = Buffer(), Buffer(), ctypes.c_bool(), Buffer(), ctypes.c_bool(), Buffer()
            self.library.call(f"{P}_mime_parameters_get", self.handle, index, ctypes.byref(name), ctypes.byref(value), ctypes.byref(has_charset), ctypes.byref(charset), ctypes.byref(has_language), ctypes.byref(language))
            parameters.append(MIMEParameter(self.library.take(name).decode("utf-8"), self.library.take(value), Library.default().take_optional_text(has_charset, charset), Library.default().take_optional_text(has_language, language)))
        return parameters

    def get(self, name: str) -> MIMEParameter | None:
        """The parameter named ``name``, in any case."""
        return next((parameter for parameter in self.entries if parameter.name.lower() == name.lower()), None)

    def text(self, name: str) -> str | None:
        """The value of the parameter named ``name``, if it is UTF-8 text."""
        parameter = self.get(name)
        if parameter is None:
            return None
        try:
            return parameter.value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def set(self, parameter: MIMEParameter) -> None:
        """Replaces the parameter of the same name, or adds it at the end."""
        arguments = (*Text.encode(parameter.name), *Bytes.readable(parameter.value), *Text.encode(parameter.charset), *Text.encode(parameter.language))
        self.library.call(f"{P}_mime_parameters_set", self.handle, *arguments)

    def remove(self, name: str) -> None:
        self.library.call(f"{P}_mime_parameters_remove", self.handle, *Text.encode(name))

    def encode(self) -> str:
        """The parameters, each ``; name=value``, extended (RFC 2231) where need be."""
        return self.library.output(f"{P}_mime_parameters_encode", self.handle).decode("ascii")


class MIMEContentType(Handle):
    """A Content-Type (RFC 2045 §5): a media type and subtype, in lower case, and parameters."""

    FREE = f"{P}_mime_content_type_free"

    def __init__(self, kind: str | None = None, subtype: str | None = None, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create(f"{P}_mime_content_type_new", *Text.encode(kind or ""), *Text.encode(subtype or "")))

    @classmethod
    def parse(cls, value: bytes) -> MIMEContentType:
        return cls(pointer=Handle.create(f"{P}_mime_content_type_parse", *Bytes.readable(value)))

    @classmethod
    def default_text(cls) -> MIMEContentType:
        """``text/plain; charset=us-ascii`` (RFC 2045 §5.2)."""
        return cls(pointer=Handle.create(f"{P}_mime_content_type_default_text"))

    @classmethod
    def default_digest(cls) -> MIMEContentType:
        """``message/rfc822`` (RFC 2046 §5.1.5)."""
        return cls(pointer=Handle.create(f"{P}_mime_content_type_default_digest"))

    def names(self) -> tuple[str, str]:
        kind, subtype = Buffer(), Buffer()
        self.library.call(f"{P}_mime_content_type_kind", self.handle, ctypes.byref(kind), ctypes.byref(subtype))
        return self.library.take(kind).decode("utf-8"), self.library.take(subtype).decode("utf-8")

    @property
    def kind(self) -> str:
        return self.names()[0]

    @property
    def subtype(self) -> str:
        return self.names()[1]

    @property
    def parameters(self) -> MIMEParameters:
        """A copy of the parameters; assign it back to change them."""
        return MIMEParameters(Handle.create(f"{P}_mime_content_type_parameters", self.handle))

    @parameters.setter
    def parameters(self, parameters: MIMEParameters) -> None:
        self.library.call(f"{P}_mime_content_type_set_parameters", self.handle, parameters.handle)

    def is_(self, kind: str, subtype: str) -> bool:
        """Whether the type is ``kind/subtype``, in any case (``is`` in Rust)."""
        return self.names() == (kind.lower(), subtype.lower())

    def is_multipart(self) -> bool:
        return self.kind == "multipart"

    def is_message(self) -> bool:
        """Whether the type is message/rfc822 or message/global (RFC 6532 §3.7)."""
        return self.is_("message", "rfc822") or self.is_("message", "global")

    def boundary(self) -> bytes | None:
        """The boundary of a multipart, if it is one of RFC 2046 §5.1.1."""
        return self.library.optional(f"{P}_mime_content_type_boundary", Buffer, self.handle)

    def format(self) -> str:
        return self.library.output(f"{P}_mime_content_type_format", self.handle).decode("utf-8")

    def __str__(self) -> str:
        return self.format()


class MIMEDisposition(Handle):
    """A Content-Disposition (RFC 2183): a type, in lower case, and parameters."""

    FREE = f"{P}_mime_disposition_free"

    def __init__(self, kind: str | None = None, pointer: int | None = None) -> None:
        super().__init__(pointer or Handle.create(f"{P}_mime_disposition_new", *Text.encode(kind or "")))

    @classmethod
    def parse(cls, value: bytes) -> MIMEDisposition:
        return cls(pointer=Handle.create(f"{P}_mime_disposition_parse", *Bytes.readable(value)))

    @property
    def kind(self) -> str:
        return self.library.output(f"{P}_mime_disposition_kind", self.handle).decode("utf-8")

    @property
    def parameters(self) -> MIMEParameters:
        """A copy of the parameters; assign it back to change them."""
        return MIMEParameters(Handle.create(f"{P}_mime_disposition_parameters", self.handle))

    @parameters.setter
    def parameters(self, parameters: MIMEParameters) -> None:
        self.library.call(f"{P}_mime_disposition_set_parameters", self.handle, parameters.handle)

    def is_inline(self) -> bool:
        return self.kind == "inline"

    def filename(self) -> str | None:
        """The suggested file name: its last path component only (RFC 2183 §2.3)."""
        data = self.library.optional(f"{P}_mime_disposition_filename", Buffer, self.handle)
        return None if data is None else data.decode("utf-8")

    def format(self) -> str:
        return self.library.output(f"{P}_mime_disposition_format", self.handle).decode("utf-8")

    def __str__(self) -> str:
        return self.format()


class MIMEEntity(Handle):
    """A MIME entity read from a message: its fields, type and encoding, where its header section
    and body are in the text read, its parts (a multipart) or its message (message/rfc822)."""

    FREE = f"{P}_mime_entity_free"

    @classmethod
    def decode(cls, text: bytes, config: MailConfig | None = None) -> MIMEEntity:
        structure = (config or MailConfig()).to_structure()
        return cls(Handle.create(f"{P}_mime_entity_decode", *Bytes.readable(text), structure))

    def ranges(self) -> tuple[range, range]:
        header_start, header_end, body_start, body_end = (ctypes.c_size_t() for _ in range(4))
        self.library.call(f"{P}_mime_entity_ranges", self.handle, ctypes.byref(header_start), ctypes.byref(header_end), ctypes.byref(body_start), ctypes.byref(body_end))
        return range(header_start.value, header_end.value), range(body_start.value, body_end.value)

    @property
    def header(self) -> range:
        """The header section, with the empty line that ends it if there is one."""
        return self.ranges()[0]

    @property
    def body(self) -> range:
        return self.ranges()[1]

    @property
    def fields(self) -> MailFields:
        return MailFields(Handle.create(f"{P}_mime_entity_fields", self.handle))

    @property
    def content_type(self) -> MIMEContentType:
        """The type of Content-Type, or the default (RFC 2045 §5.2, RFC 2046 §5.1.5)."""
        return MIMEContentType(pointer=Handle.create(f"{P}_mime_entity_content_type", self.handle))

    @property
    def encoding(self) -> MIMETransferEncoding:
        return MIMETransferEncoding(self.library.output(f"{P}_mime_entity_encoding", self.handle).decode("utf-8"))

    @property
    def parts(self) -> list[MIMEEntity]:
        count = self.library.value(f"{P}_mime_entity_part_count", ctypes.c_size_t, self.handle)
        return [MIMEEntity(Handle.create(f"{P}_mime_entity_part", self.handle, index)) for index in range(count)]

    @property
    def message(self) -> MIMEEntity | None:
        """The encapsulated message of message/rfc822 or message/global."""
        has, out = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call(f"{P}_mime_entity_message", self.handle, ctypes.byref(has), ctypes.byref(out))
        return MIMEEntity(out.value) if has.value else None

    def data(self, text: bytes) -> bytes:
        """The body in ``text`` (the text the entity was read from), decoded from its transfer encoding."""
        return self.library.output(f"{P}_mime_entity_data", self.handle, *Bytes.readable(text))

    def disposition(self) -> MIMEDisposition | None:
        has, out = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call(f"{P}_mime_entity_disposition", self.handle, ctypes.byref(has), ctypes.byref(out))
        return MIMEDisposition(pointer=out.value) if has.value else None


class MIMEMultipart(Handle):
    """The parts of the body of a multipart (RFC 2046 §5.1.1), as ranges of the text."""

    FREE = f"{P}_mime_multipart_free"

    @classmethod
    def split(cls, text: bytes, body: range, boundary: bytes) -> MIMEMultipart:
        return cls(Handle.create(f"{P}_mime_multipart_split", *Bytes.readable(text), body.start, body.stop, *Bytes.readable(boundary)))

    def ranges(self) -> tuple[range, range, bool]:
        preamble_start, preamble_end, epilogue_start, epilogue_end = (ctypes.c_size_t() for _ in range(4))
        closed = ctypes.c_bool()
        self.library.call(f"{P}_mime_multipart_ranges", self.handle, ctypes.byref(preamble_start), ctypes.byref(preamble_end), ctypes.byref(epilogue_start), ctypes.byref(epilogue_end), ctypes.byref(closed))
        return range(preamble_start.value, preamble_end.value), range(epilogue_start.value, epilogue_end.value), closed.value

    @property
    def preamble(self) -> range:
        return self.ranges()[0]

    @property
    def epilogue(self) -> range:
        """After the close delimiter; empty if there is none."""
        return self.ranges()[1]

    @property
    def closed(self) -> bool:
        """Whether the close delimiter was found; the last part runs to the end of the body if not."""
        return self.ranges()[2]

    @property
    def parts(self) -> list[range]:
        count = self.library.value(f"{P}_mime_multipart_part_count", ctypes.c_size_t, self.handle)
        parts = []
        for index in range(count):
            start, end = ctypes.c_size_t(), ctypes.c_size_t()
            self.library.call(f"{P}_mime_multipart_part", self.handle, index, ctypes.byref(start), ctypes.byref(end))
            parts.append(range(start.value, end.value))
        return parts

    @staticmethod
    def delimiter(line: bytes, boundary: bytes) -> bool | None:
        """Whether ``line`` is a delimiter of ``boundary``: ``True`` the close delimiter, ``None`` none."""
        delimiter, close = ctypes.c_bool(), ctypes.c_bool()
        Library.default().call(f"{P}_mime_multipart_delimiter", *Bytes.readable(line), *Bytes.readable(boundary), ctypes.byref(delimiter), ctypes.byref(close))
        return close.value if delimiter.value else None

    @staticmethod
    def encode(boundary: bytes, parts: list[bytes]) -> bytes:
        """A multipart body of ``parts``; raises :class:`MailError` if a part has the boundary in it."""
        pointers, lengths, count, _kept = Bytes.array(parts)
        return Library.default().output(f"{P}_mime_multipart_encode", *Bytes.readable(boundary), pointers, lengths, count)
