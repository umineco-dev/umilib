"""ASN.1 encodings, ITU-T X.690. Mirrors ``umilib::codec::asn1``.

``Tag`` uses the field name ``tag_class`` (as in C) because ``class`` is a
Python keyword.
"""

from __future__ import annotations

import ctypes
import datetime
import enum
from dataclasses import dataclass
from typing import ClassVar

from umilib.ffi import Bytes, FFIError, Handle, I128, Library, Text, U128


class ASN1Error(FFIError):
    """An error of ASN.1 encoding or decoding; ``name`` is the variant, such as ``NonCanonical``."""


Library.register_error("codec.asn1", ASN1Error)


class TagClass(enum.IntEnum):
    Universal = 0
    Application = 1
    ContextSpecific = 2
    Private = 3


@dataclass(frozen=True)
class Tag:
    """The identifier of an element: class, form and number (X.690 section 8.1.2)."""

    tag_class: TagClass
    constructed: bool
    number: int

    BOOLEAN: ClassVar[Tag]
    INTEGER: ClassVar[Tag]
    BIT_STRING: ClassVar[Tag]
    OCTET_STRING: ClassVar[Tag]
    NULL: ClassVar[Tag]
    OBJECT_IDENTIFIER: ClassVar[Tag]
    ENUMERATED: ClassVar[Tag]
    UTF8_STRING: ClassVar[Tag]
    SEQUENCE: ClassVar[Tag]
    SET: ClassVar[Tag]
    NUMERIC_STRING: ClassVar[Tag]
    PRINTABLE_STRING: ClassVar[Tag]
    TELETEX_STRING: ClassVar[Tag]
    IA5_STRING: ClassVar[Tag]
    UTC_TIME: ClassVar[Tag]
    GENERALIZED_TIME: ClassVar[Tag]
    VISIBLE_STRING: ClassVar[Tag]
    UNIVERSAL_STRING: ClassVar[Tag]
    BMP_STRING: ClassVar[Tag]

    @classmethod
    def universal(cls, number: int, constructed: bool) -> Tag:
        return cls(TagClass.Universal, constructed, number)

    @classmethod
    def context(cls, number: int, constructed: bool) -> Tag:
        return cls(TagClass.ContextSpecific, constructed, number)

    @classmethod
    def application(cls, number: int, constructed: bool) -> Tag:
        return cls(TagClass.Application, constructed, number)

    @classmethod
    def private(cls, number: int, constructed: bool) -> Tag:
        return cls(TagClass.Private, constructed, number)

    def with_constructed(self, constructed: bool) -> Tag:
        return Tag(self.tag_class, constructed, self.number)

    def to_c(self) -> ctypes.Structure:
        return Library.default().type("umilib_codec_asn1_Tag")(int(self.tag_class), self.constructed, self.number)

    @classmethod
    def from_c(cls, value: ctypes.Structure) -> Tag:
        return cls(TagClass(value.tag_class), bool(value.constructed), value.number)

    @classmethod
    def decode(cls, data: bytes, position: int) -> tuple[Tag, int]:
        library = Library.default()
        data, length = Bytes.readable(data)
        out, following = library.type("umilib_codec_asn1_Tag")(), ctypes.c_size_t()
        library.call("umilib_codec_asn1_tag_decode", data, length, position, ctypes.byref(out), ctypes.byref(following))
        return cls.from_c(out), following.value

    def encode(self) -> bytes:
        return Library.default().output("umilib_codec_asn1_tag_encode", self.to_c())

    def compare_order(self, other: Tag) -> int:
        """-1, 0 or 1 as ``self`` comes before, with or after ``other`` in the canonical
        order of X.680 section 8.6 (class, then number; the form is ignored)."""
        return Library.default().value("umilib_codec_asn1_tag_compare_order", ctypes.c_int8, self.to_c(), other.to_c())


Tag.BOOLEAN = Tag.universal(1, False)
Tag.INTEGER = Tag.universal(2, False)
Tag.BIT_STRING = Tag.universal(3, False)
Tag.OCTET_STRING = Tag.universal(4, False)
Tag.NULL = Tag.universal(5, False)
Tag.OBJECT_IDENTIFIER = Tag.universal(6, False)
Tag.OBJECT_DESCRIPTOR = Tag.universal(7, False)
Tag.EXTERNAL = Tag.universal(8, True)
Tag.REAL = Tag.universal(9, False)
Tag.ENUMERATED = Tag.universal(10, False)
Tag.EMBEDDED_PDV = Tag.universal(11, True)
Tag.UTF8_STRING = Tag.universal(12, False)
Tag.RELATIVE_OID = Tag.universal(13, False)
Tag.TIME = Tag.universal(14, False)
Tag.SEQUENCE = Tag.universal(16, True)
Tag.SET = Tag.universal(17, True)
Tag.NUMERIC_STRING = Tag.universal(18, False)
Tag.PRINTABLE_STRING = Tag.universal(19, False)
Tag.TELETEX_STRING = Tag.universal(20, False)
Tag.VIDEOTEX_STRING = Tag.universal(21, False)
Tag.IA5_STRING = Tag.universal(22, False)
Tag.UTC_TIME = Tag.universal(23, False)
Tag.GENERALIZED_TIME = Tag.universal(24, False)
Tag.GRAPHIC_STRING = Tag.universal(25, False)
Tag.VISIBLE_STRING = Tag.universal(26, False)
Tag.GENERAL_STRING = Tag.universal(27, False)
Tag.UNIVERSAL_STRING = Tag.universal(28, False)
Tag.CHARACTER_STRING = Tag.universal(29, True)
Tag.BMP_STRING = Tag.universal(30, False)
Tag.DATE = Tag.universal(31, False)
Tag.TIME_OF_DAY = Tag.universal(32, False)
Tag.DATE_TIME = Tag.universal(33, False)
Tag.DURATION = Tag.universal(34, False)


class ObjectIdentifier(Handle):
    """An OBJECT IDENTIFIER."""

    FREE = "umilib_codec_asn1_object_identifier_free"

    @classmethod
    def new(cls, content: bytes) -> ObjectIdentifier:
        data, length = Bytes.readable(content)
        return cls(Handle.create("umilib_codec_asn1_object_identifier_new", data, length))

    @classmethod
    def from_arcs(cls, arcs: list[int]) -> ObjectIdentifier:
        array = (U128 * len(arcs))(*[U128.from_int(arc) for arc in arcs])
        return cls(Handle.create("umilib_codec_asn1_object_identifier_from_arcs", array if arcs else None, len(arcs)))

    @classmethod
    def parse(cls, text: str) -> ObjectIdentifier:
        data, length = Text.encode(text)
        return cls(Handle.create("umilib_codec_asn1_object_identifier_parse", data, length))

    def as_bytes(self) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        with self.locked():
            self.library.call("umilib_codec_asn1_object_identifier_as_bytes", self.handle, ctypes.byref(pointer), ctypes.byref(length))
            return ctypes.string_at(pointer.value, length.value)

    @staticmethod
    def validate_subidentifiers(content: bytes) -> None:
        """Raises unless ``content`` is a list of subidentifiers (the contents of an OBJECT
        IDENTIFIER or a RELATIVE-OID): at least one, each minimal and within 128 bits."""
        data, length = Bytes.readable(content)
        Library.default().call("umilib_codec_asn1_object_identifier_validate_subidentifiers", data, length)

    def arcs(self) -> list[int]:
        count = self.library.value("umilib_codec_asn1_object_identifier_arc_count", ctypes.c_size_t, self.handle)
        return [self.library.value("umilib_codec_asn1_object_identifier_arcs", U128, self.handle, index).to_int() for index in range(count)]

    def __str__(self) -> str:
        return self.library.output("umilib_codec_asn1_object_identifier_to_string", self.handle).decode("ascii")

    def __repr__(self) -> str:
        return f"ObjectIdentifier({self})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ObjectIdentifier):
            return NotImplemented
        return self.library.value("umilib_codec_asn1_object_identifier_equal", ctypes.c_bool, self.handle, other.handle)

    def __hash__(self) -> int:
        return hash(self.as_bytes())


class ASN1Integer:
    """The contents of an INTEGER: big-endian two's complement in the fewest octets."""

    def __init__(self, content: bytes) -> None:
        content = bytes(content)
        Library.default().call("umilib_codec_asn1_asn1_integer_new", content, len(content))
        self.content = content

    @classmethod
    def new(cls, content: bytes) -> ASN1Integer:
        return cls(content)

    def as_bytes(self) -> bytes:
        return self.content

    def is_negative(self) -> bool:
        return self.content[0] & 0x80 != 0

    def as_i128(self) -> int:
        return Library.default().value("umilib_codec_asn1_asn1_integer_as_i128", I128, self.content, len(self.content)).to_int()

    def as_u128(self) -> int:
        return Library.default().value("umilib_codec_asn1_asn1_integer_as_u128", U128, self.content, len(self.content)).to_int()

    def as_i64(self) -> int:
        value = self.as_i128()
        if not -(1 << 63) <= value < 1 << 63:
            raise ASN1Error("codec.asn1", "OutOfRange", "the integer does not fit in i64")
        return value

    def as_u64(self) -> int:
        value = self.as_u128()
        if value >= 1 << 64:
            raise ASN1Error("codec.asn1", "OutOfRange", "the integer does not fit in u64")
        return value

    def magnitude(self) -> bytes | None:
        if self.is_negative():
            return None
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call("umilib_codec_asn1_asn1_integer_magnitude", self.content, len(self.content), ctypes.byref(pointer), ctypes.byref(length))
        # The magnitude is the end of the contents.
        return self.content[len(self.content) - length.value:]

    def to_int(self) -> int:
        """The value as a Python integer, whatever its size."""
        return int.from_bytes(self.content, "big", signed=True)

    @staticmethod
    def encode_i128(value: int) -> bytes:
        return Library.default().output("umilib_codec_asn1_asn1_integer_encode_i128", I128.from_int(value))

    @staticmethod
    def encode_unsigned(magnitude: bytes) -> bytes:
        data, length = Bytes.readable(magnitude)
        return Library.default().output("umilib_codec_asn1_asn1_integer_encode_unsigned", data, length)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ASN1Integer) and self.content == other.content

    def __repr__(self) -> str:
        return f"ASN1Integer({self.to_int()})"


@dataclass(frozen=True)
class BitString:
    """The value of a BIT STRING: ``data`` whose last ``unused`` low bits are not part of it."""

    unused: int
    data: bytes

    def __post_init__(self) -> None:
        Library.default().call("umilib_codec_asn1_bit_string_new", self.unused, self.data, len(self.data))

    @classmethod
    def new(cls, unused_bits: int, data: bytes) -> BitString:
        return cls(unused_bits, bytes(data))

    @classmethod
    def decode_content(cls, content: bytes) -> BitString:
        content = bytes(content)
        unused, pointer, length = ctypes.c_uint8(), ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call("umilib_codec_asn1_bit_string_decode_content", content, len(content), ctypes.byref(unused), ctypes.byref(pointer), ctypes.byref(length))
        return cls(unused.value, content[1:])

    def unused_bits(self) -> int:
        return self.unused

    def bytes(self) -> bytes:  # noqa: A003 - mirrors the Rust method
        return self.data

    def as_octets(self) -> bytes | None:
        return self.data if self.unused == 0 else None

    def bit_length(self) -> int:
        return len(self.data) * 8 - self.unused

    def bit(self, index: int) -> bool:
        return 0 <= index < self.bit_length() and bool(self.data[index // 8] & (0x80 >> (index % 8)))

    def has_zero_padding(self) -> bool:
        return Library.default().value("umilib_codec_asn1_bit_string_has_zero_padding", ctypes.c_bool, self.unused, self.data, len(self.data))

    def with_zero_padding(self) -> BitString:
        if self.has_zero_padding():
            return self
        mask = (0xFF << self.unused) & 0xFF
        return BitString(self.unused, self.data[:-1] + bytes([self.data[-1] & mask]))

    def encode_content(self) -> bytes:
        return bytes([self.unused]) + self.data


class ASN1String:
    """Validation and conversion of the restricted character string types."""

    @staticmethod
    def check(name: str, data: bytes) -> bool:
        data, length = Bytes.readable(data)
        return Library.default().value(f"umilib_codec_asn1_asn1_string_{name}", ctypes.c_bool, data, length)

    @staticmethod
    def is_printable(data: bytes) -> bool:
        return ASN1String.check("is_printable", data)

    @staticmethod
    def is_ia5(data: bytes) -> bool:
        return ASN1String.check("is_ia5", data)

    @staticmethod
    def is_visible(data: bytes) -> bool:
        return ASN1String.check("is_visible", data)

    @staticmethod
    def is_numeric(data: bytes) -> bool:
        return ASN1String.check("is_numeric", data)

    @staticmethod
    def decode_utf8(data: bytes) -> str:
        try:
            return bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise ASN1Error("codec.asn1", "InvalidContent", "the contents are not valid UTF-8") from None

    @staticmethod
    def decode_bmp(data: bytes) -> str:
        data, length = Bytes.readable(data)
        return Library.default().output("umilib_codec_asn1_asn1_string_decode_bmp", data, length).decode("utf-8")

    @staticmethod
    def decode_universal(data: bytes) -> str:
        data, length = Bytes.readable(data)
        return Library.default().output("umilib_codec_asn1_asn1_string_decode_universal", data, length).decode("utf-8")

    @staticmethod
    def encode_bmp(text: str) -> bytes:
        data, length = Text.encode(text)
        return Library.default().output("umilib_codec_asn1_asn1_string_encode_bmp", data, length)

    @staticmethod
    def encode_universal(text: str) -> bytes:
        data, length = Text.encode(text)
        return Library.default().output("umilib_codec_asn1_asn1_string_encode_universal", data, length)


class ASN1Real:
    """The contents octets of a REAL (X.690 section 8.5) and their DER form (section 11.3)."""

    PLUS_INFINITY = 0x40
    MINUS_INFINITY = 0x41
    NOT_A_NUMBER = 0x42
    MINUS_ZERO = 0x43
    NR3 = 0x03

    @staticmethod
    def to_der(content: bytes) -> bytes:
        """The DER contents of the REAL whose BER contents are ``content``."""
        data, length = Bytes.readable(content)
        return Library.default().output("umilib_codec_asn1_asn1_real_to_der", data, length)

    @staticmethod
    def validate_der(content: bytes) -> None:
        """Raises unless ``content`` is the DER contents of a REAL."""
        data, length = Bytes.readable(content)
        Library.default().call("umilib_codec_asn1_asn1_real_validate_der", data, length)


@dataclass(frozen=True)
class ASN1Time:
    """A moment in UTC, as held by UTCTime and GeneralizedTime."""

    year: int
    month: int
    day: int
    hour: int = 0
    minute: int = 0
    second: int = 0
    nanosecond: int = 0

    @classmethod
    def new(cls, year: int, month: int, day: int, hour: int, minute: int, second: int, nanosecond: int) -> ASN1Time:
        library = Library.default()
        out = library.type("umilib_codec_asn1_ASN1Time")()
        library.call("umilib_codec_asn1_asn1_time_new", year, month, day, hour, minute, second, nanosecond, ctypes.byref(out))
        return cls.from_c(out)

    @classmethod
    def from_c(cls, value: ctypes.Structure) -> ASN1Time:
        return cls(value.year, value.month, value.day, value.hour, value.minute, value.second, value.nanosecond)

    def to_c(self) -> ctypes.Structure:
        return Library.default().type("umilib_codec_asn1_ASN1Time")(self.year, self.month, self.day, self.hour, self.minute, self.second, self.nanosecond)

    @staticmethod
    def is_leap_year(year: int) -> bool:
        return bool(Library.default().function("umilib_codec_asn1_asn1_time_is_leap_year")(year))

    @staticmethod
    def days_in_month(year: int, month: int) -> int:
        return Library.default().function("umilib_codec_asn1_asn1_time_days_in_month")(year, month)

    @classmethod
    def decode(cls, function: str, content: bytes) -> ASN1Time:
        library = Library.default()
        data, length = Bytes.readable(content)
        out = library.type("umilib_codec_asn1_ASN1Time")()
        library.call(f"umilib_codec_asn1_asn1_time_{function}", data, length, ctypes.byref(out))
        return cls.from_c(out)

    @classmethod
    def decode_utc_time(cls, content: bytes) -> ASN1Time:
        return cls.decode("decode_utc_time", content)

    @classmethod
    def decode_generalized_time(cls, content: bytes) -> ASN1Time:
        return cls.decode("decode_generalized_time", content)

    @classmethod
    def decode_utc_time_ber(cls, content: bytes) -> ASN1Time:
        return cls.decode("decode_utc_time_ber", content)

    @classmethod
    def decode_generalized_time_ber(cls, content: bytes) -> ASN1Time:
        return cls.decode("decode_generalized_time_ber", content)

    def encode_utc_time(self) -> bytes:
        return Library.default().output("umilib_codec_asn1_asn1_time_encode_utc_time", self.to_c())

    def encode_generalized_time(self) -> bytes:
        return Library.default().output("umilib_codec_asn1_asn1_time_encode_generalized_time", self.to_c())

    @staticmethod
    def generalized_time_ber_to_der(content: bytes) -> bytes:
        """The DER contents of a GeneralizedTime in any BER form with a zone, keeping every
        digit of the fraction."""
        data, length = Bytes.readable(content)
        return Library.default().output("umilib_codec_asn1_asn1_time_generalized_time_ber_to_der", data, length)

    def to_unix_seconds(self) -> int:
        return Library.default().value("umilib_codec_asn1_asn1_time_to_unix_seconds", ctypes.c_int64, self.to_c())

    @classmethod
    def from_unix_seconds(cls, seconds: int) -> ASN1Time:
        library = Library.default()
        out = library.type("umilib_codec_asn1_ASN1Time")()
        library.call("umilib_codec_asn1_asn1_time_from_unix_seconds", seconds, ctypes.byref(out))
        return cls.from_c(out)

    def to_datetime(self) -> datetime.datetime:
        """The time as an aware :class:`datetime.datetime` in UTC (microsecond resolution)."""
        return datetime.datetime(self.year, self.month, self.day, self.hour, self.minute, self.second, self.nanosecond // 1000, datetime.timezone.utc)


__all__ = ["ASN1Error", "ASN1Integer", "ASN1Real", "ASN1String", "ASN1Time", "BitString", "ObjectIdentifier", "Tag", "TagClass"]
