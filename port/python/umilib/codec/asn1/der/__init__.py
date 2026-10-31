"""The Distinguished Encoding Rules. Mirrors ``umilib::codec::asn1::der``.

Readers keep their input alive, and so do the elements and nested readers
taken from them.
"""

from __future__ import annotations

import ctypes
from typing import Any, Callable

from umilib.codec.asn1 import ASN1Integer, ASN1Time, BitString, ObjectIdentifier, Tag
from umilib.ffi import Buffer, Bytes, Handle, I128, Library, Text


class DERElement:
    """One DER element, holding the input it points into."""

    def __init__(self, value: ctypes.Structure, owner: Any) -> None:
        self.value = value
        self.owner = owner

    @property
    def tag(self) -> Tag:
        return Tag.from_c(self.value.tag)

    @property
    def content(self) -> bytes:
        return ctypes.string_at(self.value.content, self.value.content_length) if self.value.content_length else b""

    @property
    def encoding(self) -> bytes:
        return ctypes.string_at(self.value.encoding, self.value.encoding_length)

    @property
    def position(self) -> int:
        return self.value.position

    def content_position(self) -> int:
        return Library.default().value("umilib_codec_asn1_der_der_element_content_position", ctypes.c_size_t, ctypes.byref(self.value))

    def slice(self, name: str) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call(f"umilib_codec_asn1_der_der_element_{name}", ctypes.byref(self.value), ctypes.byref(pointer), ctypes.byref(length))
        return ctypes.string_at(pointer.value, length.value) if length.value else b""

    def primitive(self) -> bytes:
        return self.slice("primitive")

    def as_boolean(self) -> bool:
        return Library.default().value("umilib_codec_asn1_der_der_element_as_boolean", ctypes.c_bool, ctypes.byref(self.value))

    def as_integer(self) -> ASN1Integer:
        return ASN1Integer(self.slice("as_integer"))

    def as_bit_string(self) -> BitString:
        unused, pointer, length = ctypes.c_uint8(), ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call("umilib_codec_asn1_der_der_element_as_bit_string", ctypes.byref(self.value), ctypes.byref(unused), ctypes.byref(pointer), ctypes.byref(length))
        return BitString(unused.value, ctypes.string_at(pointer.value, length.value) if length.value else b"")

    def as_octet_string(self) -> bytes:
        return self.slice("as_octet_string")

    def as_null(self) -> None:
        Library.default().call("umilib_codec_asn1_der_der_element_as_null", ctypes.byref(self.value))

    def as_object_identifier(self) -> ObjectIdentifier:
        return ObjectIdentifier(Handle.create("umilib_codec_asn1_der_der_element_as_object_identifier", ctypes.byref(self.value)))

    def as_utf8_string(self) -> str:
        return self.slice("as_utf8_string").decode("utf-8")

    def as_printable_string(self) -> str:
        return self.slice("as_printable_string").decode("ascii")

    def as_ia5_string(self) -> str:
        return self.slice("as_ia5_string").decode("ascii")

    def as_visible_string(self) -> str:
        return self.slice("as_visible_string").decode("ascii")

    def as_numeric_string(self) -> str:
        return self.slice("as_numeric_string").decode("ascii")

    def as_teletex_string(self) -> bytes:
        return self.slice("as_teletex_string")

    def as_bmp_string(self) -> str:
        return Library.default().output("umilib_codec_asn1_der_der_element_as_bmp_string", ctypes.byref(self.value)).decode("utf-8")

    def as_universal_string(self) -> str:
        return Library.default().output("umilib_codec_asn1_der_der_element_as_universal_string", ctypes.byref(self.value)).decode("utf-8")

    def as_utc_time(self) -> ASN1Time:
        return ASN1Time.from_c(Library.default().value("umilib_codec_asn1_der_der_element_as_utc_time", Library.default().type("umilib_codec_asn1_ASN1Time"), ctypes.byref(self.value)))

    def as_generalized_time(self) -> ASN1Time:
        return ASN1Time.from_c(Library.default().value("umilib_codec_asn1_der_der_element_as_generalized_time", Library.default().type("umilib_codec_asn1_ASN1Time"), ctypes.byref(self.value)))

    def __repr__(self) -> str:
        return f"DERElement({self.tag}, {len(self.content)} bytes at {self.position})"


class DERReader(Handle):
    """A cursor over DER elements."""

    FREE = "umilib_codec_asn1_der_der_reader_free"
    DEFAULT_MAXIMUM_DEPTH = 64

    def __init__(self, data: bytes | None = None, pointer: int | None = None, owner: Any = None) -> None:
        if pointer is None:
            owner = bytes(data)
            pointer = Handle.create("umilib_codec_asn1_der_der_reader_new", owner, len(owner))
        super().__init__(pointer)
        self.owner = owner

    @classmethod
    def new(cls, data: bytes) -> DERReader:
        return cls(data)

    def child(self, pointer: int) -> DERReader:
        return DERReader(pointer=pointer, owner=self.owner)

    def with_maximum_depth(self, maximum_depth: int) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_with_maximum_depth", self.handle, maximum_depth))

    def position(self) -> int:
        return self.library.value("umilib_codec_asn1_der_der_reader_position", ctypes.c_size_t, self.handle)

    def depth(self) -> int:
        return self.library.value("umilib_codec_asn1_der_der_reader_depth", ctypes.c_size_t, self.handle)

    def is_empty(self) -> bool:
        return self.library.value("umilib_codec_asn1_der_der_reader_is_empty", ctypes.c_bool, self.handle)

    def finish(self) -> None:
        self.library.call("umilib_codec_asn1_der_der_reader_finish", self.handle)

    def wrap(self, value: ctypes.Structure) -> DERElement:
        return DERElement(value, self.owner)

    def peek(self) -> DERElement:
        out = self.library.type("umilib_codec_asn1_der_DERElement")()
        self.library.call("umilib_codec_asn1_der_der_reader_peek", self.handle, ctypes.byref(out))
        return self.wrap(out)

    def peek_tag(self) -> Tag | None:
        has, tag = ctypes.c_bool(), self.library.type("umilib_codec_asn1_Tag")()
        self.library.call("umilib_codec_asn1_der_der_reader_peek_tag", self.handle, ctypes.byref(has), ctypes.byref(tag))
        return Tag.from_c(tag) if has.value else None

    def read_element(self) -> DERElement:
        out = self.library.type("umilib_codec_asn1_der_DERElement")()
        self.library.call("umilib_codec_asn1_der_der_reader_read_element", self.handle, ctypes.byref(out))
        return self.wrap(out)

    def read_expected(self, tag: Tag) -> DERElement:
        out = self.library.type("umilib_codec_asn1_der_DERElement")()
        self.library.call("umilib_codec_asn1_der_der_reader_read_expected", self.handle, tag.to_c(), ctypes.byref(out))
        return self.wrap(out)

    def read_optional(self, tag: Tag) -> DERElement | None:
        found, out = ctypes.c_bool(), self.library.type("umilib_codec_asn1_der_DERElement")()
        self.library.call("umilib_codec_asn1_der_der_reader_read_optional", self.handle, tag.to_c(), ctypes.byref(found), ctypes.byref(out))
        return self.wrap(out) if found.value else None

    def nested(self, element: DERElement) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_nested", self.handle, ctypes.byref(element.value)))

    def read_constructed(self, tag: Tag) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_read_constructed", self.handle, tag.to_c()))

    def read_sequence(self) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_read_sequence", self.handle))

    def read_set(self) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_read_set", self.handle))

    def read_set_of(self) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_read_set_of", self.handle))

    def read_explicit(self, number: int) -> DERReader:
        return self.child(Handle.create("umilib_codec_asn1_der_der_reader_read_explicit", self.handle, number))

    def read_optional_explicit(self, number: int) -> DERReader | None:
        found, out = ctypes.c_bool(), ctypes.c_void_p()
        self.library.call("umilib_codec_asn1_der_der_reader_read_optional_explicit", self.handle, number, ctypes.byref(found), ctypes.byref(out))
        return self.child(out.value) if found.value else None

    def slice(self, name: str) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call(f"umilib_codec_asn1_der_der_reader_{name}", self.handle, ctypes.byref(pointer), ctypes.byref(length))
        return ctypes.string_at(pointer.value, length.value) if length.value else b""

    def read_boolean(self) -> bool:
        return self.library.value("umilib_codec_asn1_der_der_reader_read_boolean", ctypes.c_bool, self.handle)

    def read_integer(self) -> ASN1Integer:
        return ASN1Integer(self.slice("read_integer"))

    def read_enumerated(self) -> ASN1Integer:
        return ASN1Integer(self.slice("read_enumerated"))

    def read_bit_string(self) -> BitString:
        unused, pointer, length = ctypes.c_uint8(), ctypes.c_void_p(), ctypes.c_size_t()
        self.library.call("umilib_codec_asn1_der_der_reader_read_bit_string", self.handle, ctypes.byref(unused), ctypes.byref(pointer), ctypes.byref(length))
        return BitString(unused.value, ctypes.string_at(pointer.value, length.value) if length.value else b"")

    def read_octet_string(self) -> bytes:
        return self.slice("read_octet_string")

    def read_null(self) -> None:
        self.library.call("umilib_codec_asn1_der_der_reader_read_null", self.handle)

    def read_object_identifier(self) -> ObjectIdentifier:
        return ObjectIdentifier(Handle.create("umilib_codec_asn1_der_der_reader_read_object_identifier", self.handle))

    def read_utf8_string(self) -> str:
        return self.slice("read_utf8_string").decode("utf-8")

    def read_printable_string(self) -> str:
        return self.slice("read_printable_string").decode("ascii")

    def read_ia5_string(self) -> str:
        return self.slice("read_ia5_string").decode("ascii")

    def read_visible_string(self) -> str:
        return self.slice("read_visible_string").decode("ascii")

    def read_numeric_string(self) -> str:
        return self.slice("read_numeric_string").decode("ascii")

    def read_bmp_string(self) -> str:
        return self.library.output("umilib_codec_asn1_der_der_reader_read_bmp_string", self.handle).decode("utf-8")

    def read_universal_string(self) -> str:
        return self.library.output("umilib_codec_asn1_der_der_reader_read_universal_string", self.handle).decode("utf-8")

    def read_utc_time(self) -> ASN1Time:
        return ASN1Time.from_c(self.library.value("umilib_codec_asn1_der_der_reader_read_utc_time", self.library.type("umilib_codec_asn1_ASN1Time"), self.handle))

    def read_generalized_time(self) -> ASN1Time:
        return ASN1Time.from_c(self.library.value("umilib_codec_asn1_der_der_reader_read_generalized_time", self.library.type("umilib_codec_asn1_ASN1Time"), self.handle))

    @staticmethod
    def decode_length(data: bytes, position: int, strict: bool) -> tuple[int | None, int]:
        data, size = Bytes.readable(data)
        definite, length, following = ctypes.c_bool(), ctypes.c_size_t(), ctypes.c_size_t()
        Library.default().call("umilib_codec_asn1_der_der_reader_decode_length", data, size, position, strict, ctypes.byref(definite), ctypes.byref(length), ctypes.byref(following))
        return (length.value if definite.value else None), following.value

    @staticmethod
    def compare_encodings(a: bytes, b: bytes) -> int:
        (a, a_length), (b, b_length) = Bytes.readable(a), Bytes.readable(b)
        return Library.default().value("umilib_codec_asn1_der_der_reader_compare_encodings", ctypes.c_int8, a, a_length, b, b_length)

    @staticmethod
    def validate(data: bytes, maximum_depth: int = DEFAULT_MAXIMUM_DEPTH) -> None:
        data, length = Bytes.readable(data)
        Library.default().call("umilib_codec_asn1_der_der_reader_validate", data, length, maximum_depth)

    @staticmethod
    def validate_shallow(element: DERElement) -> None:
        """Checks the form of ``element`` and, for a universal primitive whose rules are
        known, its contents, without looking inside constructed elements."""
        Library.default().call("umilib_codec_asn1_der_der_reader_validate_shallow", ctypes.byref(element.value))


class DERWriter(Handle):
    """Writes DER elements. Constructed elements are built by a function that fills a nested writer."""

    FREE = "umilib_codec_asn1_der_der_writer_free"

    def __init__(self) -> None:
        super().__init__(Handle.create("umilib_codec_asn1_der_der_writer_new"))

    @classmethod
    def new(cls) -> DERWriter:
        return cls()

    def as_bytes(self) -> bytes:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        with self.locked():
            self.library.call("umilib_codec_asn1_der_der_writer_as_bytes", self.handle, ctypes.byref(pointer), ctypes.byref(length))
            return ctypes.string_at(pointer.value, length.value) if length.value else b""

    def into_bytes(self) -> bytes:
        buffer = Buffer()
        with self.locked():
            self.library.call("umilib_codec_asn1_der_der_writer_into_bytes", self.handle, ctypes.byref(buffer))
            self.consumed()
        return self.library.take(buffer)

    @staticmethod
    def encode_length(length: int) -> bytes:
        return Library.default().output("umilib_codec_asn1_der_der_writer_encode_length", length)

    def write_element(self, tag: Tag, content: bytes) -> None:
        data, length = Bytes.readable(content)
        self.library.call("umilib_codec_asn1_der_der_writer_write_element", self.handle, tag.to_c(), data, length)

    def write_raw(self, encoding: bytes) -> None:
        data, length = Bytes.readable(encoding)
        self.library.call("umilib_codec_asn1_der_der_writer_write_raw", self.handle, data, length)

    def nested(self, name: str, build: Callable[[DERWriter], None], *arguments: Any) -> None:
        inner = DERWriter()
        try:
            build(inner)
            self.library.call(f"umilib_codec_asn1_der_der_writer_{name}", self.handle, *arguments, inner.handle)
        finally:
            inner.close()

    def write_constructed(self, tag: Tag, build: Callable[[DERWriter], None]) -> None:
        self.nested("write_constructed", build, tag.to_c())

    def write_sequence(self, build: Callable[[DERWriter], None]) -> None:
        self.nested("write_sequence", build)

    def write_set(self, build: Callable[[DERWriter], None]) -> None:
        self.nested("write_set", build)

    def write_set_of(self, build: Callable[[DERWriter], None]) -> None:
        self.nested("write_set_of", build)

    def write_explicit(self, number: int, build: Callable[[DERWriter], None]) -> None:
        self.nested("write_explicit", build, number)

    def write_boolean(self, value: bool) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_boolean", self.handle, bool(value))

    def write_integer_i128(self, value: int) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_integer_i128", self.handle, I128.from_int(value))

    def write_integer_unsigned(self, magnitude: bytes) -> None:
        data, length = Bytes.readable(magnitude)
        self.library.call("umilib_codec_asn1_der_der_writer_write_integer_unsigned", self.handle, data, length)

    def write_integer(self, value: ASN1Integer) -> None:
        self.write_element(Tag.INTEGER, value.as_bytes())

    def write_enumerated(self, value: int) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_enumerated", self.handle, I128.from_int(value))

    def write_bit_string(self, value: BitString) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_bit_string", self.handle, value.unused, value.data, len(value.data))

    def write_octet_string(self, value: bytes) -> None:
        data, length = Bytes.readable(value)
        self.library.call("umilib_codec_asn1_der_der_writer_write_octet_string", self.handle, data, length)

    def write_null(self) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_null", self.handle)

    def write_object_identifier(self, value: ObjectIdentifier) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_object_identifier", self.handle, value.handle)

    def write_text(self, name: str, text: str) -> None:
        data, length = Text.encode(text)
        self.library.call(f"umilib_codec_asn1_der_der_writer_{name}", self.handle, data, length)

    def write_utf8_string(self, value: str) -> None:
        self.write_text("write_utf8_string", value)

    def write_printable_string(self, value: str) -> None:
        self.write_text("write_printable_string", value)

    def write_ia5_string(self, value: str) -> None:
        self.write_text("write_ia5_string", value)

    def write_visible_string(self, value: str) -> None:
        self.write_text("write_visible_string", value)

    def write_numeric_string(self, value: str) -> None:
        self.write_text("write_numeric_string", value)

    def write_bmp_string(self, value: str) -> None:
        self.write_text("write_bmp_string", value)

    def write_universal_string(self, value: str) -> None:
        self.write_text("write_universal_string", value)

    def write_utc_time(self, value: ASN1Time) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_utc_time", self.handle, value.to_c())

    def write_generalized_time(self, value: ASN1Time) -> None:
        self.library.call("umilib_codec_asn1_der_der_writer_write_generalized_time", self.handle, value.to_c())


__all__ = ["DERElement", "DERReader", "DERWriter"]
