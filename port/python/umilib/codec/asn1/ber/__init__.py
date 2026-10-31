"""The Basic Encoding Rules. Mirrors ``umilib::codec::asn1::ber``."""

from __future__ import annotations

import ctypes
from typing import Any

from umilib.codec.asn1 import ASN1Integer, ASN1Time, BitString, ObjectIdentifier, Tag
from umilib.ffi import Buffer, Bytes, Handle, Library


class BERElement:
    """One BER element, holding the input it points into."""

    def __init__(self, value: ctypes.Structure, owner: Any) -> None:
        self.value = value
        self.owner = owner

    tag = property(lambda self: Tag.from_c(self.value.tag))
    content = property(lambda self: ctypes.string_at(self.value.content, self.value.content_length) if self.value.content_length else b"")
    encoding = property(lambda self: ctypes.string_at(self.value.encoding, self.value.encoding_length))
    position = property(lambda self: self.value.position)
    content_position = property(lambda self: self.value.content_position)
    indefinite = property(lambda self: bool(self.value.indefinite))
    depth = property(lambda self: self.value.depth)
    maximum_depth = property(lambda self: self.value.maximum_depth)

    def children(self) -> BERReader:
        return BERReader(pointer=Handle.create("umilib_codec_asn1_ber_ber_element_children", ctypes.byref(self.value)), owner=self.owner)

    def output(self, name: str, *arguments: Any) -> bytes:
        return Library.default().output(f"umilib_codec_asn1_ber_ber_element_{name}", ctypes.byref(self.value), *arguments)

    def string_content(self, segment: Tag) -> bytes:
        return self.output("string_content", segment.to_c())

    def as_boolean(self) -> bool:
        return Library.default().value("umilib_codec_asn1_ber_ber_element_as_boolean", ctypes.c_bool, ctypes.byref(self.value))

    def as_integer(self) -> ASN1Integer:
        pointer, length = ctypes.c_void_p(), ctypes.c_size_t()
        Library.default().call("umilib_codec_asn1_ber_ber_element_as_integer", ctypes.byref(self.value), ctypes.byref(pointer), ctypes.byref(length))
        return ASN1Integer(ctypes.string_at(pointer.value, length.value))

    def as_bit_string(self) -> BitString:
        unused, buffer = ctypes.c_uint8(), Buffer()
        library = Library.default()
        library.call("umilib_codec_asn1_ber_ber_element_as_bit_string", ctypes.byref(self.value), ctypes.byref(unused), ctypes.byref(buffer))
        return BitString(unused.value, library.take(buffer))

    def as_octet_string(self) -> bytes:
        return self.output("as_octet_string")

    def as_null(self) -> None:
        Library.default().call("umilib_codec_asn1_ber_ber_element_as_null", ctypes.byref(self.value))

    def as_object_identifier(self) -> ObjectIdentifier:
        return ObjectIdentifier(Handle.create("umilib_codec_asn1_ber_ber_element_as_object_identifier", ctypes.byref(self.value)))

    def as_utf8_string(self) -> str:
        return self.output("as_utf8_string").decode("utf-8")

    def as_printable_string(self) -> str:
        return self.output("as_printable_string").decode("ascii")

    def as_ia5_string(self) -> str:
        return self.output("as_ia5_string").decode("ascii")

    def as_visible_string(self) -> str:
        return self.output("as_visible_string").decode("ascii")

    def as_numeric_string(self) -> str:
        return self.output("as_numeric_string").decode("ascii")

    def as_bmp_string(self) -> str:
        return self.output("as_bmp_string").decode("utf-8")

    def as_universal_string(self) -> str:
        return self.output("as_universal_string").decode("utf-8")

    def as_utc_time(self) -> ASN1Time:
        library = Library.default()
        return ASN1Time.from_c(library.value("umilib_codec_asn1_ber_ber_element_as_utc_time", library.type("umilib_codec_asn1_ASN1Time"), ctypes.byref(self.value)))

    def as_generalized_time(self) -> ASN1Time:
        library = Library.default()
        return ASN1Time.from_c(library.value("umilib_codec_asn1_ber_ber_element_as_generalized_time", library.type("umilib_codec_asn1_ASN1Time"), ctypes.byref(self.value)))


class BERReader(Handle):
    """A cursor over BER elements."""

    FREE = "umilib_codec_asn1_ber_ber_reader_free"
    DEFAULT_MAXIMUM_DEPTH = 64
    END_OF_CONTENTS = b"\x00\x00"

    def __init__(self, data: bytes | None = None, pointer: int | None = None, owner: Any = None) -> None:
        if pointer is None:
            owner = bytes(data)
            pointer = Handle.create("umilib_codec_asn1_ber_ber_reader_new", owner, len(owner))
        super().__init__(pointer)
        self.owner = owner

    @classmethod
    def new(cls, data: bytes) -> BERReader:
        return cls(data)

    def child(self, pointer: int) -> BERReader:
        return BERReader(pointer=pointer, owner=self.owner)

    def with_maximum_depth(self, maximum_depth: int) -> BERReader:
        return self.child(Handle.create("umilib_codec_asn1_ber_ber_reader_with_maximum_depth", self.handle, maximum_depth))

    def position(self) -> int:
        return self.library.value("umilib_codec_asn1_ber_ber_reader_position", ctypes.c_size_t, self.handle)

    def depth(self) -> int:
        return self.library.value("umilib_codec_asn1_ber_ber_reader_depth", ctypes.c_size_t, self.handle)

    def is_empty(self) -> bool:
        return self.library.value("umilib_codec_asn1_ber_ber_reader_is_empty", ctypes.c_bool, self.handle)

    def finish(self) -> None:
        self.library.call("umilib_codec_asn1_ber_ber_reader_finish", self.handle)

    def element(self, name: str, *arguments: Any) -> BERElement:
        out = self.library.type("umilib_codec_asn1_ber_BERElement")()
        self.library.call(f"umilib_codec_asn1_ber_ber_reader_{name}", self.handle, *arguments, ctypes.byref(out))
        return BERElement(out, self.owner)

    def peek(self) -> BERElement:
        return self.element("peek")

    def peek_tag(self) -> Tag | None:
        has, tag = ctypes.c_bool(), self.library.type("umilib_codec_asn1_Tag")()
        self.library.call("umilib_codec_asn1_ber_ber_reader_peek_tag", self.handle, ctypes.byref(has), ctypes.byref(tag))
        return Tag.from_c(tag) if has.value else None

    def read_element(self) -> BERElement:
        return self.element("read_element")

    def read_expected(self, tag: Tag) -> BERElement:
        return self.element("read_expected", tag.to_c())

    def read_optional(self, tag: Tag) -> BERElement | None:
        found, out = ctypes.c_bool(), self.library.type("umilib_codec_asn1_ber_BERElement")()
        self.library.call("umilib_codec_asn1_ber_ber_reader_read_optional", self.handle, tag.to_c(), ctypes.byref(found), ctypes.byref(out))
        return BERElement(out, self.owner) if found.value else None

    def read_constructed(self, tag: Tag) -> BERReader:
        return self.child(Handle.create("umilib_codec_asn1_ber_ber_reader_read_constructed", self.handle, tag.to_c()))

    def read_sequence(self) -> BERReader:
        return self.child(Handle.create("umilib_codec_asn1_ber_ber_reader_read_sequence", self.handle))

    def read_set(self) -> BERReader:
        return self.child(Handle.create("umilib_codec_asn1_ber_ber_reader_read_set", self.handle))

    def read_explicit(self, number: int) -> BERReader:
        return self.child(Handle.create("umilib_codec_asn1_ber_ber_reader_read_explicit", self.handle, number))

    @staticmethod
    def is_string_type(number: int) -> bool:
        return bool(Library.default().function("umilib_codec_asn1_ber_ber_reader_is_string_type")(number))

    @staticmethod
    def must_be_constructed(number: int) -> bool:
        return bool(Library.default().function("umilib_codec_asn1_ber_ber_reader_must_be_constructed")(number))

    @staticmethod
    def to_der(data: bytes, maximum_depth: int = DEFAULT_MAXIMUM_DEPTH) -> bytes:
        data, length = Bytes.readable(data)
        return Library.default().output("umilib_codec_asn1_ber_ber_reader_to_der", data, length, maximum_depth)


__all__ = ["BERElement", "BERReader"]
