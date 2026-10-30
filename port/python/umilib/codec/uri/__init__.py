"""URIs: the generic syntax of RFC 3986 and the form encoding of ``application/x-www-form-urlencoded``.
Mirrors ``umilib::codec::uri``.

:class:`URIReference` holds the components of a URI reference as written (percent-encoded), an absent
component as ``None`` and an empty one as ``""``; it resolves references (§5) and normalizes them
(§6.2.2). :class:`URIAuthority` is its authority, :class:`URIHostKind` the form of a host.
:class:`URIPercent` encodes and decodes octets (§2.1); :class:`URIForm` reads and writes the name and
value pairs of the form encoding (WHATWG URL Standard §5). Errors are :class:`URIError`.
"""

from __future__ import annotations

import ctypes
import dataclasses
import enum
from collections.abc import Callable
from typing import Any

from umilib.ffi import Buffer, Bytes, FFIError, Library, Text

P = "umilib_codec_uri"

__all__ = ["URIAuthority", "URIError", "URIForm", "URIHostKind", "URIPercent", "URIReference"]


class URIError(FFIError):
    """An error of reading a URI or a form: ``Syntax``, ``Percent`` (a ``%`` not of two hexadecimal
    digits), ``UTF8`` (decoded octets that are not UTF-8), ``NotAbsolute`` (a base that is not an
    absolute URI) or ``NoSuchPair``."""


Library.register_error("codec.uri", URIError)


class URIHostKind(enum.IntEnum):
    """The form of a host (RFC 3986 §3.2.2)."""

    IPv6 = 0
    IPvFuture = 1
    IPv4 = 2
    RegName = 3


@dataclasses.dataclass
class URIAuthority:
    """The authority of a URI (RFC 3986 §3.2): ``host`` as written, an IP literal with its brackets;
    ``port`` the digits after ``:``, ``""`` for a ``:`` with no digits."""

    userinfo: str | None = None
    host: str = ""
    port: str | None = None

    @staticmethod
    def parse(text: str) -> URIAuthority:
        """The authority ``text``, as it stands between ``//`` and the path."""
        library = Library.default()
        has_userinfo, userinfo, host, has_port, port = ctypes.c_bool(), Buffer(), Buffer(), ctypes.c_bool(), Buffer()
        library.call(f"{P}_uri_authority_parse", *Text.encode(text), ctypes.byref(has_userinfo), ctypes.byref(userinfo), ctypes.byref(host), ctypes.byref(has_port), ctypes.byref(port))
        return URIAuthority(
            userinfo=library.take_optional_text(has_userinfo, userinfo),
            host=library.take(host).decode("utf-8"),
            port=library.take_optional_text(has_port, port),
        )

    def host_kind(self) -> URIHostKind:
        """The form of the host: an IP literal by its brackets, an IPv4 address where the host is one,
        otherwise a registered name."""
        return URIHostKind(Library.default().value(f"{P}_uri_authority_host_kind", ctypes.c_uint8, *Text.encode(self.host)))

    @staticmethod
    def is_ipv4(text: bytes) -> bool:
        """Whether ``text`` is an ``IPv4address`` (§3.2.2)."""
        return Library.default().value(f"{P}_uri_authority_is_ipv4", ctypes.c_bool, *Bytes.readable(text))

    @staticmethod
    def is_ipv6(text: bytes) -> bool:
        """Whether ``text`` is an ``IPv6address`` (§3.2.2)."""
        return Library.default().value(f"{P}_uri_authority_is_ipv6", ctypes.c_bool, *Bytes.readable(text))

    @staticmethod
    def is_ipvfuture(text: bytes) -> bool:
        """Whether ``text`` is an ``IPvFuture`` (§3.2.2)."""
        return Library.default().value(f"{P}_uri_authority_is_ipvfuture", ctypes.c_bool, *Bytes.readable(text))

    def __str__(self) -> str:
        return str(URIReference(authority=self))[2:]


@dataclasses.dataclass
class URIReference:
    """A URI reference (RFC 3986 §4.1), each component as written. :meth:`parse` checks the grammar of
    Appendix A; :meth:`check` does the same for a reference built field by field; ``str`` writes the
    components back (§5.3)."""

    scheme: str | None = None
    authority: URIAuthority | None = None
    path: str = ""
    query: str | None = None
    fragment: str | None = None

    @staticmethod
    def parse(text: str) -> URIReference:
        """The reference ``text``, checked against the grammar of RFC 3986 Appendix A."""
        out = ctypes.c_void_p()
        Library.default().call(f"{P}_uri_reference_parse", *Text.encode(text), ctypes.byref(out))
        return URIReference.take_handle(out.value)

    def check(self) -> None:
        """Raises :class:`URIError` unless the components, written back, read as the same reference."""
        self.with_handle(lambda handle: Library.default().call(f"{P}_uri_reference_check", handle))

    def is_relative(self) -> bool:
        """Whether this is a relative reference (§4.2): one without a scheme."""
        return self.with_handle(lambda handle: Library.default().value(f"{P}_uri_reference_is_relative", ctypes.c_bool, handle))

    def is_absolute(self) -> bool:
        """Whether this is an absolute URI (§4.3): one with a scheme and without a fragment."""
        return self.with_handle(lambda handle: Library.default().value(f"{P}_uri_reference_is_absolute", ctypes.c_bool, handle))

    def resolve(self, base: URIReference) -> URIReference:
        """The target of this reference resolved against ``base`` (§5.2.2, strict)."""

        def resolve(handle: int) -> URIReference:
            def against(base_handle: int) -> URIReference:
                out = ctypes.c_void_p()
                Library.default().call(f"{P}_uri_reference_resolve", handle, base_handle, ctypes.byref(out))
                return URIReference.take_handle(out.value)

            return base.with_handle(against)

        return self.with_handle(resolve)

    def normalize(self) -> URIReference:
        """This reference normalized by its syntax (§6.2.2), an empty port dropped (§6.2.3)."""

        def normalize(handle: int) -> URIReference:
            out = ctypes.c_void_p()
            Library.default().call(f"{P}_uri_reference_normalize", handle, ctypes.byref(out))
            return URIReference.take_handle(out.value)

        return self.with_handle(normalize)

    @staticmethod
    def merge(base: URIReference, path: str) -> str:
        """The path of ``base`` merged with the relative path ``path`` (§5.2.3)."""
        return base.with_handle(lambda handle: Library.default().output(f"{P}_uri_reference_merge", handle, *Text.encode(path)).decode("utf-8"))

    @staticmethod
    def remove_dot_segments(path: str) -> str:
        """``path`` with its ``.`` and ``..`` segments removed (§5.2.4)."""
        return Library.default().output(f"{P}_uri_reference_remove_dot_segments", *Text.encode(path)).decode("utf-8")

    @staticmethod
    def check_scheme(scheme: str) -> None:
        """Raises :class:`URIError` unless ``scheme`` is a scheme (§3.1)."""
        Library.default().call(f"{P}_uri_reference_check_scheme", *Text.encode(scheme))

    @staticmethod
    def is_path_byte(byte: int) -> bool:
        """Whether ``byte`` may stand in a path as it is (§3.3)."""
        return Library.default().value(f"{P}_uri_reference_is_path_byte", ctypes.c_bool, byte)

    @staticmethod
    def is_query_byte(byte: int) -> bool:
        """Whether ``byte`` may stand in a query or a fragment as it is (§3.4, §3.5)."""
        return Library.default().value(f"{P}_uri_reference_is_query_byte", ctypes.c_bool, byte)

    def with_handle(self, use: Callable[[int], Any]) -> Any:
        """Calls ``use`` with a C handle of this reference, released afterwards."""
        library = Library.default()
        out = ctypes.c_void_p()
        library.call(f"{P}_uri_reference_new", ctypes.byref(out))
        handle = out.value
        try:
            library.call(f"{P}_uri_reference_set_scheme", handle, *Text.encode(self.scheme))
            if self.authority is None:
                library.call(f"{P}_uri_reference_set_authority", handle, False, None, 0, None, 0, None, 0)
            else:
                authority = self.authority
                library.call(f"{P}_uri_reference_set_authority", handle, True, *Text.encode(authority.userinfo), *Text.encode(authority.host), *Text.encode(authority.port))
            library.call(f"{P}_uri_reference_set_path", handle, *Text.encode(self.path))
            library.call(f"{P}_uri_reference_set_query", handle, *Text.encode(self.query))
            library.call(f"{P}_uri_reference_set_fragment", handle, *Text.encode(self.fragment))
            return use(handle)
        finally:
            library.function(f"{P}_uri_reference_free")(handle)

    @staticmethod
    def take_handle(handle: int) -> URIReference:
        """The reference of the C handle ``handle``, which is released."""
        library = Library.default()
        try:
            scheme = library.optional(f"{P}_uri_reference_scheme", Buffer, handle)
            has = ctypes.c_bool()
            has_userinfo, userinfo, host, has_port, port = ctypes.c_bool(), Buffer(), Buffer(), ctypes.c_bool(), Buffer()
            library.call(f"{P}_uri_reference_authority", handle, ctypes.byref(has), ctypes.byref(has_userinfo), ctypes.byref(userinfo), ctypes.byref(host), ctypes.byref(has_port), ctypes.byref(port))
            authority = URIAuthority(
                userinfo=library.take_optional_text(has_userinfo, userinfo),
                host=library.take(host).decode("utf-8"),
                port=library.take_optional_text(has_port, port),
            )
            query = library.optional(f"{P}_uri_reference_query", Buffer, handle)
            fragment = library.optional(f"{P}_uri_reference_fragment", Buffer, handle)
            return URIReference(
                scheme=None if scheme is None else scheme.decode("utf-8"),
                authority=authority if has.value else None,
                path=library.output(f"{P}_uri_reference_path", handle).decode("utf-8"),
                query=None if query is None else query.decode("utf-8"),
                fragment=None if fragment is None else fragment.decode("utf-8"),
            )
        finally:
            library.function(f"{P}_uri_reference_free")(handle)

    def __str__(self) -> str:
        return self.with_handle(lambda handle: Library.default().output(f"{P}_uri_reference_format", handle).decode("utf-8"))


class URIPercent:
    """Percent-encoding (RFC 3986 §2.1) and the character classes of §2."""

    HEXADECIMAL = b"0123456789ABCDEF"

    @staticmethod
    def is_unreserved(byte: int) -> bool:
        """Whether ``byte`` is unreserved (§2.3): ALPHA, DIGIT, ``-``, ``.``, ``_``, ``~``."""
        return Library.default().value(f"{P}_uri_percent_is_unreserved", ctypes.c_bool, byte)

    @staticmethod
    def is_sub_delim(byte: int) -> bool:
        """Whether ``byte`` is a sub-delimiter (§2.2): ``!$&'()*+,;=``."""
        return Library.default().value(f"{P}_uri_percent_is_sub_delim", ctypes.c_bool, byte)

    @staticmethod
    def is_gen_delim(byte: int) -> bool:
        """Whether ``byte`` is a general delimiter (§2.2): ``:/?#[]@``."""
        return Library.default().value(f"{P}_uri_percent_is_gen_delim", ctypes.c_bool, byte)

    @staticmethod
    def is_pchar(byte: int) -> bool:
        """Whether ``byte`` is a ``pchar`` other than a percent-encoding (§3.3)."""
        return Library.default().value(f"{P}_uri_percent_is_pchar", ctypes.c_bool, byte)

    @staticmethod
    def encode(data: bytes, keep: Callable[[int], bool]) -> str:
        """``data`` with every octet ``keep`` does not take percent-encoded."""
        kept = bytes(byte for byte in range(256) if keep(byte))
        return Library.default().output(f"{P}_uri_percent_encode", *Bytes.readable(data), *Bytes.readable(kept)).decode("ascii")

    @staticmethod
    def encode_component(data: bytes) -> str:
        """``data`` with every octet but the unreserved percent-encoded (§2.4)."""
        return Library.default().output(f"{P}_uri_percent_encode_component", *Bytes.readable(data)).decode("ascii")

    @staticmethod
    def digit(byte: int) -> int | None:
        """The value of the hexadecimal digit ``byte``."""
        return Library.default().optional(f"{P}_uri_percent_digit", ctypes.c_uint8, byte)

    @staticmethod
    def decode(text: bytes) -> bytes:
        """The octets of ``text``, its percent-encodings decoded."""
        return Library.default().output(f"{P}_uri_percent_decode", *Bytes.readable(text))

    @staticmethod
    def decode_text(text: bytes) -> str:
        """The UTF-8 text of ``text``, its percent-encodings decoded."""
        return Library.default().output(f"{P}_uri_percent_decode_text", *Bytes.readable(text)).decode("utf-8")

    @staticmethod
    def check(text: bytes) -> None:
        """Raises :class:`URIError` unless every ``%`` of ``text`` begins a percent-encoding."""
        Library.default().call(f"{P}_uri_percent_check", *Bytes.readable(text))


class URIForm:
    """The form encoding ``application/x-www-form-urlencoded`` (WHATWG URL Standard §5; RFC 6749
    Appendix B)."""

    @staticmethod
    def is_kept(byte: int) -> bool:
        """Whether the serializer keeps ``byte`` as it is: the alphanumerics and ``*-._``."""
        return Library.default().value(f"{P}_uri_form_is_kept", ctypes.c_bool, byte)

    @staticmethod
    def parse(data: bytes) -> list[tuple[str, str]]:
        """The pairs of ``data`` (WHATWG URL §5.1); octets that are not UTF-8 raise ``UTF8``."""
        library = Library.default()
        out = ctypes.c_void_p()
        library.call(f"{P}_uri_form_parse", *Bytes.readable(data), ctypes.byref(out))
        try:
            pairs = []
            for index in range(library.value(f"{P}_uri_form_pairs_count", ctypes.c_size_t, out.value)):
                name, value = Buffer(), Buffer()
                library.call(f"{P}_uri_form_pairs_get", out.value, index, ctypes.byref(name), ctypes.byref(value))
                pairs.append((library.take(name).decode("utf-8"), library.take(value).decode("utf-8")))
            return pairs
        finally:
            library.function(f"{P}_uri_form_pairs_free")(out.value)

    @staticmethod
    def decode(text: bytes) -> str:
        """The text of one name or value: ``+`` a space, percent-encodings decoded leniently."""
        return Library.default().output(f"{P}_uri_form_decode", *Bytes.readable(text)).decode("utf-8")

    @staticmethod
    def encode_text(text: str) -> str:
        """One name or value written (WHATWG URL §5.2)."""
        return Library.default().output(f"{P}_uri_form_encode_text", *Text.encode(text)).decode("ascii")

    @staticmethod
    def encode(pairs: list[tuple[str, str]]) -> str:
        """``pairs`` written: ``name=value``, joined by ``&``."""
        library = Library.default()
        out = ctypes.c_void_p()
        library.call(f"{P}_uri_form_pairs_new", ctypes.byref(out))
        try:
            for name, value in pairs:
                library.call(f"{P}_uri_form_pairs_push", out.value, *Text.encode(name), *Text.encode(value))
            return library.output(f"{P}_uri_form_encode", out.value).decode("ascii")
        finally:
            library.function(f"{P}_uri_form_pairs_free")(out.value)
